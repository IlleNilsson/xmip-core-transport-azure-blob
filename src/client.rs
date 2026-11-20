//! Xmip's side: the calls a Location and an archive make, each one signed
//! request over one connection.
//!
//! The endpoint carries the account — `https://account.blob.core.windows.net`
//! in the cloud, `http://127.0.0.1:10000` for Azurite or a test — and the
//! path names the container and the blob under it.
//!
//! A receive gets and deletes a blob only as it was listed: Get Blob and
//! Delete Blob carry `If-Match` with the `Etag` the listing gave, and the
//! service answers 412 `ConditionNotMet` where the blob was written again
//! since and 404 `BlobNotFound` where it is gone. A receive's claim and an
//! archive write a blob only where none lies: Put Blob carries
//! `If-None-Match: *`, which the
//! conditional-header tables answer with 412 where a blob is there and the
//! service with 409 `BlobAlreadyExists`. Microsoft's sources are pages of
//! <https://learn.microsoft.com/en-us/rest/api/storageservices/>:
//! `specifying-conditional-headers-for-blob-service-operations`,
//! `get-blob`, `delete-blob`, `put-blob` and `blob-service-error-codes`.
//! Shared Key signs both headers (`azure::shared_key`).

use std::time::Duration;

use transport::error::{Result, protocol_error};
use transport::listed::AsListed;

use azure::shared_key::{self, Signer};
use codec::percent::encode;
use http::endpoint::{Connections, Offer};
use http::status;
use net::Endpoint;
use net::http::{Request, Response};

pub struct Client {
    endpoint: Endpoint,
    signer: Signer,
    timeout: Option<Duration>,
    /// The connections kept to the service, shared with the transport
    /// that made this client.
    connections: Connections,
}

impl Client {
    /// Speak to the Blob endpoint at `endpoint` — `http://host:port` or
    /// `https://host:port` — as `account` with its key, base64.
    ///
    /// # Errors
    /// Where `endpoint` is not an HTTP URL, or the key is not base64.
    pub fn new(endpoint: &str, account: &str, key_base64: &str) -> Result<Self> {
        Ok(Self {
            endpoint: Endpoint::parse(endpoint)?,
            signer: Signer::new(account, key_base64)?,
            timeout: None,
            connections: Connections::new(),
        })
    }

    /// Give up on an endpoint that stops answering after `timeout`.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Keep connections among `connections`, which the transport holds
    /// across every client it makes.
    #[must_use]
    pub fn sharing(mut self, connections: Connections) -> Self {
        self.connections = connections;
        self
    }

    /// The blobs under `prefix` in `container`, each with its `Etag`, as
    /// many as one listing carries — five thousand — so a fuller prefix is
    /// taken that many at a time.
    ///
    /// # Errors
    /// Where the endpoint refused, could not be reached, or did not answer
    /// with a listing naming each blob's `Etag`.
    pub fn list(&self, container: &str, prefix: &str) -> Result<Vec<(String, String)>> {
        let request = Request::new("GET", format!("/{}", encode(container, false)))
            .query("restype", "container")
            .query("comp", "list")
            .query("prefix", prefix);
        crate::xml::BLOBS.objects(self.call(request)?.text()?)
    }

    /// The blob at `blob` in `container`, or none where there is none.
    ///
    /// # Errors
    /// Where the endpoint refused or could not be reached.
    pub fn get(&self, container: &str, blob: &str) -> Result<Option<Vec<u8>>> {
        let answer = self.exchange(Request::new("GET", path(container, blob)))?;
        if coded(&answer, 404, "BlobNotFound") {
            return Ok(None);
        }
        Ok(Some(judge(answer)?.body))
    }

    /// The blob at `blob` in `container` as long as it bears `etag`, the
    /// `Etag` its listing gave it: Get Blob with `If-Match`. One written
    /// again or deleted since is [`AsListed::Changed`], and nothing is read.
    ///
    /// # Errors
    /// Where the endpoint refused or could not be reached.
    pub fn get_as_listed(
        &self,
        container: &str,
        blob: &str,
        etag: &str,
    ) -> Result<AsListed<Vec<u8>>> {
        let request = Request::new("GET", path(container, blob)).header("If-Match", &quoted(etag));
        Ok(match as_listed(self.exchange(request)?)? {
            AsListed::Held(answer) => AsListed::Held(answer.body),
            AsListed::Changed => AsListed::Changed,
        })
    }

    /// Delete the blob at `blob` in `container` as long as it bears `etag`,
    /// the `Etag` its listing gave it: Delete Blob with `If-Match`. One
    /// written again or deleted since is [`AsListed::Changed`], and nothing
    /// is deleted.
    ///
    /// # Errors
    /// Where the endpoint refused or could not be reached.
    pub fn delete_as_listed(
        &self,
        container: &str,
        blob: &str,
        etag: &str,
    ) -> Result<AsListed<()>> {
        let request =
            Request::new("DELETE", path(container, blob)).header("If-Match", &quoted(etag));
        Ok(match as_listed(self.exchange(request)?)? {
            AsListed::Held(_) => AsListed::Held(()),
            AsListed::Changed => AsListed::Changed,
        })
    }

    /// Store `bytes` as the block blob at `blob` in `container`, over any
    /// blob already there.
    ///
    /// # Errors
    /// Where the endpoint refused or could not be reached.
    pub fn put(&self, container: &str, blob: &str, bytes: &[u8]) -> Result<()> {
        self.call(block_blob(container, blob, bytes)).map(|_| ())
    }

    /// Store `bytes` as the block blob at `blob` in `container` where no
    /// blob lies, never over one: Put Blob with `If-None-Match: *`. The
    /// `ETag` it was stored with, or `None` where a blob was there, which
    /// is left as it was.
    ///
    /// # Errors
    /// Where the endpoint refused or could not be reached, or stored it
    /// without saying its `ETag`.
    pub fn put_new(&self, container: &str, blob: &str, bytes: &[u8]) -> Result<Option<String>> {
        let request = block_blob(container, blob, bytes).header("If-None-Match", "*");
        created(self.exchange(request)?)
    }

    fn call(&self, request: Request) -> Result<Response> {
        judge(self.exchange(request)?)
    }

    /// `request` signed and sent, its answer as it came.
    fn exchange(&self, request: Request) -> Result<Response> {
        let signed = self.signer.sign(
            request.header("Host", &self.endpoint.authority()),
            &shared_key::now(),
        );
        self.connections
            .exchange(&self.endpoint, self.timeout, Offer::Http11, &signed)
    }
}

fn path(container: &str, blob: &str) -> String {
    format!("/{}/{}", encode(container, false), encode(blob, true))
}

/// A Put Blob of `bytes` as a block blob.
fn block_blob(container: &str, blob: &str, bytes: &[u8]) -> Request {
    Request::new("PUT", path(container, blob))
        .header("Content-Type", "application/octet-stream")
        .header("x-ms-blob-type", "BlockBlob")
        .body(bytes)
}

/// An `Etag` as `If-Match` carries it: quoted, as the service writes it in
/// a header since version 2011-08-18, where a listing gave it bare.
fn quoted(etag: &str) -> String {
    if etag.starts_with('"') {
        etag.to_string()
    } else {
        format!("\"{etag}\"")
    }
}

/// A conditional get's or delete's answer: 412 `ConditionNotMet`, written
/// again since, and 404 `BlobNotFound`, gone since, are
/// [`AsListed::Changed`]; anything else is judged. Another 412 — a lease's
/// — or another 404 — a container's — is the failure it is.
fn as_listed(answer: Response) -> Result<AsListed<Response>> {
    if coded(&answer, 412, "ConditionNotMet") || coded(&answer, 404, "BlobNotFound") {
        return Ok(AsListed::Changed);
    }
    judge(answer).map(AsListed::Held)
}

/// A create's answer: the `ETag` it stored the blob with. 412
/// `ConditionNotMet`, as the conditional-header tables have it, and 409
/// `BlobAlreadyExists`, as the service answers, both say a blob was there.
fn created(answer: Response) -> Result<Option<String>> {
    if coded(&answer, 412, "ConditionNotMet") || coded(&answer, 409, "BlobAlreadyExists") {
        return Ok(None);
    }
    let stored = judge(answer)?;
    let etag = stored.header_value("ETag").map(str::to_string);
    etag.map(Some)
        .ok_or_else(|| protocol_error("the Blob service stored a blob without saying its ETag"))
}

/// Whether `answer` is `status` with `code` in its body. The status is
/// asked first, so a blob's own bytes are never scanned for a code.
fn coded(answer: &Response, status: u16, code: &str) -> bool {
    answer.status == status && error_code(answer) == code
}

/// The code the service put in an error's body; empty where there is none.
fn error_code(answer: &Response) -> String {
    answer
        .text()
        .ok()
        .and_then(|xml| codec::xml::text(xml, "Code").ok().flatten())
        .unwrap_or_default()
}

/// A 2xx answer as it is; anything else as a failure naming the status and
/// the code the service put in the body, retryable where HTTP or the
/// service says come back.
fn judge(response: Response) -> Result<Response> {
    status::judge("the Blob service", response, error_code, |code| {
        code == "ServerBusy"
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{Event, Session};
    use std::assert_matches;
    use transport::socket;

    const KEY: &str = "c2VjcmV0";

    #[test]
    fn the_calls_reach_a_session_and_come_back_shaped_as_azure_shapes_them() {
        let (listener, address) = socket::bind_tcp("127.0.0.1:0").expect("bind");
        let far_end = std::thread::spawn(move || {
            let mut session = Session::new("acct", KEY)
                .expect("base64")
                .timing_out_after(Duration::from_secs(2));
            let events: Vec<Event> = (0..8)
                .map(|_| session.serve_one(&listener).expect("served"))
                .collect();
            (session, events)
        });
        let client = Client::new(&format!("http://{address}"), "acct", KEY)
            .expect("endpoint")
            .timing_out_after(Duration::from_secs(2));
        client.put("orders", "in/a b.edi", b"UNA").expect("put");
        let stored = client.put_new("orders", "out/c.edi", b"UNB").expect("put");
        assert_eq!(stored.as_deref(), Some("\"0x2\""), "its ETag");
        let there = client.put_new("orders", "out/c.edi", b"UNC").expect("put");
        assert_eq!(there, None, "one is there");
        assert_eq!(
            client.list("orders", "in/").expect("list"),
            vec![("in/a b.edi".to_string(), "0x1".to_string())],
            "the first blob written"
        );
        let got = client.get_as_listed("orders", "in/a b.edi", "0x1");
        assert!(matches!(got, Ok(AsListed::Held(ref bytes)) if bytes == b"UNA"));
        let deleted = client.delete_as_listed("orders", "in/a b.edi", "0x1");
        assert!(matches!(deleted, Ok(AsListed::Held(()))));
        assert_eq!(client.get("orders", "in/a b.edi").expect("none"), None);
        assert_eq!(
            client.get("orders", "out/c.edi").expect("one"),
            Some(b"UNB".to_vec()),
            "the first written stays"
        );
        let (session, events) = far_end.join().expect("thread");
        assert_eq!(session.blobs().len(), 1);
        assert_eq!(events[2], Event::Refused("BlobAlreadyExists".to_string()));
        assert_matches!(&events[3], Event::Listed { prefix, .. } if prefix == "in/");
        let origin = "azure-blob://orders/in/a b.edi".to_string();
        assert_eq!(events[4], Event::Retrieved(origin.clone()));
        assert_eq!(events[5], Event::Deleted(origin));
        assert_eq!(events[6], Event::Refused("BlobNotFound".to_string()));
    }

    #[test]
    fn a_changed_blob_and_one_already_there_are_answers_and_any_other_refusal_fails() {
        let error =
            |status, code| Response::new(status).body(crate::xml::error(code, "").as_bytes());
        assert!(matches!(
            as_listed(error(412, "ConditionNotMet")),
            Ok(AsListed::Changed)
        ));
        assert!(matches!(
            as_listed(error(404, "BlobNotFound")),
            Ok(AsListed::Changed)
        ));
        assert!(matches!(
            as_listed(Response::new(202)),
            Ok(AsListed::Held(_))
        ));
        for (status, code) in [
            (404, "ContainerNotFound"),
            (412, "LeaseIdMissing"),
            (409, "BlobAlreadyExists"),
            (403, "AuthenticationFailed"),
        ] {
            let failure = as_listed(error(status, code)).err().expect(code);
            assert!(
                failure.message.contains(&format!("{status} {code}")),
                "{failure}"
            );
        }
        let stored = created(Response::new(201).header("ETag", "\"0x7\""));
        assert_eq!(stored.expect("stored").as_deref(), Some("\"0x7\""));
        assert!(created(Response::new(201)).is_err(), "stored, ETag unsaid");
        assert_eq!(
            created(error(409, "BlobAlreadyExists")).expect("there"),
            None
        );
        assert_eq!(created(error(412, "ConditionNotMet")).expect("there"), None);
        for (status, code) in [
            (409, "BlobImmutableDueToPolicy"),
            (412, "LeaseIdMissing"),
            (404, "ContainerNotFound"),
        ] {
            assert!(created(error(status, code)).is_err(), "{code}");
        }
        assert!(
            !coded(
                &Response::new(200).body(b"<Code>BlobNotFound</Code>"),
                404,
                "BlobNotFound"
            ),
            "a blob's bytes are not an error"
        );
        assert_eq!(quoted("0x1"), "\"0x1\"");
        assert_eq!(quoted("\"0x1\""), "\"0x1\"");
    }

    #[test]
    fn a_server_failure_is_worth_repeating_and_a_client_one_is_not() {
        assert!(judge(Response::new(503)).expect_err("server").retryable);
        assert!(judge(Response::new(429)).expect_err("throttled").retryable);
        let busy = Response::new(400).body(crate::xml::error("ServerBusy", "").as_bytes());
        assert!(judge(busy).expect_err("busy").retryable);
        assert!(!judge(Response::new(403)).expect_err("forbidden").retryable);
        assert!(Client::new("orders.local", "acct", KEY).is_err());
        assert!(Client::new("http://orders.local", "acct", "not base64!").is_err());
    }
}
