//! Xmip's side: the four calls a Location makes, each one signed request
//! over one connection.
//!
//! The endpoint carries the account — `https://account.blob.core.windows.net`
//! in the cloud, `http://127.0.0.1:10000` for Azurite or a test — and the
//! path names the container and the blob under it.

use std::time::Duration;

use transport::error::{Result, TransportError};

use crate::shared_key::{self, Signer};
use crate::xml;
use http::endpoint;
use http::message::{self, Request, Response};
use http::percent::encode;

pub struct Client {
    endpoint: String,
    host: String,
    signer: Signer,
    timeout: Option<Duration>,
}

impl Client {
    /// Speak to the Blob endpoint at `endpoint` — `http://host:port` or
    /// `https://host:port` — as `account` with its key, base64.
    ///
    /// # Errors
    /// Where `endpoint` is not an HTTP URL, or the key is not base64.
    pub fn new(endpoint: &str, account: &str, key_base64: &str) -> Result<Self> {
        Ok(Self {
            endpoint: endpoint.to_string(),
            host: endpoint::authority(endpoint)?,
            signer: Signer::new(account, key_base64)?,
            timeout: None,
        })
    }

    /// Give up on an endpoint that stops answering after `timeout`.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// The blobs under `prefix` in `container`, as many as one listing
    /// carries — five thousand — so a fuller prefix is taken that many at a
    /// time.
    ///
    /// # Errors
    /// Where the endpoint refused, could not be reached, or did not answer
    /// with a listing.
    pub fn list(&self, container: &str, prefix: &str) -> Result<Vec<String>> {
        let request = Request::new("GET", format!("/{}", encode(container, false)))
            .query("restype", "container")
            .query("comp", "list")
            .query("prefix", prefix);
        Ok(xml::texts(&self.call(request)?.text(), "Name"))
    }

    /// The blob at `blob` in `container`.
    ///
    /// # Errors
    /// Where there is no such blob, or the endpoint refused or could not be
    /// reached.
    pub fn get(&self, container: &str, blob: &str) -> Result<Vec<u8>> {
        Ok(self.call(Request::new("GET", path(container, blob)))?.body)
    }

    /// Store `bytes` as the block blob at `blob` in `container`.
    ///
    /// # Errors
    /// Where the endpoint refused or could not be reached.
    pub fn put(&self, container: &str, blob: &str, bytes: &[u8]) -> Result<()> {
        let request = Request::new("PUT", path(container, blob))
            .header("Content-Type", "application/octet-stream")
            .header("x-ms-blob-type", "BlockBlob")
            .body(bytes);
        self.call(request).map(|_| ())
    }

    /// Delete the blob at `blob` in `container`.
    ///
    /// # Errors
    /// Where there is no such blob, or the endpoint refused or could not be
    /// reached.
    pub fn delete(&self, container: &str, blob: &str) -> Result<()> {
        self.call(Request::new("DELETE", path(container, blob)))
            .map(|_| ())
    }

    fn call(&self, request: Request) -> Result<Response> {
        let signed = self
            .signer
            .sign(request.header("Host", &self.host), &shared_key::now());
        let stream = endpoint::connect(&self.endpoint, self.timeout)?;
        judge(message::exchange(stream, &signed)?)
    }
}

fn path(container: &str, blob: &str) -> String {
    format!("/{}/{}", encode(container, false), encode(blob, true))
}

/// A 2xx answer as it is; anything else as a failure naming the status and
/// the code the service put in the body, retryable where it says come back.
fn judge(response: Response) -> Result<Response> {
    if (200..300).contains(&response.status) {
        return Ok(response);
    }
    let code = xml::first(&response.text(), "Code").unwrap_or_default();
    let retryable = response.status >= 500
        || response.status == 408
        || response.status == 429
        || code == "ServerBusy";
    Err(TransportError {
        message: format!("the Blob service answered {} {code}", response.status),
        retryable,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{Event, Session};
    use transport::socket;

    const KEY: &str = "c2VjcmV0";

    #[test]
    fn the_four_calls_reach_a_session_and_come_back_shaped_as_azure_shapes_them() {
        let (listener, address) = socket::bind_tcp("127.0.0.1:0").expect("bind");
        let far_end = std::thread::spawn(move || {
            let mut session = Session::new("acct", KEY)
                .expect("base64")
                .timing_out_after(Duration::from_secs(2));
            let events: Vec<Event> = (0..6)
                .map(|_| session.serve_one(&listener).expect("served"))
                .collect();
            (session, events)
        });
        let client = Client::new(&format!("http://{address}"), "acct", KEY)
            .expect("endpoint")
            .timing_out_after(Duration::from_secs(2));
        client.put("orders", "in/a b.edi", b"UNA").expect("put");
        client.put("orders", "out/c.edi", b"UNB").expect("put");
        assert_eq!(
            client.list("orders", "in/").expect("list"),
            vec!["in/a b.edi".to_string()]
        );
        assert_eq!(client.get("orders", "in/a b.edi").expect("get"), b"UNA");
        client.delete("orders", "in/a b.edi").expect("delete");
        let missing = client.get("orders", "in/a b.edi").expect_err("gone");
        assert!(missing.message.contains("404 BlobNotFound"), "{missing}");
        assert!(!missing.retryable);
        let (session, events) = far_end.join().expect("thread");
        assert_eq!(session.blobs().len(), 1);
        assert!(matches!(&events[2], Event::Listed { prefix, .. } if prefix == "in/"));
        let origin = "azure-blob://orders/in/a b.edi".to_string();
        assert_eq!(events[3], Event::Retrieved(origin.clone()));
        assert_eq!(events[4], Event::Deleted(origin));
        assert_eq!(events[5], Event::Refused("BlobNotFound".to_string()));
    }

    #[test]
    fn a_server_failure_is_worth_repeating_and_a_client_one_is_not() {
        assert!(judge(Response::new(503)).expect_err("server").retryable);
        assert!(judge(Response::new(429)).expect_err("throttled").retryable);
        let busy = Response::new(400).body(xml::error("ServerBusy", "").as_bytes());
        assert!(judge(busy).expect_err("busy").retryable);
        assert!(!judge(Response::new(403)).expect_err("forbidden").retryable);
        assert!(Client::new("orders.local", "acct", KEY).is_err());
        assert!(Client::new("http://orders.local", "acct", "not base64!").is_err());
    }
}
