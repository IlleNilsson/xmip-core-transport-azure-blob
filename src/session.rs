//! The far end: enough of the Blob service to answer one Location, and what
//! a test or the System Tests put on loopback.
//!
//! Not Azure. One session holds blobs in memory, verifies every request
//! against one account key, and answers the four calls with the shapes the
//! service answers them — the enumeration, the blob, the error with its
//! code in the body and in `x-ms-error-code` — holding a get or a delete to
//! the `If-Match` it carries and a put to its `If-None-Match: *`, as the
//! service does. A Location that needs durability, leases or a second
//! account talks to the service through [`crate::Client`].

use std::collections::BTreeMap;
use std::net::TcpListener;
use std::time::Duration;

use transport::Taken;
use transport::error::Result;

use crate::{origin, xml};
use azure::shared_key::Signer;
use codec::percent::decode;
use http::server;
use net::http::{Request, Response};

/// What the client did, as [`Session::serve_one`] reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The client listed `prefix` in `container`.
    Listed { container: String, prefix: String },
    /// The client fetched this blob.
    Retrieved(String),
    /// The client stored a blob; here is the Stream.
    Stored(Taken),
    /// The client deleted this blob.
    Deleted(String),
    /// The client was answered with this error code.
    Refused(String),
}

pub struct Session {
    signer: Signer,
    blobs: BTreeMap<String, Vec<u8>>,
    /// Each blob's `Etag`: the count of writes this session had made when
    /// it was written, so one written again is tagged anew.
    tags: BTreeMap<String, u64>,
    writes: u64,
    timeout: Option<Duration>,
}

impl Session {
    /// Answer requests signed as `account` with its key, base64.
    ///
    /// # Errors
    /// Where `key_base64` is not base64.
    pub fn new(account: &str, key_base64: &str) -> Result<Self> {
        Ok(Self {
            signer: Signer::new(account, key_base64)?,
            blobs: BTreeMap::new(),
            tags: BTreeMap::new(),
            writes: 0,
            timeout: None,
        })
    }

    /// Give up on a client that stops mid-request after `timeout`.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// What is held now, keyed `container/blob`, stores and deletes
    /// included.
    #[must_use]
    pub fn blobs(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.blobs
    }

    /// Accept one connection on `listener`, answer its one request, and say
    /// what it was.
    ///
    /// # Errors
    /// Where the connection could not be accepted, broke, or sent nothing.
    pub fn serve_one(&mut self, listener: &TcpListener) -> Result<Event> {
        // A far end holds no Clock: its one request counts on the
        // operating system's.
        let clock = std::sync::Arc::new(xcore::SystemClock);
        server::serve_one(listener, self.timeout, clock, |request| {
            self.answer(request)
        })
    }

    fn answer(&mut self, request: &Request) -> (Event, Response) {
        if let Err(failure) = self.signer.verify(request) {
            return refused(403, "AuthenticationFailed", &failure.message);
        }
        let path = decode(&request.path);
        let rest = path.trim_start_matches('/');
        let (container, blob) = rest.split_once('/').unwrap_or((rest, ""));
        if container.is_empty() {
            return refused(400, "InvalidUri", "a request naming no container");
        }
        let listing = request.query_value("comp") == Some("list");
        match (request.method.as_str(), blob.is_empty()) {
            ("GET", true) if listing => self.list(container, request),
            ("GET", false) => self.get(container, blob, request),
            ("PUT", false) => self.put(container, blob, request),
            ("DELETE", false) => self.delete(container, blob, request),
            _ => refused(405, "UnsupportedHttpVerb", "not one of the four calls"),
        }
    }

    fn list(&self, container: &str, request: &Request) -> (Event, Response) {
        let prefix = request
            .query_value("prefix")
            .unwrap_or_default()
            .to_string();
        let under = format!("{container}/{prefix}");
        let listed: Vec<(String, String)> = self
            .tags
            .iter()
            .filter(|(held, _)| held.starts_with(&under))
            .map(|(held, written)| (held[container.len() + 1..].to_string(), etag(*written)))
            .collect();
        let response = Response::new(200)
            .header("Content-Type", "application/xml")
            .body(xml::listing(container, &prefix, &listed).as_bytes());
        (
            Event::Listed {
                container: container.to_string(),
                prefix,
            },
            response,
        )
    }

    fn get(&self, container: &str, blob: &str, request: &Request) -> (Event, Response) {
        let held = format!("{container}/{blob}");
        if let Some(unmet) = self.unmet(&held, request) {
            return unmet;
        }
        match self.blobs.get(&held) {
            Some(bytes) => (
                Event::Retrieved(origin(container, blob)),
                Response::new(200)
                    .header("Content-Type", "application/octet-stream")
                    .header("x-ms-blob-type", "BlockBlob")
                    .body(bytes),
            ),
            None => not_found(),
        }
    }

    fn put(&mut self, container: &str, blob: &str, request: &Request) -> (Event, Response) {
        let held = format!("{container}/{blob}");
        if let Some(unmet) = self.unmet(&held, request) {
            return unmet;
        }
        self.writes += 1;
        self.tags.insert(held.clone(), self.writes);
        self.blobs.insert(held, request.body.clone());
        (
            Event::Stored(Taken::new(origin(container, blob), request.body.clone())),
            Response::new(201).header("ETag", &format!("\"{}\"", etag(self.writes))),
        )
    }

    fn delete(&mut self, container: &str, blob: &str, request: &Request) -> (Event, Response) {
        // Unlike S3, the Blob service says when there was nothing to delete.
        let held = format!("{container}/{blob}");
        if let Some(unmet) = self.unmet(&held, request) {
            return unmet;
        }
        self.tags.remove(&held);
        match self.blobs.remove(&held) {
            Some(_) => (Event::Deleted(origin(container, blob)), Response::new(202)),
            None => not_found(),
        }
    }

    /// The service's answer where the blob at `held` does not meet the
    /// condition `request` carries: an `If-Match` on no blob is 404
    /// `BlobNotFound` and on another `Etag` 412 `ConditionNotMet`, quoted or
    /// not; an `If-None-Match: *` on a blob that is there is 409
    /// `BlobAlreadyExists`, which is what the service answers a Put Blob
    /// with it (Blob Storage error codes,
    /// <https://learn.microsoft.com/en-us/rest/api/storageservices/blob-service-error-codes>).
    fn unmet(&self, held: &str, request: &Request) -> Option<(Event, Response)> {
        let written = self.tags.get(held);
        if let Some(wanted) = request.header_value("If-Match") {
            return match written {
                None => Some(not_found()),
                Some(written) if wanted.trim_matches('"') != etag(*written) => Some(refused(
                    412,
                    "ConditionNotMet",
                    "The condition specified using HTTP conditional header(s) is not met.",
                )),
                Some(_) => None,
            };
        }
        (request.header_value("If-None-Match") == Some("*") && written.is_some()).then(|| {
            refused(
                409,
                "BlobAlreadyExists",
                "The specified blob already exists.",
            )
        })
    }
}

fn not_found() -> (Event, Response) {
    refused(404, "BlobNotFound", "The specified blob does not exist.")
}

/// The `Etag` of the `written`th write, as a listing shows one: hex, and
/// unquoted there.
fn etag(written: u64) -> String {
    format!("0x{written:X}")
}

fn refused(status: u16, code: &str, message: &str) -> (Event, Response) {
    (
        Event::Refused(code.to_string()),
        Response::new(status)
            .header("Content-Type", "application/xml")
            .header("x-ms-error-code", code)
            .body(xml::error(code, message).as_bytes()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "c2VjcmV0";
    const AT: &str = "Tue, 08 Sep 2026 12:00:00 GMT";

    fn signed(request: Request) -> Request {
        Signer::new("acct", KEY)
            .expect("base64")
            .sign(request.header("Host", "blob.local"), AT)
    }

    fn listing(prefix: &str) -> Request {
        Request::new("GET", "/c")
            .query("restype", "container")
            .query("comp", "list")
            .query("prefix", prefix)
    }

    #[test]
    fn a_session_answers_in_azures_shapes_and_refuses_a_bad_signature() {
        let mut session = Session::new("acct", KEY).expect("base64");
        let (event, response) = session.answer(&signed(Request::new("PUT", "/c/b").body(b"x")));
        assert_eq!(response.status, 201);
        assert_eq!(
            event,
            Event::Stored(Taken::new("azure-blob://c/b", b"x".to_vec()))
        );
        assert_eq!(response.header_value("ETag"), Some("\"0x1\""));
        let (_, response) = session.answer(&signed(Request::new("PUT", "/c/b").body(b"x")));
        assert_eq!(
            response.header_value("ETag"),
            Some("\"0x2\""),
            "written again"
        );
        let (_, response) = session.answer(&signed(listing("b")));
        let listed = xml::BLOBS
            .objects(response.text().expect("text"))
            .expect("read");
        assert_eq!(listed, [("b".to_string(), "0x2".to_string())]);
        let (_, response) = session.answer(&signed(listing("z")));
        assert!(!response.text().expect("text").contains("<Name>"));
        let (event, response) = session.answer(&signed(Request::new("DELETE", "/c/b")));
        assert_eq!(
            (event, response.status),
            (Event::Deleted("azure-blob://c/b".to_string()), 202)
        );
        assert!(session.blobs().is_empty());
        let (event, response) = session.answer(&signed(Request::new("DELETE", "/c/b")));
        assert_eq!(event, Event::Refused("BlobNotFound".to_string()));
        assert_eq!(
            response.header_value("x-ms-error-code"),
            Some("BlobNotFound")
        );
        let other = Signer::new("acct", "d3Jvbmc=")
            .expect("base64")
            .sign(Request::new("GET", "/c/b").header("Host", "blob.local"), AT);
        let (event, response) = session.answer(&other);
        assert_eq!(event, Event::Refused("AuthenticationFailed".to_string()));
        assert_eq!(response.status, 403);
        let (_, response) = session.answer(&signed(Request::new("GET", "/")));
        assert_eq!(response.status, 400);
        let (_, response) = session.answer(&signed(Request::new("GET", "/c")));
        assert_eq!(
            response.status, 405,
            "a container GET that is not a listing"
        );
    }

    #[test]
    fn a_session_holds_a_request_to_the_condition_it_carries() {
        let mut session = Session::new("acct", KEY).expect("base64");
        let create = || {
            Request::new("PUT", "/c/b")
                .header("If-None-Match", "*")
                .body(b"x")
        };
        let (_, response) = session.answer(&signed(create()));
        assert_eq!(response.status, 201, "none there");
        let (event, response) = session.answer(&signed(create()));
        assert_eq!(
            (event, response.status),
            (Event::Refused("BlobAlreadyExists".to_string()), 409)
        );
        let matching =
            |method: &str, tag: &str| signed(Request::new(method, "/c/b").header("If-Match", tag));
        let (_, response) = session.answer(&matching("GET", "\"0x2\""));
        assert_eq!(response.status, 412);
        assert_eq!(
            response.header_value("x-ms-error-code"),
            Some("ConditionNotMet")
        );
        let (_, response) = session.answer(&matching("DELETE", "0x2"));
        assert_eq!(response.status, 412, "unquoted as well");
        assert_eq!(session.blobs().len(), 1, "nothing deleted");
        let (_, response) = session.answer(&matching("GET", "\"0x1\""));
        assert_eq!(
            (response.status, response.body.as_slice()),
            (200, &b"x"[..])
        );
        let (_, response) = session.answer(&matching("DELETE", "\"0x1\""));
        assert_eq!(response.status, 202);
        let (_, response) = session.answer(&matching("GET", "\"0x1\""));
        assert_eq!(response.status, 404, "gone");
        let (_, response) = session.answer(&matching("DELETE", "\"0x1\""));
        assert_eq!(response.status, 404);
    }
}
