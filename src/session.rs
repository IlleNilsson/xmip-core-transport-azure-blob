//! The far end: enough of the Blob service to answer one Location, and what
//! a test or the playground puts on loopback.
//!
//! Not Azure. One session holds blobs in memory, verifies every request
//! against one account key, and answers the four calls with the shapes the
//! service answers them — the enumeration, the blob, the error with its
//! code in the body and in `x-ms-error-code`. A Location that needs
//! durability, leases or a second account talks to the service through
//! [`crate::Client`].

use std::collections::BTreeMap;
use std::net::TcpListener;
use std::time::Duration;

use transport::Arrived;
use transport::error::{Result, protocol_error};
use transport::socket;

use crate::shared_key::Signer;
use crate::xml;
use http::message::{self, Request, Response};
use http::percent::decode;

/// What the client did, as [`Session::serve_one`] reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The client listed `prefix` in `container`.
    Listed { container: String, prefix: String },
    /// The client fetched this blob.
    Retrieved(String),
    /// The client stored a blob; here is the Stream.
    Stored(Arrived),
    /// The client deleted this blob.
    Deleted(String),
    /// The client was answered with this error code.
    Refused(String),
}

pub struct Session {
    signer: Signer,
    blobs: BTreeMap<String, Vec<u8>>,
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
            timeout: None,
        })
    }

    /// Give up on a client that stops mid-request after `timeout`.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Hold these blobs, keyed `container/blob`.
    #[must_use]
    pub fn with_blobs(mut self, blobs: BTreeMap<String, Vec<u8>>) -> Self {
        self.blobs = blobs;
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
        let (stream, _) = socket::accept_tcp(listener, self.timeout)?;
        let (mut reader, mut writer) = socket::split(stream)?;
        let request = message::read_request(&mut reader)?
            .ok_or_else(|| protocol_error("a connection that sent no request"))?;
        let (event, response) = self.answer(&request);
        message::write_response(&mut writer, &response)?;
        Ok(event)
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
            ("GET", false) => self.get(container, blob),
            ("PUT", false) => self.put(container, blob, &request.body),
            ("DELETE", false) => self.delete(container, blob),
            _ => refused(405, "UnsupportedHttpVerb", "not one of the four calls"),
        }
    }

    fn list(&self, container: &str, request: &Request) -> (Event, Response) {
        let prefix = request
            .query_value("prefix")
            .unwrap_or_default()
            .to_string();
        let under = format!("{container}/{prefix}");
        let names: Vec<String> = self
            .blobs
            .keys()
            .filter(|held| held.starts_with(&under))
            .map(|held| held[container.len() + 1..].to_string())
            .collect();
        let response = Response::new(200)
            .header("Content-Type", "application/xml")
            .body(xml::listing(container, &prefix, &names).as_bytes());
        (
            Event::Listed {
                container: container.to_string(),
                prefix,
            },
            response,
        )
    }

    fn get(&self, container: &str, blob: &str) -> (Event, Response) {
        match self.blobs.get(&format!("{container}/{blob}")) {
            Some(bytes) => (
                Event::Retrieved(origin(container, blob)),
                Response::new(200)
                    .header("Content-Type", "application/octet-stream")
                    .header("x-ms-blob-type", "BlockBlob")
                    .body(bytes),
            ),
            None => refused(404, "BlobNotFound", "The specified blob does not exist."),
        }
    }

    fn put(&mut self, container: &str, blob: &str, bytes: &[u8]) -> (Event, Response) {
        self.blobs
            .insert(format!("{container}/{blob}"), bytes.to_vec());
        (
            Event::Stored(Arrived::new(origin(container, blob), bytes)),
            Response::new(201).header("ETag", "\"xmip\""),
        )
    }

    fn delete(&mut self, container: &str, blob: &str) -> (Event, Response) {
        // Unlike S3, the Blob service says when there was nothing to delete.
        match self.blobs.remove(&format!("{container}/{blob}")) {
            Some(_) => (Event::Deleted(origin(container, blob)), Response::new(202)),
            None => refused(404, "BlobNotFound", "The specified blob does not exist."),
        }
    }
}

fn origin(container: &str, blob: &str) -> String {
    format!("azure-blob://{container}/{blob}")
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
            Event::Stored(Arrived::new("azure-blob://c/b", b"x".to_vec()))
        );
        let (_, response) = session.answer(&signed(listing("b")));
        assert!(response.text().contains("<Name>b</Name>"));
        let (_, response) = session.answer(&signed(listing("z")));
        assert!(!response.text().contains("<Name>"));
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
}
