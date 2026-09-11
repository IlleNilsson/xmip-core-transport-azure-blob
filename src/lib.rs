#![forbid(unsafe_code)]

//! Streams that arrive as blobs in an Azure container. One blob is one
//! Stream, its name kept beside it.
//!
//! Blob Storage is the drop box of every organisation that lives in Azure,
//! and its REST API is four calls on a container: list under a prefix, get,
//! put, delete. A Receive Location lists a prefix, gets each blob and
//! deletes it once it is safely a Stream; a Send Location puts a Stream as
//! a block blob. Both are Shared Key over plain HTTP/1.1 on a socket —
//! `https://` with the `tls` feature, which is the http technology's TLS
//! (ADR-0033).
//!
//! ```text
//! shared_key.rs  signing a request, and verifying one
//! xml.rs         the enumeration and the error, picked by hand
//! client.rs      Xmip's side: list, get, put, delete
//! session.rs     the far end a test or the playground runs on loopback
//! ```
//!
//! The endpoint, the percent-encoding and HTTP itself come from the http
//! technology, the flat XML scan from the capability (ADR-0044).
//!
//! Blob Storage has blobs and a lease this transport does not yet take, so
//! [`Transport::claims`] answers [`NoNativeClaim`], ADR-0024 clause 5. The
//! native claim the record names — a renewable blob lease — is a later step.
//!
//! The origin URI is the blob in the protocol's own terms:
//! `azure-blob://container/in/order-1.edi`. A send target is the same form,
//! or a name alone in this transport's container.

pub mod client;
pub mod session;
pub mod shared_key;
pub mod xml;

use std::net::TcpListener;
use std::time::Duration;

pub use client::Client;
use http::endpoint;
pub use session::{Event, Session};
use transport::error::{Result, protocol_error};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::socket;
use transport::{Arrived, Directions, NoNativeClaim, ResourceClaim, Transport};

/// What the loopback pair agrees on: one account with its key in base64
/// as the portal shows it, one container, one blob put there.
const LOOPBACK_ACCOUNT: &str = "probe";
const LOOPBACK_CONTAINER: &str = "probe";
const LOOPBACK_BLOB: &str = "probe.bin";
const LOOPBACK_KEY: &str = "cHJvYmU=";

#[derive(Clone)]
pub struct AzureBlobTransport {
    endpoint: String,
    account: String,
    container: String,
    key: String,
    prefix: String,
    timeout: Option<Duration>,
}

impl AzureBlobTransport {
    /// Speak to the endpoint at `endpoint` — `http://host:port` or
    /// `https://host:port` — as `account`, about `container`.
    #[must_use]
    pub fn new(endpoint: impl Into<String>, account: &str, container: &str) -> Self {
        Self {
            endpoint: endpoint.into(),
            account: account.to_string(),
            container: container.to_string(),
            key: String::new(),
            prefix: String::new(),
            timeout: None,
        }
    }

    /// Sign with this account key, base64 as the portal shows it.
    #[must_use]
    pub fn with_key(mut self, key_base64: &str) -> Self {
        self.key = key_base64.to_string();
        self
    }

    /// Receive only what is under `prefix` — `in/`, say.
    #[must_use]
    pub fn with_prefix(mut self, prefix: &str) -> Self {
        self.prefix = prefix.to_string();
        self
    }

    /// Give up on an endpoint that stops answering after `timeout`.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// The client this transport speaks through.
    ///
    /// # Errors
    /// Where the endpoint is not an HTTP URL, or the key is not base64.
    pub fn client(&self) -> Result<Client> {
        let client = Client::new(&self.endpoint, &self.account, &self.key)?;
        Ok(match self.timeout {
            Some(timeout) => client.timing_out_after(timeout),
            None => client,
        })
    }

    /// A far end that holds this transport's account and key, for a test
    /// or the playground to run on loopback.
    ///
    /// # Errors
    /// Where the key is not base64.
    pub fn session(&self) -> Result<Session> {
        let session = Session::new(&self.account, &self.key)?;
        Ok(match self.timeout {
            Some(timeout) => session.timing_out_after(timeout),
            None => session,
        })
    }

    /// Where a target names the container and blob itself —
    /// `azure-blob://container/blob` — or is a name alone in this
    /// transport's container.
    fn resolve<'a>(&'a self, target: &'a str) -> (&'a str, &'a str) {
        socket::target("azure-blob", target).unwrap_or((&self.container, target))
    }
}

impl Transport for AzureBlobTransport {
    fn name(&self) -> &'static str {
        "azure-blob"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    /// Every blob under the prefix, each deleted once it is a Stream.
    fn receive(&self) -> Result<Vec<Arrived>> {
        let client = self.client()?;
        let mut arrived = Vec::new();
        for blob in client.list(&self.container, &self.prefix)? {
            let bytes = client.get(&self.container, &blob)?;
            client.delete(&self.container, &blob)?;
            arrived.push(Arrived::new(
                format!("azure-blob://{}/{blob}", self.container),
                bytes,
            ));
        }
        Ok(arrived)
    }

    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        let (container, blob) = self.resolve(target);
        self.client()?.put(container, blob, bytes)
    }

    fn claims(&self) -> Option<&dyn ResourceClaim> {
        Some(&NoNativeClaim)
    }
}

impl AzureBlobTransport {
    /// Both ends on this machine: an ephemeral local port, one account key
    /// the far end expects and the near end signs with, the loopback
    /// timeout.
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("http://127.0.0.1:0", LOOPBACK_ACCOUNT, LOOPBACK_CONTAINER)
            .with_key(LOOPBACK_KEY)
            .timing_out_after(LOOPBACK_TIMEOUT)
    }
}

/// A bound session waiting for its one store. The Blob service opens a
/// connection per call, so the session serves one request at a time until
/// one stored.
struct Serving {
    session: Session,
    listener: TcpListener,
    address: String,
}

impl FarEnd for Serving {
    fn address(&self) -> &str {
        &self.address
    }

    fn take_one(self: Box<Self>) -> Result<Arrived> {
        let Self {
            mut session,
            listener,
            ..
        } = *self;
        loop {
            match session.serve_one(&listener)? {
                Event::Stored(arrived) => return Ok(arrived),
                Event::Refused(code) => {
                    return Err(protocol_error(format!("the session refused: {code}")));
                }
                _ => {}
            }
        }
    }
}

impl Loopback for AzureBlobTransport {
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        let (listener, address) = socket::bind_tcp(&endpoint::authority(&self.endpoint)?)?;
        Ok(Box::new(Serving {
            session: self.session()?,
            listener,
            address,
        }))
    }

    /// Put the payload as one block blob, from a fresh near end signing as
    /// this transport does, at the endpoint on `address`.
    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        let near = Self {
            endpoint: format!("http://{address}"),
            ..self.clone()
        };
        near.send(LOOPBACK_BLOB, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::JoinHandle;

    const KEY: &str = "c2VjcmV0";

    fn node(endpoint: &str, key: &str) -> AzureBlobTransport {
        AzureBlobTransport::new(endpoint, "acct", "orders")
            .with_key(key)
            .with_prefix("in/")
            .timing_out_after(Duration::from_secs(2))
    }

    fn serve(
        mut session: Session,
        listener: TcpListener,
        requests: usize,
    ) -> JoinHandle<(Session, Vec<Event>)> {
        std::thread::spawn(move || {
            let events = (0..requests)
                .map(|_| session.serve_one(&listener).expect("served"))
                .collect();
            (session, events)
        })
    }

    #[test]
    fn what_is_sent_to_a_session_is_received_back_and_deleted() {
        let (listener, address) = socket::bind_tcp("127.0.0.1:0").expect("bind");
        let near = node(&format!("http://{address}"), KEY);
        // Two puts, one list, then a get and a delete per blob under in/.
        let far_end = serve(near.session().expect("base64"), listener, 7);
        near.send("in/1.edi", b"UNA:+.? '").expect("a name alone");
        near.send("azure-blob://orders/in/2.edi", b"")
            .expect("a full target");
        let mut arrived = near.receive().expect("received");
        arrived.sort_by(|a, b| a.origin_uri.cmp(&b.origin_uri));
        assert_eq!(arrived.len(), 2);
        assert_eq!(arrived[0].origin_uri, "azure-blob://orders/in/1.edi");
        assert_eq!(arrived[0].bytes, b"UNA:+.? '");
        assert_eq!(arrived[1].origin_uri, "azure-blob://orders/in/2.edi");
        assert!(arrived[1].bytes.is_empty());
        let (session, events) = far_end.join().expect("thread");
        assert!(session.blobs().is_empty(), "deleted after retrieve");
        assert_eq!(
            events[0],
            Event::Stored(Arrived::new(
                "azure-blob://orders/in/1.edi",
                b"UNA:+.? '".to_vec()
            ))
        );
        let deleted = events.iter().filter(|e| matches!(e, Event::Deleted(_)));
        assert_eq!(deleted.count(), 2);
    }

    #[test]
    fn a_wrong_key_is_refused_with_azures_own_status_and_code() {
        let (listener, address) = socket::bind_tcp("127.0.0.1:0").expect("bind");
        let far_end = serve(
            node("http://x", KEY).session().expect("base64"),
            listener,
            1,
        );
        let failure = node(&format!("http://{address}"), "d3Jvbmc=")
            .send("in/1.edi", b"x")
            .expect_err("refused");
        assert!(
            failure.message.contains("403 AuthenticationFailed"),
            "{failure}"
        );
        assert!(!failure.retryable);
        let (_, events) = far_end.join().expect("thread");
        assert_eq!(
            events,
            vec![Event::Refused("AuthenticationFailed".to_string())]
        );
    }

    #[test]
    fn blobs_are_artefacts_without_a_lock_and_an_unreachable_endpoint_is_retryable() {
        let near = node("http://127.0.0.1:1", KEY);
        assert!(near.claims().is_some());
        assert_eq!(near.name(), "azure-blob");
        assert!(near.directions().receives() && near.directions().sends());
        assert!(near.receive().expect_err("nothing listening").retryable);
        let failure = node("orders.local", KEY)
            .send("b", b"")
            .expect_err("no scheme");
        assert!(!failure.retryable);
        assert!(
            !node("http://x", "not base64!")
                .send("b", b"")
                .expect_err("key")
                .retryable
        );
    }

    #[test]
    fn the_loopback_stores_one_blob_through_its_own_session() {
        let pair = AzureBlobTransport::loopback();
        let arrived = pair.round(b"a blob").expect("round");
        assert_eq!(arrived.bytes, b"a blob");
        assert_eq!(arrived.origin_uri, "azure-blob://probe/probe.bin");
        assert_eq!(pair.name(), "azure-blob");
        assert_eq!(pair.ceiling(), None);
    }

    /// The Playground's edge payloads, written here so the crate does not
    /// depend on it.
    fn edge_payloads() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("empty", Vec::new()),
            ("one byte", vec![0x2a]),
            ("every byte", (0..=255).collect()),
            ("nul run", vec![0; 512]),
            ("high bytes", vec![0xff; 512]),
            ("crlf storm", b"\r\n".repeat(400)),
        ]
    }

    #[test]
    fn the_loopback_returns_the_edge_payloads_whole() {
        let pair = AzureBlobTransport::loopback();
        for (name, payload) in edge_payloads() {
            assert!(pair.refuses(&payload).is_none(), "{name}");
            let arrived = pair.round(&payload).expect(name);
            assert_eq!(arrived.bytes, payload, "{name}");
        }
    }
}
