#![forbid(unsafe_code)]

//! Streams that arrive as blobs in an Azure container. One blob is one
//! Stream, its name kept beside it.
//!
//! Blob Storage is the drop box of every organization that lives in Azure,
//! and its REST API is four calls on a container: list under a prefix, get,
//! put, delete. A Receive Location lists a prefix, gets each blob as the
//! runtime first reads it, and deletes it once the runtime accepts it after
//! the whole receive cycle, both only while it bears the `Etag` it was
//! listed with — one refused stays where it lies and is not received again
//! while its `Etag` is unchanged, one whose cycle failed stays for the next
//! receive; a Send Location puts a Stream as a block blob.
//! Both are Shared Key over plain HTTP/1.1 on a socket — `https://` with
//! the `tls` feature, which is the http technology's TLS (ADR-0033).
//!
//! ```text
//! xml.rs         the enumeration and the error, picked by hand
//! client.rs      Xmip's side: list, get and delete as listed, put, put new
//! container.rs   the container as the capability's receive and claim reach it
//! session.rs     the far end a test or the essentials runs on loopback
//! ```
//!
//! The endpoint, HTTP itself, the RFC 1123 date and the judgment of an
//! answer come from the http technology, the percent-encoding from `net`,
//! Shared Key from the Azure crate, the flat XML scan from the capability (ADR-0044).
//! Shared Key lived here until the owner's ruling of 2026-09-22 put what
//! Azure speaks in the Azure crate.
//!
//! **One node receives a blob** (ADR-0024, amendment 2026-11-20): a receive
//! claims each blob it hands over by putting `<name>.xmip-claim` beside it
//! with `If-None-Match: *`, which the service performs "only if the
//! resource doesn't exist" — the capability's claim, written once
//! (`transport::listed::Claims`). The claim holds the node's location and
//! the time; it is deleted as it was put however the cycle ends, and a
//! node that starts again deletes every claim its name still holds. Not a
//! blob lease, which would lock the blob against its producer's own writes
//! while it is held. [`Transport::claims`] answers the same claim for one
//! blob by its address.
//!
//! The origin URI is the blob in the protocol's own terms:
//! `azure-blob://container/in/order-1.edi`. A send target is the same form,
//! or a name alone in this transport's container.

pub mod client;
pub mod container;
pub mod session;
pub mod xml;

use std::net::TcpListener;
use std::time::Duration;

pub use client::Client;
use http::endpoint::Connections;
use net::{Endpoint, Target};
pub use session::{Event, Session};
use transport::claim::Claimant;
use transport::error::{Result, protocol_error};
use transport::listed::Claims;
use transport::listening::Listening;
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::socket;
use transport::{ArrivalIdentity, NodeLocation};
use transport::{Arrived, Configured, Directions, ResourceClaim, Transport};
use xcore::settings::{Applies, Kind, Presence, Read, Setting, Settings};

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
    /// The connections kept to the service, shared by every client this
    /// makes.
    connections: Connections,
    /// The claims this Location makes, and the blobs it refused and left
    /// in the container, each with its `Etag`; a clone shares them.
    claims: Claims,
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
            connections: Connections::new(),
            claims: Claims::new(Claimant::process()),
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

    /// The client this transport speaks through.
    ///
    /// # Errors
    /// Where the endpoint is not an HTTP URL, or the key is not base64.
    pub fn client(&self) -> Result<Client> {
        let client = Client::new(&self.endpoint, &self.account, &self.key)?;
        let client = client.sharing(self.connections.clone());
        Ok(match self.timeout {
            Some(timeout) => client.timing_out_after(timeout),
            None => client,
        })
    }

    /// A far end that holds this transport's account and key, for a test
    /// or the essentials to run on loopback.
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
        Target::under(Self::SCHEMES, target).map_or((&self.container, target), |named| {
            (named.authority(), named.path())
        })
    }
}

impl Transport for AzureBlobTransport {
    fn name(&self) -> &'static str {
        "azure-blob"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    fn arrivals(&self) -> transport::Arrivals {
        transport::Arrivals::Ordered("a receive lists again what is not yet told")
    }

    fn waiting(&self) -> transport::Waiting {
        transport::Waiting::Polled("a receive lists the container and returns")
    }

    /// Every blob under the prefix that this node's claim wins, listed by
    /// the capability's one object-store receive
    /// ([`transport::listed::Claims::listed`]): each claimed by a Put Blob
    /// of its claim with `If-None-Match: *`, one passed over where
    /// another's claim lies. The receive gets and deletes nothing, each
    /// blob's `GET` is made when the runtime first reads its body — whole,
    /// `net::http` reads a `GET` body whole — and its acknowledgement
    /// deletes it on [`transport::Verdict::Accepted`] only, both with
    /// `If-Match` the `Etag` it was listed with: one written again or gone
    /// since is not read, and not deleted ([`Client::get_as_listed`],
    /// [`Client::delete_as_listed`]). On
    /// [`transport::Verdict::Refused`] it is left where it lies and this
    /// Location does not receive it again while its `Etag` is unchanged —
    /// one written again is a new arrival; the memory is the node
    /// process's, so a node started again receives it once more. On
    /// [`transport::Verdict::Failed`] it is left for the next receive to
    /// list and get again. Whatever the verdict, its claim is deleted.
    fn receive_up_to(&self, most: usize) -> Result<Vec<Arrived>> {
        self.claims.listed(&self.container()?, most)
    }

    fn sending(&self) -> transport::Sending {
        transport::Sending::Gathered(
            "the HTTP client writes a request whole, its length counted from it",
        )
    }

    fn send_from(&self, target: &str, outgoing: transport::Outgoing<'_>) -> Result<()> {
        let bytes: &[u8] = &outgoing.gather()?;
        let (container, blob) = self.resolve(target);
        self.client()?.put(container, blob, bytes)
    }

    fn claims(&self) -> Option<&dyn ResourceClaim> {
        Some(self)
    }
}

impl Configured for AzureBlobTransport {
    /// The address is the Blob service endpoint,
    /// `https://<account>.blob.core.windows.net`. The account key is the
    /// Location's credentials, not a setting: a secret never is.
    const SETTINGS: &'static Settings = &Settings {
        technology: env!("CARGO_PKG_NAME"),
        settings: &[
            Setting {
                name: "account",
                kind: Kind::Text,
                presence: Presence::Required,
                meaning: "The storage account requests are signed as.",
                applies: Applies::Both,
            },
            Setting {
                name: "container",
                kind: Kind::Text,
                presence: Presence::Required,
                meaning: "The container blobs are taken from, and put in when a send target \
                          names none.",
                applies: Applies::Both,
            },
            Setting {
                name: "prefix",
                kind: Kind::Text,
                presence: Presence::Optional,
                meaning: "The name prefix a Receive Location takes blobs under, in/; the \
                          whole container when left out.",
                applies: Applies::Receive,
            },
            transport::configured::timeout(
                Applies::Both,
                None,
                "How long an endpoint that stops answering is waited on; unbounded \
                 when left out.",
            ),
        ],
    };

    /// The schemes a Location's address is entered with to choose this technology.
    const SCHEMES: &'static [&'static str] = &["azure-blob"];

    fn timeout_kept(&mut self) -> Option<&mut dyn transport::configured::TimeoutKept> {
        Some(&mut self.timeout)
    }

    fn configured(address: &str, settings: &Read) -> Result<Self> {
        // The account key comes through the Location's credentials.
        let mut transport = Self::new(
            address,
            settings.text("account"),
            settings.text("container"),
        );
        if let Some(prefix) = settings.optional_text("prefix") {
            transport = transport.with_prefix(prefix);
        }
        Ok(transport)
    }

    /// The connections its clients share, an HTTP/2 one's frames in a span
    /// counted on `clock`, its node's (ADR-0068, amendment 2026-11-16).
    fn timed_by(mut self, clock: &std::sync::Arc<dyn xcore::Clock>) -> Self {
        self.connections = self.connections.timed_by(clock);
        self
    }

    /// Claims made in `node`'s name from here on; every claim that name
    /// still holds in the container is deleted by the first receive that
    /// reaches it (ADR-0024, amendment 2026-11-20).
    fn on_node(mut self, node: &NodeLocation) -> Result<Self> {
        self.claims = Claims::recovering(Claimant::of(node));
        Ok(self)
    }
}

/// The blob `blob` in `container`, as an origin says it, under the scheme
/// above: `azure-blob://container/blob`. The one place the form is
/// written: the transport's receive, the session's answers and the
/// azure-blob archive's receipt all name a blob by it.
#[must_use]
pub fn origin(container: &str, blob: &str) -> String {
    format!("azure-blob://{container}/{blob}")
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

impl Loopback for AzureBlobTransport {
    fn arrival_identity(&self) -> ArrivalIdentity {
        ArrivalIdentity::Unnamed(
            "an object names no sender: the bucket it was taken from is in its origin",
        )
    }

    /// A bound session waiting for its one store. The Blob service opens a
    /// connection per call, so the session serves one request at a time
    /// until one stored.
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        let mut session = self.session()?;
        Ok(Box::new(Listening::new(
            move |listener: &TcpListener| loop {
                match session.serve_one(listener)? {
                    Event::Stored(arrived) => return Ok(arrived),
                    Event::Refused(code) => {
                        return Err(protocol_error(format!("the session refused: {code}")));
                    }
                    _ => {}
                }
            },
            socket::bind_tcp(&Endpoint::parse(&self.endpoint)?.address())?,
        )))
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
    use std::assert_matches;
    use std::io::Read as _;
    use std::thread::JoinHandle;
    use transport::Taken;

    const KEY: &str = "c2VjcmV0";

    fn node(endpoint: &str, key: &str) -> AzureBlobTransport {
        AzureBlobTransport::new(endpoint, "acct", "orders")
            .with_key(key)
            .with_prefix("in/")
            .timing_out_after(Duration::from_secs(2))
    }

    #[test]
    fn azure_blob_declares_its_settings_and_reads_through_them() {
        use xcore::settings::Given;
        assert_eq!(
            AzureBlobTransport::SETTINGS.problems(),
            Vec::<String>::new()
        );
        let text = |name: &str, value: &str| (name.to_string(), Given::Text(value.to_string()));
        let endpoint = "https://acct.blob.core.windows.net";
        let given = [
            text("account", "acct"),
            text("container", "orders"),
            text("prefix", "in/"),
            text("timeout", "5s"),
        ];
        let received = AzureBlobTransport::open(endpoint, Applies::Receive, &given).expect("built");
        assert_eq!(received.endpoint, endpoint);
        assert_eq!(
            (received.account.as_str(), received.container.as_str()),
            ("acct", "orders")
        );
        assert_eq!(received.prefix, "in/");
        assert_eq!(received.timeout, Some(Duration::from_secs(5)));
        assert!(received.key.is_empty(), "the key is the credentials'");
        let Err(refused) = AzureBlobTransport::open(endpoint, Applies::Send, &given[..1]) else {
            panic!("the container is required");
        };
        assert!(refused.message.contains("\"container\""), "{refused}");
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
    fn a_blob_is_got_when_read_deleted_when_accepted_and_left_when_refused_or_failed() {
        let (listener, address) = socket::bind_tcp("127.0.0.1:0").expect("bind");
        let near = node(&format!("http://{address}"), KEY);
        // Three puts; a list, three claims, the one get read, its delete,
        // its claim's, the other two claims'; a list, a claim, a get, a
        // delete, its claim's; a list to see what is left.
        let far_end = serve(near.session().expect("base64"), listener, 18);
        near.send("in/1.edi", b"UNA:+.? '").expect("a name alone");
        near.send("azure-blob://orders/in/2.edi", b"")
            .expect("a full target");
        near.send("in/3.edi", b"third").expect("a name alone");
        let mut arrived = near.receive().expect("received");
        arrived.sort_by(|a, b| a.origin_uri.cmp(&b.origin_uri));
        assert_eq!(arrived.len(), 3);
        assert!(arrived.iter().all(Arrived::defers));
        let third = arrived.pop().expect("third");
        let second = arrived.pop().expect("second");
        assert_eq!(second.origin_uri, "azure-blob://orders/in/2.edi");
        let first = arrived.pop().expect("first").taken().expect("accepted");
        assert_eq!(first.origin_uri, "azure-blob://orders/in/1.edi");
        assert_eq!(first.bytes, b"UNA:+.? '");
        second.failed().expect("left");
        third
            .refused(transport::Refusal::Unacceptable)
            .expect("left");
        let again = near.receive().expect("received again");
        assert_eq!(again.len(), 1, "the failed one, not the refused one");
        let again = again.into_iter().next().expect("one").taken().expect("ok");
        assert_eq!(again.origin_uri, "azure-blob://orders/in/2.edi");
        assert_eq!(again.bytes, [] as [u8; 0]);
        let left = near
            .client()
            .expect("client")
            .list("orders", "in/")
            .expect("list");
        assert_eq!(
            left,
            [("in/3.edi".to_string(), "0x3".to_string())],
            "still there"
        );
        let (session, events) = far_end.join().expect("thread");
        assert_eq!(session.blobs().len(), 1, "only the refused one is held");
        assert_eq!(
            events[0],
            Event::Stored(Taken::new(
                "azure-blob://orders/in/1.edi",
                b"UNA:+.? '".to_vec()
            ))
        );
        let named = |blob: &str| format!("azure-blob://orders/in/{blob}");
        assert_matches!(events[3], Event::Listed { .. });
        assert_matches!(
            &events[4],
            Event::Stored(claim) if claim.origin_uri == named("1.edi.xmip-claim"),
            "claimed beside it"
        );
        assert_eq!(
            events[7..12],
            [
                Event::Retrieved(named("1.edi")),
                Event::Deleted(named("1.edi")),
                Event::Deleted(named("1.edi.xmip-claim")),
                Event::Deleted(named("2.edi.xmip-claim")),
                Event::Deleted(named("3.edi.xmip-claim"))
            ],
            "only what was read was got, only what was accepted deleted, every claim let go"
        );
        assert_matches!(events[12], Event::Listed { .. });
        assert_eq!(
            events[14..17],
            [
                Event::Retrieved(named("2.edi")),
                Event::Deleted(named("2.edi")),
                Event::Deleted(named("2.edi.xmip-claim"))
            ]
        );
        assert_matches!(events[17], Event::Listed { .. });
    }

    #[test]
    fn two_nodes_listing_one_container_never_both_receive_one_blob() {
        let (listener, address) = socket::bind_tcp("127.0.0.1:0").expect("bind");
        let on = |place: &str| {
            let location =
                NodeLocation::new(format!("process-{}/place-{place}", std::process::id()));
            node(&format!("http://{address}"), KEY)
                .on_node(&location)
                .expect("on its node")
        };
        let (first, second) = (on("first"), on("second"));
        // A put; the first's list and claim; the second's list, and its
        // read of the claim it finds as it starts; the first's get, delete
        // and its claim's; the second's list.
        let far_end = serve(first.session().expect("base64"), listener, 9);
        first.send("in/1.edi", b"once").expect("put");
        let won = first.receive().expect("listed");
        assert!(second.receive().expect("listed").is_empty(), "held");
        let taken = won.into_iter().next().expect("won").taken().expect("ok");
        assert_eq!(taken.bytes, b"once");
        assert!(second.receive().expect("listed").is_empty(), "gone");
        let (session, events) = far_end.join().expect("thread");
        assert!(session.blobs().is_empty(), "the blob and its claim");
        let claim = "azure-blob://orders/in/1.edi.xmip-claim".to_string();
        assert_eq!(
            events[4],
            Event::Retrieved(claim),
            "another node's, and left"
        );
    }

    #[test]
    fn a_refused_blob_is_not_received_again_until_it_is_written_again() {
        let (listener, address) = socket::bind_tcp("127.0.0.1:0").expect("bind");
        let near = node(&format!("http://{address}"), KEY);
        // A put; a list, a claim, its delete; a list; a put again; a list,
        // a claim, a get, a delete, its claim's.
        let far_end = serve(near.session().expect("base64"), listener, 11);
        near.send("in/1.edi", b"first").expect("put");
        let refused = near.receive().expect("received").remove(0);
        refused
            .refused(transport::Refusal::Forbidden)
            .expect("left");
        assert!(near.receive().expect("listed").is_empty(), "unchanged");
        near.send("in/1.edi", b"second").expect("written again");
        let again = near
            .receive()
            .expect("listed")
            .remove(0)
            .taken()
            .expect("ok");
        assert_eq!(again.bytes, b"second", "another Etag, a new arrival");
        let (session, _) = far_end.join().expect("thread");
        assert!(session.blobs().is_empty(), "accepted, so deleted");
    }

    #[test]
    fn a_replacement_between_read_and_acceptance_stays_for_the_next_listing() {
        let (listener, address) = socket::bind_tcp("127.0.0.1:0").expect("bind");
        let near = node(&format!("http://{address}"), KEY);
        // A put; a list, a claim, the get read; a put again; the delete
        // refused, its claim's; a list, a claim, a get, a delete, its
        // claim's.
        let far_end = serve(near.session().expect("base64"), listener, 12);
        near.send("in/1.edi", b"first").expect("put");
        let listed = near.receive().expect("listed").remove(0);
        let (_, mut body, told) = listed.into_parts();
        let mut read = Vec::new();
        body.read_to_end(&mut read).expect("read as listed");
        assert_eq!(read, b"first");
        near.send("in/1.edi", b"second").expect("written again");
        told.acknowledge(transport::Verdict::Accepted)
            .expect("told done");
        let again = near.receive().expect("listed").remove(0);
        let again = again.taken().expect("the replacement is still there");
        assert_eq!(again.bytes, b"second");
        let (session, events) = far_end.join().expect("thread");
        assert_eq!(
            events[5],
            Event::Refused("ConditionNotMet".to_string()),
            "the first delete held to the Etag listed"
        );
        assert!(session.blobs().is_empty(), "each deleted as it was listed");
    }

    #[test]
    fn a_replacement_between_listing_and_first_read_is_not_read_under_the_old_stamp() {
        let (listener, address) = socket::bind_tcp("127.0.0.1:0").expect("bind");
        let near = node(&format!("http://{address}"), KEY);
        // A put; a list, a claim; a put again; the get refused, its
        // claim's delete; a list, a claim, a get, a delete, its claim's.
        let far_end = serve(near.session().expect("base64"), listener, 11);
        near.send("in/1.edi", b"first").expect("put");
        let listed = near.receive().expect("listed").remove(0);
        near.send("in/1.edi", b"second").expect("written again");
        let failure = listed.taken().expect_err("not read under the old Etag");
        assert!(
            failure.message.contains("changed since it was listed"),
            "{failure}"
        );
        assert!(failure.retryable, "{failure}");
        let again = near.receive().expect("listed").remove(0);
        let again = again.taken().expect("a new arrival");
        assert_eq!(again.bytes, b"second");
        let (session, events) = far_end.join().expect("thread");
        assert_eq!(events[4], Event::Refused("ConditionNotMet".to_string()));
        assert!(session.blobs().is_empty(), "accepted as listed, so deleted");
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
    fn blobs_are_claimed_artifacts_and_an_unreachable_endpoint_is_retryable() {
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

    /// The Essentials' edge payloads, written here so the crate does not
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
