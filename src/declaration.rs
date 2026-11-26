//! What a Location of this technology is configured with: its declaration,
//! which `Configured` reads, built with the crate's `declaration` feature
//! alone and the code behind the default (ADR-0064, amendments 2026-10-22
//! and 2026-11-26), for the library the surfaces load to carry (open
//! problem 48).

use xcore::settings::{Applies, Kind, Presence, Setting, Settings};

/// Every setting a Location takes beyond its address, the Blob service
/// endpoint, `https://<account>.blob.core.windows.net`. The account key is
/// the Location's `secret`, a password secret the Administration Database
/// keeps, never a setting.
pub const SETTINGS: &Settings = &Settings {
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
pub const SCHEMES: &[&str] = &["azure-blob"];
