//! What a Location of this technology is configured with: its declaration,
//! which `Configured` reads, built with the crate's `declaration` feature
//! alone and the code behind the default (ADR-0064, amendments 2026-10-22
//! and 2026-11-26), for the library the surfaces load to carry (open
//! problem 48).

use xcore::settings::{Applies, Kind, Presence, Setting, Settings};

/// Every setting a Location takes beyond its address, the Party's endpoint
/// a Send Location posts to, or the one a Receive Location listens at:
/// `as2://host:port/as2`. The S/MIME certificate is the Location's
/// credentials, not a setting.
pub const SETTINGS: &Settings = &Settings {
    technology: env!("CARGO_PKG_NAME"),
    settings: &[
        Setting {
            name: "as2_id",
            kind: Kind::Text,
            presence: Presence::Required,
            meaning: "This Party's own AS2 name: AS2-From on a send, the AS2-To a \
                      received message must carry.",
            applies: Applies::Both,
        },
        Setting {
            name: "to_party_id",
            kind: Kind::Text,
            presence: Presence::Required,
            meaning: "The AS2 name of the Party sent to, written as AS2-To.",
            applies: Applies::Send,
        },
        transport::configured::timeout(
            Applies::Both,
            None,
            "How long a Party that stops mid-message is waited on; unbounded \
             when left out.",
        ),
    ],
};

/// `as2://`, and `as2s://`, which TLS guards.
pub const SCHEMES: &[&str] = &["as2", "as2s"];
