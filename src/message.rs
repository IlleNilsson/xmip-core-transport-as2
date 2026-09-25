//! One AS2 message: the partner headers RFC 4130 section 6 puts on an HTTP
//! POST, the entity that is its body, and the MIC the receipt hashes it to.
//!
//! `AS2-From` and `AS2-To` are the partners as the agreement names them,
//! `Message-ID` is what the MDN answers, and `Disposition-Notification-To`
//! is the ask for that MDN — with `Disposition-Notification-Options` saying
//! it should be signed, and with what. The four are read back off a request
//! the same way they were written on to it.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use net::http::Request;
use sha2::{Digest, Sha256};
use transport::error::{Result, protocol_error};

use crate::signer::Entity;

/// The `AS2-Version` this crate writes.
pub const VERSION: &str = "1.2";

/// One message as the headers describe it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub from: String,
    pub to: String,
    pub message_id: String,
    /// Where the sender wants the MDN, or `None` where none was asked for.
    pub notification_to: Option<String>,
    /// The digest the sender wants the MDN's MIC in, where it asked for one.
    pub micalg: Option<String>,
    pub entity: Entity,
}

impl Message {
    /// A message from `from` to `to`, asking for an MDN back on the
    /// connection in `micalg`.
    #[must_use]
    pub fn new(from: &str, to: &str, micalg: &str, entity: Entity) -> Self {
        Self {
            from: from.to_string(),
            to: to.to_string(),
            message_id: next_message_id(),
            notification_to: Some(from.to_string()),
            micalg: Some(micalg.to_string()),
            entity,
        }
    }

    /// The POST that carries this message to `path`, `Host` set to
    /// `authority`.
    #[must_use]
    pub fn request(&self, authority: &str, path: &str) -> Request {
        let mut request = Request::new("POST", path)
            .header("Host", authority)
            .header("AS2-Version", VERSION)
            .header("AS2-From", &self.from)
            .header("AS2-To", &self.to)
            .header("Message-ID", &self.message_id)
            .header("Content-Type", &self.entity.content_type)
            .body(&self.entity.body);
        if let Some(to) = &self.notification_to {
            request = request.header("Disposition-Notification-To", to);
        }
        if let Some(micalg) = &self.micalg {
            let options = format!(
                "signed-receipt-protocol=optional, pkcs7-signature; \
                 signed-receipt-micalg=optional, {micalg}"
            );
            request = request.header("Disposition-Notification-Options", &options);
        }
        request
    }

    /// The message a POST carries.
    ///
    /// # Errors
    /// Where the request is not a POST, or `AS2-From`, `AS2-To` or
    /// `Message-ID` is missing — a peer that is not speaking AS2.
    pub fn from_request(request: &Request) -> Result<Self> {
        if request.method != "POST" {
            return Err(protocol_error(format!(
                "an AS2 message is a POST, not a {}",
                request.method
            )));
        }
        let required = |name: &str| {
            request
                .header_value(name)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .ok_or_else(|| protocol_error(format!("a POST with no {name} header")))
        };
        let micalg = request
            .header_value("Disposition-Notification-Options")
            .and_then(requested_micalg);
        Ok(Self {
            from: required("AS2-From")?,
            to: required("AS2-To")?,
            message_id: required("Message-ID")?,
            notification_to: request
                .header_value("Disposition-Notification-To")
                .map(str::to_string),
            micalg,
            entity: Entity::new(
                request
                    .header_value("Content-Type")
                    .unwrap_or("application/octet-stream"),
                request.body.clone(),
            ),
        })
    }

    /// Whether the sender asked for an MDN at all.
    #[must_use]
    pub fn wants_receipt(&self) -> bool {
        self.notification_to.is_some()
    }
}

/// The `signed-receipt-micalg` a `Disposition-Notification-Options` header
/// asks for: `sha-256` out of
/// `signed-receipt-protocol=optional, pkcs7-signature; signed-receipt-micalg=optional, sha-256`.
fn requested_micalg(options: &str) -> Option<String> {
    options
        .split(';')
        .map(str::trim)
        .find_map(|parameter| parameter.strip_prefix("signed-receipt-micalg="))
        .and_then(|value| value.split(',').nth(1))
        .map(|algorithm| algorithm.trim().to_ascii_lowercase())
}

/// The MIC of an entity in `micalg`: RFC 4130 section 7.3.1, the digest
/// over the content as it travelled. Only `sha-256` is spoken.
///
/// # Errors
/// Where `micalg` names a digest this crate does not compute.
pub fn mic(micalg: &str, body: &[u8]) -> Result<Vec<u8>> {
    match micalg.to_ascii_lowercase().as_str() {
        "sha-256" | "sha256" => Ok(Sha256::digest(body).to_vec()),
        other => Err(protocol_error(format!(
            "a receipt digest this transport does not compute: {other}"
        ))),
    }
}

/// A `Message-ID` that no other message from this process carries:
/// `<nanos.n@xmip>`.
fn next_message_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("<{nanos}.{n}@xmip>")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_message_reads_back_off_the_request_it_wrote() {
        let entity = Entity::new("application/edi-x12", b"ISA*00*".to_vec());
        let message = Message::new("Buyer", "Seller", "sha-256", entity);
        let request = message.request("as2.seller:8080", "/as2");
        assert_eq!(request.header_value("AS2-From"), Some("Buyer"));
        assert_eq!(request.header_value("Host"), Some("as2.seller:8080"));
        assert!(
            request
                .header_value("Disposition-Notification-Options")
                .expect("asked")
                .ends_with("sha-256")
        );
        let read = Message::from_request(&request).expect("read");
        assert_eq!(read, message);
        assert!(read.wants_receipt());
        assert!(read.message_id.starts_with('<'));
        assert_ne!(
            message.message_id,
            Message::new("a", "b", "sha-256", Entity::new("t", vec![])).message_id
        );
    }

    #[test]
    fn a_post_without_the_partner_headers_is_refused() {
        let request = Request::new("POST", "/as2").body(b"ISA");
        assert!(Message::from_request(&request).is_err());
        let get = Request::new("GET", "/as2")
            .header("AS2-From", "a")
            .header("AS2-To", "b")
            .header("Message-ID", "<1@x>");
        assert!(Message::from_request(&get).is_err());
        let bare = Request::new("POST", "/as2")
            .header("AS2-From", "a")
            .header("AS2-To", "b")
            .header("Message-ID", "<1@x>");
        let message = Message::from_request(&bare).expect("read");
        assert!(!message.wants_receipt());
        assert_eq!(message.entity.content_type, "application/octet-stream");
    }

    #[test]
    fn the_mic_is_sha_256_over_the_body_and_nothing_else_is_spoken() {
        let digest = mic("sha-256", b"ISA").expect("digested");
        assert_eq!(digest.len(), 32);
        assert_eq!(mic("SHA256", b"ISA").expect("digested"), digest);
        assert!(mic("md5", b"ISA").is_err());
        assert_eq!(
            requested_micalg(concat!(
                "signed-receipt-protocol=optional, pkcs7-signature; ",
                "signed-receipt-micalg=optional, SHA-256"
            )),
            Some("sha-256".to_string())
        );
        assert_eq!(requested_micalg("nothing"), None);
    }
}
