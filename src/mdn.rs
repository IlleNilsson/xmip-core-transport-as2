//! The Message Disposition Notification: what the receiver answers a
//! message with, RFC 4130 section 7 over RFC 3798.
//!
//! A `multipart/report` of two parts — a human-readable line and a
//! `message/disposition-notification` whose fields say which message this
//! answers, what became of it and the MIC the receiver computed. The sender
//! compares that MIC with its own: matching MICs are the proof the partner
//! got exactly the bytes sent, which is what AS2 exists to give.

use std::fmt::Write;

use codec::base64;
use transport::error::{Result, protocol_error};

use crate::signer::Entity;

/// The `Content-Type` of an MDN before any signature is put around it.
const REPORT: &str = "multipart/report; report-type=disposition-notification";

/// What the receiver reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mdn {
    /// The `Message-ID` this answers.
    pub original_message_id: String,
    /// The partner reporting, as `AS2-To` named it.
    pub recipient: String,
    /// `processed`, or `processed/error: …` and its kin.
    pub disposition: String,
    /// The MIC the receiver computed and the digest it used.
    pub mic: Option<(Vec<u8>, String)>,
}

impl Mdn {
    /// A receipt saying `original_message_id` was processed, with `mic` in
    /// `micalg` over what arrived.
    #[must_use]
    pub fn processed(
        original_message_id: &str,
        recipient: &str,
        mic: Vec<u8>,
        micalg: &str,
    ) -> Self {
        Self {
            original_message_id: original_message_id.to_string(),
            recipient: recipient.to_string(),
            disposition: "automatic-action/MDN-sent-automatically; processed".to_string(),
            mic: Some((mic, micalg.to_string())),
        }
    }

    /// Whether the receiver says the message was processed without error.
    #[must_use]
    pub fn is_processed(&self) -> bool {
        self.disposition
            .rsplit(';')
            .next()
            .is_some_and(|outcome| outcome.trim().eq_ignore_ascii_case("processed"))
    }

    /// This receipt as the entity that goes back in the answer.
    #[must_use]
    pub fn entity(&self) -> Entity {
        let boundary = "xmip-mdn-boundary";
        let mut fields = format!(
            "Reporting-UA: xmip\r\nOriginal-Recipient: rfc822; {r}\r\n\
             Final-Recipient: rfc822; {r}\r\nOriginal-Message-ID: {id}\r\n\
             Disposition: {d}\r\n",
            r = self.recipient,
            id = self.original_message_id,
            d = self.disposition
        );
        if let Some((mic, micalg)) = &self.mic {
            let _ = write!(
                fields,
                "Received-Content-MIC: {}, {micalg}\r\n",
                base64::encode(mic)
            );
        }
        let body = format!(
            "--{boundary}\r\nContent-Type: text/plain\r\n\r\n\
             The message was {}.\r\n\
             --{boundary}\r\nContent-Type: message/disposition-notification\r\n\r\n\
             {fields}\r\n--{boundary}--\r\n",
            if self.is_processed() {
                "processed"
            } else {
                "not processed"
            }
        );
        Entity::new(format!("{REPORT}; boundary=\"{boundary}\""), body)
    }

    /// The receipt an entity carries.
    ///
    /// # Errors
    /// Where the entity is not a `multipart/report` with a disposition
    /// notification in it, or the notification lacks its message id.
    pub fn from_entity(entity: &Entity) -> Result<Self> {
        let boundary = boundary_of(&entity.content_type)?;
        let text = String::from_utf8_lossy(&entity.body);
        let notification = text
            .split(&format!("--{boundary}"))
            .find_map(|part| {
                let (head, body) = part.split_once("\r\n\r\n")?;
                head.to_ascii_lowercase()
                    .contains("message/disposition-notification")
                    .then_some(body)
            })
            .ok_or_else(|| protocol_error("a report with no disposition notification in it"))?;
        let field = |name: &str| {
            notification.lines().find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.trim()
                    .eq_ignore_ascii_case(name)
                    .then(|| value.trim().to_string())
            })
        };
        let mic = field("Received-Content-MIC").and_then(|value| {
            let (digest, micalg) = value.split_once(',')?;
            let digest = base64::decode(digest.trim()).ok()?;
            Some((digest, micalg.trim().to_ascii_lowercase()))
        });
        Ok(Self {
            original_message_id: field("Original-Message-ID")
                .ok_or_else(|| protocol_error("a notification with no Original-Message-ID"))?,
            recipient: field("Final-Recipient")
                .and_then(|value| value.split_once(';').map(|(_, who)| who.trim().to_string()))
                .unwrap_or_default(),
            disposition: field("Disposition").unwrap_or_default(),
            mic,
        })
    }
}

/// The boundary a `multipart/report` names.
fn boundary_of(content_type: &str) -> Result<String> {
    if !content_type
        .to_ascii_lowercase()
        .starts_with("multipart/report")
    {
        return Err(protocol_error(format!(
            "an answer that is not an MDN: {content_type}"
        )));
    }
    content_type
        .split(';')
        .map(str::trim)
        .find_map(|parameter| parameter.strip_prefix("boundary="))
        .map(|value| value.trim_matches('"').to_string())
        .ok_or_else(|| protocol_error("a multipart report with no boundary"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_receipt_reads_back_off_the_entity_it_wrote() {
        let mdn = Mdn::processed("<1@buyer>", "Seller", vec![1, 2, 3, 250], "sha-256");
        let entity = mdn.entity();
        assert!(entity.content_type.starts_with("multipart/report"));
        assert!(entity.body.starts_with(b"--xmip-mdn-boundary\r\n"));
        let read = Mdn::from_entity(&entity).expect("read");
        assert_eq!(read, mdn);
        assert!(read.is_processed());
    }

    #[test]
    fn an_answer_that_is_not_a_report_is_refused() {
        assert!(Mdn::from_entity(&Entity::new("text/plain", b"ok".to_vec())).is_err());
        assert!(Mdn::from_entity(&Entity::new(REPORT, b"no boundary".to_vec())).is_err());
        let hollow = Entity::new(
            format!("{REPORT}; boundary=b"),
            b"--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b--\r\n".to_vec(),
        );
        assert!(Mdn::from_entity(&hollow).is_err());
        let failed = Mdn {
            disposition: "automatic-action/MDN-sent-automatically; processed/error: bad".into(),
            ..Mdn::processed("<1@x>", "y", vec![], "sha-256")
        };
        assert!(!failed.is_processed());
        assert!(
            !Mdn::from_entity(&failed.entity())
                .expect("read")
                .is_processed()
        );
    }

    #[test]
    fn the_mic_travels_in_base_64_and_one_that_is_not_is_no_mic() {
        let mdn = Mdn::processed("<1@buyer>", "Seller", vec![1, 2, 3], "sha-256");
        let entity = mdn.entity();
        let body = String::from_utf8(entity.body.clone()).expect("text");
        assert!(
            body.contains("Received-Content-MIC: AQID, sha-256"),
            "{body}"
        );
        let wrong = Entity::new(
            entity.content_type.clone(),
            body.replace("AQID", "not base64!").into_bytes(),
        );
        assert_eq!(Mdn::from_entity(&wrong).expect("read").mic, None);
    }
}
