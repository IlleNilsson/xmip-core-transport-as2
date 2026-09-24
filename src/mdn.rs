//! The Message Disposition Notification: what the receiver answers a
//! message with, RFC 4130 section 7 over RFC 3798.
//!
//! A `multipart/report` of two parts — a human-readable line and a
//! `message/disposition-notification` whose fields say which message this
//! answers, what became of it and the MIC the receiver computed. The sender
//! compares that MIC with its own: matching MICs are the proof the partner
//! got exactly the bytes sent, which is what AS2 exists to give. The report
//! is written and read as `codec::mime` writes and reads every multipart
//! body; until 2026-09-24 this file split the body wherever the boundary's
//! text appeared.

use std::fmt::Write;

use codec::base64;
use codec::mime::{self, Part};
use transport::error::{Result, protocol_error};

use crate::signer::Entity;

/// The `Content-Type` of an MDN before any signature is put around it.
const REPORT: &str = "multipart/report; report-type=disposition-notification";
/// The media type of the part that carries the notification's fields.
const NOTIFICATION: &str = "message/disposition-notification";

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
        let boundary = mime::boundary();
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
        let outcome = if self.is_processed() {
            "processed"
        } else {
            "not processed"
        };
        let parts = [
            Part::new(format!("The message was {outcome}.")).header("Content-Type", "text/plain"),
            Part::new(fields).header("Content-Type", NOTIFICATION),
        ];
        Entity::new(
            format!("{REPORT}; boundary=\"{boundary}\""),
            mime::write(&boundary, &parts),
        )
    }

    /// The receipt an entity carries.
    ///
    /// # Errors
    /// Where the entity is not a `multipart/report` with a disposition
    /// notification in it, or the notification lacks its message id.
    pub fn from_entity(entity: &Entity) -> Result<Self> {
        let boundary = boundary_of(&entity.content_type)?;
        let parts = mime::read(&entity.body, boundary)
            .map_err(|refusal| protocol_error(refusal.to_string()))?;
        let notification = parts
            .iter()
            .find(|part| part.content_type().map(mime::media_type).as_deref() == Some(NOTIFICATION))
            .map(|part| String::from_utf8_lossy(&part.body).into_owned())
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
fn boundary_of(content_type: &str) -> Result<&str> {
    if mime::media_type(content_type) != "multipart/report" {
        return Err(protocol_error(format!(
            "an answer that is not an MDN: {content_type}"
        )));
    }
    mime::parameter(content_type, "boundary")
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
        assert!(entity.body.starts_with(b"--=_xmip_"));
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
        let theirs = Entity::new(
            "Multipart/Report; Report-Type=disposition-notification; Boundary = \"q r\"",
            b"--q r\r\nContent-Type: text/plain\r\n\r\nok\r\n--q r\r\n\
              Content-Type: Message/Disposition-Notification\r\n\r\n\
              Original-Message-ID: <9@partner-x>\r\nDisposition: a; processed\r\n\r\n--q r--\r\n"
                .to_vec(),
        );
        let read = Mdn::from_entity(&theirs).expect("a partner's casing and spacing");
        assert_eq!(read.original_message_id, "<9@partner-x>");
        assert!(read.is_processed());
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
