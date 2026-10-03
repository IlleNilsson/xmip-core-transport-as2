//! What a received message earns once its receive cycle has ended: its
//! MDN where the cycle accepted it, an error MDN where it refused it,
//! `503` where Xmip could not complete it.
//!
//! The MIC is computed as the message is read — it is over what arrived —
//! and the MDN is signed and written only on [`Verdict::Accepted`]: a
//! receipt is the Party's proof of delivery, so none goes back before the
//! Stream is Xmip's (runtime-model section 5). [`Verdict::Refused`] answers
//! the error disposition, `processed/error:` with the RFC 4130 section
//! 7.4.3 modifier that says why (`authentication-failed` for a sender not
//! identified, `unexpected-processing-error` otherwise), signed as any
//! MDN: a final answer the Party files and does not send again. Where the
//! Party asked for no MDN, the refusal is HTTP's own `4xx`
//! (`http::server::refused`). [`Verdict::Failed`] answers `503 Service
//! Unavailable`, never an error MDN: a `503` is the transient failure RFC
//! 4130's senders retry, so the Party keeps the message and sends it again.

use http::server;
use net::http::Response;
use transport::error::Result;
use transport::{Refusal, Verdict};

use crate::mdn::Mdn;
use crate::message::{self, Message};
use crate::signer::{Entity, Signer};

/// The answer a message waits for.
#[derive(Clone, Debug)]
pub struct Receipt {
    me: String,
    party: String,
    /// The MDN, where the Party asked for one.
    mdn: Option<Mdn>,
}

impl Receipt {
    /// What `message`, unwrapped to `entity`, is answered with on
    /// acceptance by Party `me`.
    ///
    /// # Errors
    /// Where the Party asked for its MIC in a digest this crate does not
    /// compute.
    pub fn for_message(message: &Message, entity: &Entity, me: &str) -> Result<Self> {
        let mdn = if message.wants_receipt() {
            let micalg = message.micalg.as_deref().unwrap_or("sha-256");
            let mic = message::mic(micalg, &entity.body)?;
            Some(Mdn::processed(&message.message_id, me, mic, micalg))
        } else {
            None
        };
        Ok(Self {
            me: me.to_string(),
            party: message.from.clone(),
            mdn,
        })
    }

    /// The answer `verdict` earns: on acceptance the MDN, wrapped by
    /// `signer`, or `200` where none was asked for; on refusal the error
    /// MDN, wrapped by `signer`, or the `4xx` that says why where none was
    /// asked for; `503` where Xmip could not complete the cycle.
    ///
    /// # Errors
    /// Where the signer could not sign the MDN.
    pub fn answer(&self, verdict: Verdict, signer: &dyn Signer) -> Result<Response> {
        let mdn = match (verdict, &self.mdn) {
            (Verdict::Failed, _) => {
                return Ok(Response::new(server::FAILED)
                    .body(b"the message was not taken into custody; send it again"));
            }
            (Verdict::Accepted, None) => return Ok(Response::new(200)),
            (Verdict::Refused(why), None) => return Ok(Response::new(server::refused(why))),
            (Verdict::Accepted, Some(mdn)) => mdn.clone(),
            (Verdict::Refused(why), Some(mdn)) => mdn.refused(modifier(why)),
        };
        let wrapped = signer.wrap(mdn.entity())?;
        Ok(Response::new(200)
            .header("AS2-Version", message::VERSION)
            .header("AS2-From", &self.me)
            .header("AS2-To", &self.party)
            .header("Content-Type", &wrapped.content_type)
            .body(&wrapped.body))
    }
}

/// The AS2 disposition modifier a refusal is reported with (RFC 4130
/// section 7.4.3): `authentication-failed` where the sender could not be
/// identified, `unexpected-processing-error` where it is not permitted or
/// its content was refused — the list has no closer word for either.
const fn modifier(why: Refusal) -> &'static str {
    match why {
        Refusal::Unidentified => "authentication-failed",
        Refusal::Forbidden | Refusal::Unacceptable => "unexpected-processing-error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::Unsigned;

    #[test]
    fn acceptance_answers_the_mdn_refusal_an_error_mdn_and_failure_503() {
        let entity = Entity::new("application/edi-x12", b"ISA".to_vec());
        let message = Message::new("Buyer", "Seller", "sha-256", entity.clone());
        let receipt = Receipt::for_message(&message, &entity, "Seller").expect("receipt");
        let mdn = |verdict| {
            let answer = receipt.answer(verdict, &Unsigned).expect("answered");
            assert_eq!(answer.status, 200);
            assert_eq!(answer.header_value("AS2-To"), Some("Buyer"));
            Mdn::from_entity(&Entity::new(
                answer.header_value("Content-Type").unwrap_or_default(),
                answer.body.clone(),
            ))
            .expect("an MDN")
        };
        assert!(mdn(Verdict::Accepted).is_processed());
        let refused = mdn(Verdict::Refused(Refusal::Unidentified));
        assert!(!refused.is_processed());
        assert!(
            refused
                .disposition
                .ends_with("processed/error: authentication-failed"),
            "{}",
            refused.disposition
        );
        assert_eq!(refused.mic, None);
        let failed = receipt.answer(Verdict::Failed, &Unsigned).expect("failed");
        assert_eq!(failed.status, 503);
    }

    #[test]
    fn a_party_that_asked_for_no_mdn_hears_http_statuses() {
        let entity = Entity::new("application/edi-x12", b"ISA".to_vec());
        let mut message = Message::new("Buyer", "Seller", "sha-256", entity.clone());
        message.notification_to = None;
        let receipt = Receipt::for_message(&message, &entity, "Seller").expect("receipt");
        let status = |verdict| receipt.answer(verdict, &Unsigned).expect("answered").status;
        assert_eq!(status(Verdict::Accepted), 200);
        assert_eq!(status(Verdict::Refused(Refusal::Forbidden)), 403);
        assert_eq!(status(Verdict::Failed), 503);
    }
}
