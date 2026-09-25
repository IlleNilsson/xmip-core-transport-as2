#![forbid(unsafe_code)]

//! Streams that arrive as AS2 messages. One message is one Stream, the
//! partner ids and the message id kept beside it.
//!
//! AS2 is EDI over HTTP, RFC 4130: a POST carrying the payload as its body
//! and the partners in `AS2-From` and `AS2-To`, answered with a Message
//! Disposition Notification that carries the MIC of what arrived — the
//! receipt a partner keeps as proof of delivery. A Receive Location listens
//! for partners and answers each message with its MDN; a Send Location posts
//! to a partner and reads the MDN back on the same connection, refusing the
//! send where the receipt is missing, says anything but processed, or names
//! a MIC other than the one computed here.
//!
//! S/MIME signing and encryption need a certificate. The envelope and the
//! MDN are here; the signer is a [`Signer`] that
//! `xmip-core-authenticate-certificate` supplies, and without one the
//! exchange is [`Unsigned`] — two Xmip nodes on one wire, or a partner test
//! bench. The http technology carries the request, the answer and the
//! endpoint; TLS is its `tls` feature (ADR-0033).
//!
//! The origin URI carries what the headers knew:
//! `as2://peer/path?from=Buyer&message-id=1.2@buyer`.

pub mod loopback;
pub mod mdn;
pub mod message;
pub mod signer;

use std::net::TcpListener;
use std::time::Duration;

pub use mdn::Mdn;
pub use message::Message;
use net::Endpoint;
use net::http::{Request, Response, exchange, read_request, write_response};
pub use signer::{Entity, Signer, Unsigned};
use transport::error::{Result, TransportError, protocol_error};
use transport::socket;
use transport::{Arrived, Directions, Transport};

pub struct As2Transport {
    /// The partner's endpoint to send to, or the address to listen at.
    endpoint: String,
    me: String,
    partner: String,
    signer: Box<dyn Signer>,
    timeout: Option<Duration>,
}

impl As2Transport {
    /// Speak as partner `me` to `partner` at `endpoint` —
    /// `http://host:port/as2` or `as2://host:port/as2` — unsigned until
    /// [`Self::signing_with`].
    #[must_use]
    pub fn new(endpoint: impl Into<String>, me: &str, partner: &str) -> Self {
        Self {
            endpoint: as_http(&endpoint.into()),
            me: me.to_string(),
            partner: partner.to_string(),
            signer: Box::new(Unsigned),
            timeout: None,
        }
    }

    /// Sign and seal with this, and verify with it.
    #[must_use]
    pub fn signing_with(mut self, signer: impl Signer + 'static) -> Self {
        self.signer = Box::new(signer);
        self
    }

    /// Give up on a partner that stops mid-message.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Bind at the endpoint's authority as the far end partners post to,
    /// and report the address actually assigned.
    ///
    /// # Errors
    /// Where the address is taken, malformed, or not permitted.
    pub fn bind(&self) -> Result<(TcpListener, String)> {
        socket::bind_tcp(&Endpoint::parse(&self.endpoint)?.address())
    }

    /// Accept one message on an already-bound listener and answer its MDN.
    ///
    /// # Errors
    /// Where the connection broke, the POST is not an AS2 message, or it
    /// was addressed to some other partner — each answered with the status
    /// that says so before the error is returned.
    pub fn accept_one(&self, listener: &TcpListener) -> Result<Arrived> {
        let (stream, peer) = socket::accept_tcp(listener, self.timeout)?;
        let (mut reader, mut writer) = socket::split(stream)?;
        let request = read_request(&mut reader)?
            .ok_or_else(|| protocol_error("a partner that connected and sent nothing"))?;
        match self.take(&request) {
            Ok((message, entity, answer)) => {
                write_response(&mut writer, &answer)?;
                let origin = format!(
                    "as2://{peer}{}?from={}&message-id={}",
                    request.path,
                    message.from,
                    message.message_id.trim_matches(['<', '>'])
                );
                Ok(Arrived::new(origin, entity.body))
            }
            Err(error) => {
                let status = if error.retryable { 503 } else { 400 };
                let refusal = Response::new(status).body(error.message.as_bytes());
                write_response(&mut writer, &refusal)?;
                Err(error)
            }
        }
    }

    /// The message a request carries, its entity unwrapped, and the answer
    /// it earns.
    fn take(&self, request: &Request) -> Result<(Message, Entity, Response)> {
        let message = Message::from_request(request)?;
        if message.to != self.me {
            return Err(protocol_error(format!(
                "a message for {}, and this partner is {}",
                message.to, self.me
            )));
        }
        let entity = self.signer.unwrap(message.entity.clone())?;
        let answer = if message.wants_receipt() {
            let micalg = message
                .micalg
                .clone()
                .unwrap_or_else(|| "sha-256".to_string());
            let mic = message::mic(&micalg, &entity.body)?;
            let receipt = Mdn::processed(&message.message_id, &self.me, mic, &micalg);
            let wrapped = self.signer.wrap(receipt.entity())?;
            Response::new(200)
                .header("AS2-Version", message::VERSION)
                .header("AS2-From", &self.me)
                .header("AS2-To", &message.from)
                .header("Content-Type", &wrapped.content_type)
                .body(&wrapped.body)
        } else {
            Response::new(200)
        };
        Ok((message, entity, answer))
    }

    /// Where a target names the partner's endpoint itself, or is empty and
    /// means the one configured.
    fn resolve(&self, target: &str) -> String {
        if target.is_empty() {
            self.endpoint.clone()
        } else {
            as_http(target)
        }
    }

    /// The receipt the partner answered, checked against what was sent.
    fn verify_receipt(&self, response: &Response, sent: &Message, mic: &[u8]) -> Result<()> {
        if !(200..300).contains(&response.status) {
            let retryable = http::status::retryable(response.status);
            return Err(TransportError {
                message: format!("the partner answered {}", response.status),
                retryable,
            });
        }
        let entity = Entity::new(
            response.header_value("Content-Type").unwrap_or_default(),
            response.body.clone(),
        );
        let receipt = Mdn::from_entity(&self.signer.unwrap(entity)?)?;
        if receipt.original_message_id != sent.message_id {
            return Err(protocol_error(format!(
                "a receipt for {}, not for {}",
                receipt.original_message_id, sent.message_id
            )));
        }
        if !receipt.is_processed() {
            return Err(protocol_error(format!(
                "the partner did not process the message: {}",
                receipt.disposition
            )));
        }
        match &receipt.mic {
            Some((theirs, _)) if theirs == mic => Ok(()),
            Some(_) => Err(protocol_error(
                "the partner's MIC is not the MIC of what was sent",
            )),
            None => Err(protocol_error("a receipt with no MIC in it")),
        }
    }
}

/// `as2://` is `http://` on the wire, and `as2s://` is `https://`.
fn as_http(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("as2://") {
        format!("http://{rest}")
    } else if let Some(rest) = url.strip_prefix("as2s://") {
        format!("https://{rest}")
    } else {
        url.to_string()
    }
}

impl Transport for As2Transport {
    fn name(&self) -> &'static str {
        "as2"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    fn receive(&self) -> Result<Vec<Arrived>> {
        let (listener, _) = self.bind()?;
        Ok(vec![self.accept_one(&listener)?])
    }

    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        let url = self.resolve(target);
        let endpoint = Endpoint::parse(&url)?;
        let plain = Entity::new("application/octet-stream", bytes.to_vec());
        let mic = message::mic(self.signer.micalg(), &plain.body)?;
        let wrapped = self.signer.wrap(plain)?;
        let message = Message::new(&self.me, &self.partner, self.signer.micalg(), wrapped);
        let request = message.request(&endpoint.authority(), endpoint.path());
        let connection = http::endpoint::connect(&endpoint, self.timeout)?;
        let response = exchange(connection, &request)?;
        self.verify_receipt(&response, &message, &mic)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use transport::loopback::Loopback;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn far_end() -> (As2Transport, TcpListener, String) {
        let far_end =
            As2Transport::new("as2://127.0.0.1:0/as2", "Seller", "Buyer").timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        (far_end, listener, address)
    }

    #[test]
    fn a_message_is_posted_and_its_receipt_carries_the_mic_back() {
        let loopback = As2Transport::loopback();
        let first = loopback.round(b"ISA*00*").expect("first");
        assert_eq!(first.bytes, b"ISA*00*");
        assert!(first.origin_uri.starts_with("as2://127.0.0.1:"));
        assert!(first.origin_uri.contains("/as2?from=Buyer&message-id="));
        let long = vec![0x2a; 200_000];
        assert_eq!(loopback.round(&long).expect("second").bytes, long);
        assert!(loopback.round(b"").expect("third").bytes.is_empty());
        assert_eq!(loopback.name(), "as2");
        assert_eq!(loopback.directions(), Directions::BOTH);
        assert!(loopback.claims().is_none());
        assert!(loopback.ceiling().is_none());
        assert!(loopback.refuses(b"ISA").is_none());
    }

    #[test]
    fn a_target_may_name_the_partners_endpoint_itself() {
        let (far_end, listener, address) = far_end();
        let sender = std::thread::spawn(move || {
            As2Transport::new("as2://127.0.0.1:0/as2", "Buyer", "Seller")
                .timing_out_after(secs(2))
                .send(&format!("http://{address}/as2"), b"ISA")
        });
        assert_eq!(far_end.accept_one(&listener).expect("named").bytes, b"ISA");
        sender.join().expect("thread").expect("sent");
    }

    #[test]
    fn the_loopback_returns_the_edges_whole() {
        let loopback = As2Transport::loopback();
        let edges: [(&str, Vec<u8>); 6] = [
            ("empty", Vec::new()),
            ("one byte", vec![0x2a]),
            ("every byte", (0..=255).collect()),
            ("nul run", vec![0; 512]),
            ("high bytes", vec![0xff; 512]),
            ("crlf storm", b"\r\n".repeat(400)),
        ];
        for (name, payload) in edges {
            assert_eq!(
                loopback.round(&payload).expect(name).bytes,
                payload,
                "{name}"
            );
        }
    }

    #[test]
    fn a_post_that_is_not_as2_is_answered_400_and_refused() {
        let (far_end, listener, address) = far_end();
        let poster = std::thread::spawn(move || {
            let mut stream = socket::connect_tcp(&address, Some(secs(2))).expect("connect");
            stream
                .write_all(b"POST /as2 HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nISA")
                .expect("write");
            let mut answer = Vec::new();
            stream.read_to_end(&mut answer).expect("read");
            String::from_utf8_lossy(&answer).into_owned()
        });
        let error = far_end.accept_one(&listener).expect_err("not AS2");
        assert!(!error.retryable, "{error}");
        assert!(poster.join().expect("thread").starts_with("HTTP/1.1 400"));
    }

    #[test]
    fn a_message_for_another_partner_is_refused_and_the_sender_hears_it() {
        let (far_end, listener, address) = far_end();
        let sender = std::thread::spawn(move || {
            As2Transport::new(format!("as2://{address}/as2"), "Buyer", "Somebody")
                .timing_out_after(secs(2))
                .send("", b"ISA")
        });
        assert!(far_end.accept_one(&listener).is_err());
        let error = sender.join().expect("thread").expect_err("refused");
        assert!(!error.retryable);
        assert!(error.message.contains("400"), "{error}");
    }

    #[test]
    fn a_receipt_that_does_not_match_is_not_a_delivery() {
        let (_, listener, address) = far_end();
        std::thread::spawn(move || {
            let (stream, _) = socket::accept_tcp(&listener, Some(secs(2))).expect("accept");
            let (mut reader, mut writer) = socket::split(stream).expect("split");
            let request = read_request(&mut reader).expect("read").expect("one");
            let message = Message::from_request(&request).expect("as2");
            let wrong = Mdn::processed(&message.message_id, "Seller", vec![0; 32], "sha-256");
            let entity = wrong.entity();
            let answer = Response::new(200)
                .header("Content-Type", &entity.content_type)
                .body(&entity.body);
            write_response(&mut writer, &answer).expect("answered");
        });
        let error = As2Transport::new(format!("http://{address}/as2"), "Buyer", "Seller")
            .timing_out_after(secs(2))
            .send("", b"ISA")
            .expect_err("wrong MIC");
        assert!(error.message.contains("MIC"), "{error}");
        assert!(!error.retryable);
        let (_, listener, address) = far_end();
        std::thread::spawn(move || {
            let (stream, _) = socket::accept_tcp(&listener, Some(secs(2))).expect("accept");
            let (mut reader, mut writer) = socket::split(stream).expect("split");
            read_request(&mut reader).expect("read");
            write_response(&mut writer, &Response::new(503)).expect("answered");
        });
        let error = As2Transport::new(format!("http://{address}/as2"), "Buyer", "Seller")
            .timing_out_after(secs(2))
            .send("", b"ISA")
            .expect_err("busy");
        assert!(error.retryable, "{error}");
    }
}
