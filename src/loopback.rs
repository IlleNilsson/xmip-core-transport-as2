//! Both ends of one AS2 exchange on this machine (ADR-0051): a partner
//! listening at an ephemeral local port takes the one message the other
//! partner posts and answers its MDN, which the sender verifies before the
//! send counts. The exchange is unsigned — two Xmip nodes on one wire,
//! which is what [`Unsigned`](crate::Unsigned) is for.

use std::net::TcpListener;

use http::target::HttpTarget;
use transport::error::Result;
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::{Arrived, Transport};

use crate::As2Transport;

/// The partner the loopback listens as.
pub const ME: &str = "Seller";
/// The partner that posts to it.
pub const PARTNER: &str = "Buyer";

impl As2Transport {
    /// Both ends on this machine: [`ME`] listening at an ephemeral local
    /// port for [`PARTNER`], the loopback timeout on either side, unsigned.
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("as2://127.0.0.1:0/as2", ME, PARTNER).timing_out_after(LOOPBACK_TIMEOUT)
    }

    /// This partner again, unsigned: what the far end listens as. A signer
    /// is not cloned; the loopback never has one.
    fn unsigned_twin(&self) -> Self {
        let twin = Self::new(self.endpoint.clone(), &self.me, &self.partner);
        match self.timeout {
            Some(timeout) => twin.timing_out_after(timeout),
            None => twin,
        }
    }
}

/// A bound partner waiting for its one message.
struct Listening {
    partner: As2Transport,
    listener: TcpListener,
    address: String,
}

impl FarEnd for Listening {
    fn address(&self) -> &str {
        &self.address
    }

    fn take_one(self: Box<Self>) -> Result<Arrived> {
        self.partner.accept_one(&self.listener)
    }
}

impl Loopback for As2Transport {
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        let (listener, address) = self.bind()?;
        Ok(Box::new(Listening {
            partner: self.unsigned_twin(),
            listener,
            address,
        }))
    }

    /// The other partner posts to this one's path at `address`.
    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        let path = HttpTarget::parse(&self.endpoint)?.path;
        let near = Self::new(format!("as2://{address}{path}"), &self.partner, &self.me);
        near.timing_out_after(self.timeout.unwrap_or(LOOPBACK_TIMEOUT))
            .send("", payload)
    }
}
