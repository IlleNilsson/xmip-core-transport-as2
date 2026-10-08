//! Both ends of one AS2 exchange on this machine (ADR-0051): a Party
//! listening at an ephemeral local port takes the one message the other
//! Party posts and answers its MDN, which the sender verifies before the
//! send counts. The exchange is unsigned — two Xmip nodes on one wire,
//! which is what [`Unsigned`](crate::Unsigned) is for.

use std::net::TcpListener;

use net::Endpoint;
use transport::ArrivalIdentity;
use transport::Transport;
use transport::error::Result;
use transport::listening::Listening;
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};

use crate::As2Transport;

/// The Party the loopback listens as.
const ME: &str = "Seller";
/// The Party that posts to it.
pub const PARTY: &str = "Buyer";

impl As2Transport {
    /// Both ends on this machine: [`ME`] listening at an ephemeral local
    /// port for [`PARTY`], the loopback timeout on either side, unsigned.
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("as2://127.0.0.1:0/as2", ME, PARTY).timing_out_after(LOOPBACK_TIMEOUT)
    }

    /// This Party again, unsigned: what the far end listens as. A signer
    /// is not cloned; the loopback never has one.
    fn unsigned_twin(&self) -> Self {
        let twin = Self::new(self.endpoint.clone(), &self.me, &self.party);
        match self.timeout {
            Some(timeout) => twin.timing_out_after(timeout),
            None => twin,
        }
    }
}

impl Loopback for As2Transport {
    fn arrival_identity(&self) -> ArrivalIdentity {
        http::server::REQUEST
    }

    /// A bound Party waiting for its one message.
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        let party = self.unsigned_twin();
        Ok(Box::new(Listening::new(
            move |listener: &TcpListener| party.accept_one(listener),
            self.bind()?,
        )))
    }

    /// The other Party posts to this one's path at `address`.
    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        let endpoint = Endpoint::parse_under(&self.endpoint, &crate::SCHEMES)?;
        let path = endpoint.path();
        let near = Self::new(format!("as2://{address}{path}"), &self.party, &self.me);
        near.timing_out_after(self.timeout.unwrap_or(LOOPBACK_TIMEOUT))
            .send("", payload)
    }
}
