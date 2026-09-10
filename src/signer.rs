//! Who signs and seals an AS2 entity, and who does not.
//!
//! RFC 4130 wraps the payload in S/MIME: `multipart/signed` with a
//! `pkcs7-signature` part, or `application/pkcs7-mime` enveloped for the
//! partner's certificate. Both need a certificate and a private key, and
//! those are the business of `xmip-core-authenticate-certificate`, which the
//! manifest names as this technology's dependency: it supplies a [`Signer`]
//! and this crate applies it to every message and every MDN. Until it does,
//! [`Unsigned`] carries the entity as it is, which is the exchange two Xmip
//! nodes on one wire agree on and what a partner test bench accepts.

use transport::error::Result;

/// An entity as it travels: its media type and its bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entity {
    pub content_type: String,
    pub body: Vec<u8>,
}

impl Entity {
    #[must_use]
    pub fn new(content_type: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            content_type: content_type.into(),
            body: body.into(),
        }
    }
}

/// What wraps an entity on the way out and unwraps it on the way in.
///
/// A signer is applied to the message and, where the partner asked for a
/// signed receipt, to the MDN as well — RFC 4130 sections 5 and 7.
pub trait Signer: Send + Sync {
    /// The digest the MDN's `Received-Content-MIC` names, as the
    /// `Disposition-Notification-Options` header spells it: `sha-256`.
    fn micalg(&self) -> &'static str;

    /// `entity` wrapped for the wire: signed, sealed, or left as it is.
    ///
    /// # Errors
    /// Where the key or the certificate cannot sign.
    fn wrap(&self, entity: Entity) -> Result<Entity>;

    /// An entity off the wire, its wrapping verified and removed.
    ///
    /// # Errors
    /// Where the signature does not verify or the seal will not open.
    fn unwrap(&self, entity: Entity) -> Result<Entity>;
}

/// No certificate: the entity travels as it is, and the MDN says which
/// digest it was hashed with all the same.
#[derive(Clone, Copy, Debug, Default)]
pub struct Unsigned;

impl Signer for Unsigned {
    fn micalg(&self) -> &'static str {
        "sha-256"
    }

    fn wrap(&self, entity: Entity) -> Result<Entity> {
        Ok(entity)
    }

    fn unwrap(&self, entity: Entity) -> Result<Entity> {
        Ok(entity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unsigned_exchange_leaves_the_entity_as_it_is() {
        let entity = Entity::new("application/edi-x12", b"ISA*00*".to_vec());
        let wrapped = Unsigned.wrap(entity.clone()).expect("wrapped");
        assert_eq!(wrapped, entity);
        assert_eq!(Unsigned.unwrap(wrapped).expect("unwrapped"), entity);
        assert_eq!(Unsigned.micalg(), "sha-256");
    }
}
