// Copyright 2019-2022 Manta Network.
// This file is part of manta-rs.
//
// manta-rs is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// manta-rs is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with manta-rs.  If not, see <http://www.gnu.org/licenses/>.

//! Groth16 Trusted Setup Ceremony Signatures

use crate::{
    ceremony::signature::{Message, Nonce},
    groth16::ceremony::Ceremony,
};
use manta_crypto::{
    dalek::ed25519::{generate_keypair, Ed25519, SignatureError},
    rand::{ChaCha20Rng, SeedableRng},
    signature,
};
use manta_util::{
    serde::{Deserialize, Serialize},
    AsBytes,
};

/// Signature Scheme
pub trait SignatureScheme:
    Default
    + signature::Sign<Message = Message<Self::Nonce>, Randomness = ()>
    + signature::Verify<Verification = Result<(), Self::Error>>
{
    /// Message Nonce
    type Nonce: Clone + Nonce;

    /// Verification Error Type
    type Error;

    /// Generates a keypair from `bytes` returning `None` if `bytes` was not the right format.
    fn generate_keys(bytes: &[u8]) -> Option<(Self::SigningKey, Self::VerifyingKey)>;
}

impl<N> SignatureScheme for Ed25519<Message<N>>
where
    N: AsBytes + Default + Nonce + Clone,
{
    type Nonce = N;
    type Error = SignatureError;

    #[inline]
    fn generate_keys(bytes: &[u8]) -> Option<(Self::SigningKey, Self::VerifyingKey)> {
        let keypair = generate_keypair(&mut ChaCha20Rng::from_seed(bytes.try_into().ok()?));
        Some((keypair.secret, keypair.public))
    }
}

/// Signs the `message` with the `nonce` attached using the `signing_key`.
#[inline]
pub fn sign<T, S>(
    signing_key: &S::SigningKey,
    nonce: S::Nonce,
    message: &T,
) -> Result<S::Signature, bincode::Error>
where
    T: Serialize,
    S: SignatureScheme,
{
    Ok(S::default().sign(
        signing_key,
        &(),
        &Message {
            nonce,
            encoded_message: bincode::serialize(message)?,
        },
        &mut (),
    ))
}

/// Verification Error
#[derive(Debug)]
pub enum VerificationError<E> {
    /// Serialization
    Serialization(bincode::Error),

    /// Base Verification Error Type
    Error(E),
}

impl<E> From<bincode::Error> for VerificationError<E> {
    #[inline]
    fn from(err: bincode::Error) -> Self {
        Self::Serialization(err)
    }
}

/// Verifies the `signature` of `message` with `nonce` attached using `verifying_key`.
#[inline]
pub fn verify<T, S>(
    verifying_key: &S::VerifyingKey,
    nonce: S::Nonce,
    message: &T,
    signature: &S::Signature,
) -> Result<(), VerificationError<S::Error>>
where
    T: Serialize,
    S: SignatureScheme,
{
    S::default()
        .verify(
            verifying_key,
            &Message {
                nonce,
                encoded_message: bincode::serialize(message)?,
            },
            signature,
            &mut (),
        )
        .map_err(VerificationError::Error)
}

/* TODO[remove]:
/// Signed Message
#[derive(Deserialize, Serialize)]
#[serde(
    bound(
        serialize = r"
            C::Identifier: Serialize,
            T: Serialize,
            C::Nonce: Serialize,
            C::Signature: Serialize,
        ",
        deserialize = r"
            C::Identifier: Deserialize<'de>,
            T: Deserialize<'de>,
            C::Nonce: Deserialize<'de>,
            C::Signature: Deserialize<'de>,
        ",
    ),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
pub struct Signed<T, C>
where
    C: Ceremony,
{
    /// Message
    pub message: T,

    /// Nonce
    pub nonce: C::Nonce,

    /// Signature
    pub signature: C::Signature,

    /// Participant Identifier
    pub identifier: C::Identifier,
}

impl<T, C> Signed<T, C>
where
    C: Ceremony,
{
    /// Generates a signed message with `signing_key` on `message` and `nonce`.
    #[inline]
    pub fn new(
        message: T,
        nonce: &C::Nonce,
        signing_key: &C::SigningKey,
        identifier: C::Identifier,
    ) -> Result<Self, bincode::Error>
    where
        T: Serialize,
        C::Nonce: Clone,
    {
        let signature = sign::<_, C>(signing_key, nonce.clone(), &message)?;
        let message = Signed {
            message,
            nonce: nonce.clone(),
            signature,
            identifier,
        };
        Ok(message)
    }
}
*/
