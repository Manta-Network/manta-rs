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

//! Trusted Setup Ceremony Signatures

use alloc::vec::Vec;
use manta_crypto::{
    dalek::ed25519::{Ed25519, SignatureError},
    signature,
};
use manta_util::AsBytes;

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Nonce
pub trait Nonce: Default + PartialEq {
    /// Increments the current nonce by one.
    fn increment(&mut self);

    /// Checks if the current nonce is valid.
    fn is_valid(&self) -> bool;

    /// Checks that `self` and `rhs` are valid and are both equal.
    #[inline]
    fn matches(&self, rhs: &Self) -> bool {
        self.is_valid() && rhs.is_valid() && self == rhs
    }
}

impl Nonce for u64 {
    #[inline]
    fn increment(&mut self) {
        *self = self.saturating_add(1);
    }

    #[inline]
    fn is_valid(&self) -> bool {
        *self != Self::MAX
    }
}

/// Message with Nonce
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct RawMessage<N> {
    /// Nonce
    pub nonce: N,

    /// Encoded Message
    pub encoded_message: Vec<u8>,
}

impl<N> RawMessage<N> {
    /// Builds a new [`RawMessage`] from `nonce` and `encoded_message`.
    #[inline]
    pub fn new(nonce: N, encoded_message: Vec<u8>) -> Self {
        Self {
            nonce,
            encoded_message,
        }
    }
}

impl<N> AsBytes for RawMessage<N>
where
    N: AsBytes,
{
    #[inline]
    fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = self.nonce.as_bytes();
        bytes.extend_from_slice(&self.encoded_message);
        bytes
    }
}

/// Signature Scheme
pub trait SignatureScheme:
    Default
    + signature::Sign<Message = RawMessage<Self::Nonce>, Randomness = ()>
    + signature::Verify<Verification = Result<(), Self::Error>>
{
    /// Message Nonce Type
    type Nonce: Clone + Nonce;

    /// Verification Error Type
    type Error;
}

impl<N> SignatureScheme for Ed25519<RawMessage<N>>
where
    N: AsBytes + Clone + Default + Nonce,
{
    type Nonce = N;
    type Error = SignatureError;
}

/// Signs the `message` with the `nonce` attached using the `signing_key`.
#[cfg(feature = "bincode")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "bincode")))]
#[inline]
pub fn sign<S, T>(
    signing_key: &S::SigningKey,
    nonce: S::Nonce,
    message: &T,
) -> Result<S::Signature, bincode::Error>
where
    S: SignatureScheme,
    T: Serialize,
{
    Ok(S::default().sign(
        signing_key,
        &(),
        &RawMessage::new(nonce, bincode::serialize(message)?),
        &mut (),
    ))
}

/// Verification Error
#[cfg(feature = "bincode")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "bincode")))]
#[derive(Debug)]
pub enum VerificationError<E> {
    /// Serialization
    Serialization(bincode::Error),

    /// Base Verification Error Type
    Error(E),
}

#[cfg(feature = "bincode")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "bincode")))]
impl<E> From<bincode::Error> for VerificationError<E> {
    #[inline]
    fn from(err: bincode::Error) -> Self {
        Self::Serialization(err)
    }
}

/// Verifies the `signature` of `message` with `nonce` attached using `verifying_key`.
#[cfg(feature = "bincode")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "bincode")))]
#[inline]
pub fn verify<S, T>(
    verifying_key: &S::VerifyingKey,
    nonce: S::Nonce,
    message: &T,
    signature: &S::Signature,
) -> Result<(), VerificationError<S::Error>>
where
    S: SignatureScheme,
    T: Serialize,
{
    S::default()
        .verify(
            verifying_key,
            &RawMessage::new(nonce, bincode::serialize(message)?),
            signature,
            &mut (),
        )
        .map_err(VerificationError::Error)
}

/// Signed Message
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = r"
                S::Nonce: Deserialize<'de>,
                S::Signature: Deserialize<'de>,
                I: Deserialize<'de>,
                T: Deserialize<'de>,
            ",
            serialize = r"
                S::Nonce: Serialize,
                S::Signature: Serialize,
                I: Serialize,
                T: Serialize,
            ",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields,
    )
)]
pub struct SignedMessage<S, I, T>
where
    S: SignatureScheme,
{
    /// Signature
    pub signature: S::Signature,

    /// Nonce
    pub nonce: S::Nonce,

    /// Participant Identifier
    pub identifier: I,

    /// Message
    pub message: T,
}

impl<S, I, T> SignedMessage<S, I, T>
where
    S: SignatureScheme,
{
    /// Builds a new [`SignedMessage`] without checking that the `signature` actually attests to the
    /// `message`.
    #[inline]
    pub fn new_unchecked(
        signature: S::Signature,
        nonce: S::Nonce,
        identifier: I,
        message: T,
    ) -> Self {
        Self {
            signature,
            nonce,
            identifier,
            message,
        }
    }

    /// Generates a signed message with `signing_key` on `message` and `nonce`.
    #[cfg(feature = "bincode")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "bincode")))]
    #[inline]
    pub fn generate(
        signing_key: &S::SigningKey,
        nonce: S::Nonce,
        identifier: I,
        message: T,
    ) -> Result<Self, bincode::Error>
    where
        T: Serialize,
    {
        Ok(Self::new_unchecked(
            sign::<S, _>(signing_key, nonce.clone(), &message)?,
            nonce,
            identifier,
            message,
        ))
    }

    /// Verifies `self` against the `verifying_key`.
    #[cfg(feature = "bincode")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "bincode")))]
    #[inline]
    pub fn verify(&self, verifying_key: &S::VerifyingKey) -> Result<(), VerificationError<S::Error>>
    where
        T: Serialize,
    {
        verify::<S, _>(
            verifying_key,
            self.nonce.clone(),
            &self.message,
            &self.signature,
        )
    }
}
