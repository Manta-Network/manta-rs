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

use alloc::vec::Vec;
use manta_crypto::signature;
use manta_util::{serde::Serialize, AsBytes};

/// Nonce
pub trait Nonce: PartialEq {
    /// Increments the current nonce by one.
    fn increment(&self) -> Self;

    /// Checks if the current nonce is valid.
    fn is_valid(&self) -> bool;
}

impl Nonce for u64 {
    #[inline]
    fn increment(&self) -> Self {
        self.saturating_add(1)
    }

    #[inline]
    fn is_valid(&self) -> bool {
        *self != Self::MAX
    }
}

/// Checks if the two nonces, `current` and `user_nonce`, are both valid and equal to each other.
#[inline]
pub fn check_nonce<N>(current: &N, user_nonce: &N) -> bool
where
    N: Nonce,
{
    current.is_valid() && user_nonce.is_valid() && current == user_nonce
}

/// Message with Nonce
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Message<N> {
    /// Nonce
    pub nonce: N,

    /// Encoded Message
    pub encoded_message: Vec<u8>,
}

impl<N> AsBytes for Message<N>
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
    + signature::Sign<Message = Message<Self::Nonce>, Randomness = ()>
    + signature::Verify<Verification = Result<(), Self::Error>>
{
    /// Message Nonce
    type Nonce: Nonce;

    /// Verification Error Type
    type Error;
}

/// Signs the `message` with the `nonce` attached using the `signing_key`.
#[inline]
pub fn sign<T, S>(
    signing_key: &S::SigningKey,
    nonce: S::Nonce,
    message: &T,
) -> Result<S::Signature, serde_json::Error>
where
    T: Serialize,
    S: SignatureScheme,
{
    Ok(S::default().sign(
        signing_key,
        &(),
        &Message {
            nonce,
            encoded_message: serde_json::to_vec(message)?,
        },
        &mut (),
    ))
}

/// Verification Error
#[derive(Debug)]
pub enum VerificationError<E> {
    /// Serialization
    Serialization(serde_json::Error),

    /// Base Verification Error Type
    Error(E),
}

impl<E> From<serde_json::Error> for VerificationError<E> {
    #[inline]
    fn from(err: serde_json::Error) -> Self {
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
                encoded_message: serde_json::to_vec(message)?,
            },
            signature,
            &mut (),
        )
        .map_err(VerificationError::Error)
}
