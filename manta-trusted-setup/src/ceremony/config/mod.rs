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

//! Ceremony Configurations

use crate::{
    ceremony::{
        queue::{HasIdentifier, Priority},
        signature::{self, HasNonce, HasPublicKey, SignatureScheme},
        state::UserPriority,
        util::HasContributed,
    },
    mpc,
};
use manta_crypto::{
    arkworks::serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError},
    rand::{OsRng, Rand},
    signature::{SignatureType, SigningKeyType, VerifyingKeyType},
};
use std::io::{Read, Write};

pub mod g16_bls12_381;

/// Trustred Setup Ceremony Config
pub trait CeremonyConfig {
    /// Setup
    type Setup: mpc::Verify + mpc::Contribute;

    /// Signature Scheme
    type SignatureScheme: SignatureScheme<Vec<u8>>;

    /// Participant
    type Participant: Priority
        + HasIdentifier
        + signature::HasPublicKey<Self::SignatureScheme, Vec<u8>>
        + HasContributed
        + signature::HasNonce<Self::SignatureScheme, Vec<u8>>;
}

/// State
pub type State<C> = <<C as CeremonyConfig>::Setup as mpc::Types>::State;

/// Challenge
pub type Challenge<C> = <<C as CeremonyConfig>::Setup as mpc::Types>::Challenge;

/// Hasher
pub type Hasher<C> = <<C as CeremonyConfig>::Setup as mpc::Contribute>::Hasher;

/// Proof
pub type Proof<C> = <<C as CeremonyConfig>::Setup as mpc::Types>::Proof;

/// Nonce
pub type Nonce<C> = <<C as CeremonyConfig>::SignatureScheme as SignatureScheme<Vec<u8>>>::Nonce;

/// Public Key
pub type PublicKey<C> = <<C as CeremonyConfig>::SignatureScheme as VerifyingKeyType>::VerifyingKey;

/// Signature
pub type Signature<C> = <<C as CeremonyConfig>::SignatureScheme as SignatureType>::Signature;

/// Private Key
pub type PrivateKey<C> = <<C as CeremonyConfig>::SignatureScheme as SigningKeyType>::SigningKey;

/// Participant Identifier
pub type ParticipantIdentifier<C> =
    <<C as CeremonyConfig>::Participant as HasIdentifier>::Identifier;

/// Participant
#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct Participant<S>
where
    S: SignatureScheme<Vec<u8>, Nonce = u64>,
    S::VerifyingKey: CanonicalDeserialize + CanonicalSerialize,
{
    /// Public Key
    pub public_key: S::VerifyingKey,

    /// Twitter Account
    pub twitter: String,

    /// Priority
    pub priority: UserPriority,

    /// Nonce
    pub nonce: u64,

    /// Boolean on whether this participant has contributed
    pub contributed: bool,
}

impl<S> Participant<S>
where
    S: SignatureScheme<Vec<u8>, Nonce = u64>,
    S::VerifyingKey: CanonicalDeserialize + CanonicalSerialize,
{
    /// Builds a new [`Participant`] from `public_key`, `twitter`, and `priority`.
    #[inline]
    pub fn new(public_key: S::VerifyingKey, twitter: &str, priority: UserPriority) -> Self {
        Self {
            public_key,
            twitter: twitter.to_string(),
            priority,
            nonce: OsRng.gen(),
            contributed: false,
        }
    }
}

impl<S> Priority for Participant<S>
where
    S: SignatureScheme<Vec<u8>, Nonce = u64>,
    S::VerifyingKey: CanonicalDeserialize + CanonicalSerialize,
{
    #[inline]
    fn priority(&self) -> usize {
        match self.priority {
            UserPriority::Normal => 0,
            UserPriority::High => 1,
        }
    }

    #[inline]
    fn reduce_priority(&mut self) {
        self.priority = UserPriority::Normal;
    }
}

impl<S> HasIdentifier for Participant<S>
where
    S: SignatureScheme<Vec<u8>, Nonce = u64>,
    S::VerifyingKey: CanonicalDeserialize + CanonicalSerialize + Clone + Ord,
{
    type Identifier = S::VerifyingKey;

    #[inline]
    fn identifier(&self) -> Self::Identifier {
        self.public_key.clone()
    }
}

impl<S> HasPublicKey<S, Vec<u8>> for Participant<S>
where
    S: SignatureScheme<Vec<u8>, Nonce = u64>,
    S::VerifyingKey: CanonicalDeserialize + CanonicalSerialize + Clone,
{
    #[inline]
    fn public_key(&self) -> S::VerifyingKey {
        self.public_key.clone()
    }
}

impl<S> HasNonce<S, Vec<u8>> for Participant<S>
where
    S: SignatureScheme<Vec<u8>, Nonce = u64>,
    S::VerifyingKey: CanonicalDeserialize + CanonicalSerialize,
{
    #[inline]
    fn nonce(&self) -> S::Nonce {
        self.nonce
    }

    #[inline]
    fn set_nonce(&mut self, nonce: S::Nonce) {
        self.nonce = nonce;
    }
}

impl<S> HasContributed for Participant<S>
where
    S: SignatureScheme<Vec<u8>, Nonce = u64>,
    S::VerifyingKey: CanonicalDeserialize + CanonicalSerialize,
{
    #[inline]
    fn has_contributed(&self) -> bool {
        self.contributed
    }

    #[inline]
    fn set_contributed(&mut self) {
        self.contributed = true;
    }
}
