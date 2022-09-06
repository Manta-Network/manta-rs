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

//! Participant

use super::signature::{HasNonce, HasPublicKey, SignatureScheme};
use manta_crypto::rand::{OsRng, Rand};
use manta_util::serde::{Deserialize, Serialize};

/// Has Contributed
pub trait HasContributed {
    /// Checks if the participant has contributed.
    fn has_contributed(&self) -> bool;

    /// Sets the participant as contributed.
    fn set_contributed(&mut self);
}

/// Priority
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(
    bound(deserialize = "", serialize = ""),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
pub enum UserPriority {
    /// High Priority
    High,

    /// Normal Priority
    Normal,
}

/// Priority
pub trait Priority {
    /// Gets the priority value.
    fn priority(&self) -> usize;

    /// Reduces the priority.
    fn reduce_priority(&mut self);
}

/// Identifier
pub trait HasIdentifier {
    /// Identifier Type
    type Identifier: Ord + Clone;

    /// Gets the identifier.
    fn identifier(&self) -> Self::Identifier;
}

/// Participant
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    bound(
        serialize = "S::VerifyingKey: Serialize, UserPriority: Serialize",
        deserialize = "S::VerifyingKey: Deserialize<'de>, UserPriority: Deserialize<'de>"
    ),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
pub struct Participant<S>
where
    S: SignatureScheme<Vec<u8>, Nonce = u64>,
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
{
    /// Builds a new [`Participant`] from `public_key`, `twitter`, and `priority`.
    #[inline]
    pub fn new(public_key: S::VerifyingKey, twitter: &str, priority: UserPriority) -> Self {
        Self {
            public_key,
            twitter: twitter.to_string(),
            priority,
            nonce: OsRng.gen(), // TODO： Change to u16 rand
            contributed: false,
        }
    }
}

impl<S> Priority for Participant<S>
where
    S: SignatureScheme<Vec<u8>, Nonce = u64>,
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
    S::VerifyingKey: Clone + Ord,
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
    S::VerifyingKey: Clone,
{
    #[inline]
    fn public_key(&self) -> S::VerifyingKey {
        self.public_key.clone()
    }
}

impl<S> HasNonce<S, Vec<u8>> for Participant<S>
where
    S: SignatureScheme<Vec<u8>, Nonce = u64>,
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
