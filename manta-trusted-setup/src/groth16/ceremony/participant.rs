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

use crate::groth16::ceremony::{
    self,
    signature::{Nonce, SignatureScheme},
    UserPriority,
};

/// Participant
pub struct Participant<S>
where
    S: SignatureScheme<Nonce = u64>,
{
    /// Verifying Key
    verifying_key: S::VerifyingKey,

    /// Twitter Account
    twitter: String,

    /// Priority
    priority: UserPriority,

    /// Nonce
    nonce: S::Nonce,

    /// Boolean on whether this participant has contributed
    contributed: bool,
}

impl<S> ceremony::Participant for Participant<S>
where
    S: SignatureScheme<Nonce = u64>,
{
    type Identifier = S::VerifyingKey;
    type VerifyingKey = S::VerifyingKey;
    type Nonce = S::Nonce;

    #[inline]
    fn id(&self) -> &Self::Identifier {
        &self.verifying_key
    }

    #[inline]
    fn verifying_key(&self) -> &Self::VerifyingKey {
        &self.verifying_key
    }

    #[inline]
    fn level(&self) -> UserPriority {
        self.priority
    }

    #[inline]
    fn reduce_priority(&mut self) {
        self.priority = UserPriority::Normal;
    }

    #[inline]
    fn has_contributed(&self) -> bool {
        self.contributed
    }

    #[inline]
    fn set_contributed(&mut self) {
        self.contributed = true
    }

    #[inline]
    fn get_nonce(&self) -> Self::Nonce {
        self.nonce
    }

    #[inline]
    fn increment_nonce(&mut self) {
        self.nonce.increment();
    }
}

impl<S> Participant<S>
where
    S: SignatureScheme<Nonce = u64>,
{
    /// Builds a new [`Participant`].
    #[inline]
    pub fn new(
        verifying_key: S::VerifyingKey,
        twitter: String,
        priority: UserPriority,
        nonce: S::Nonce,
        contributed: bool,
    ) -> Self {
        Self {
            verifying_key,
            twitter,
            priority,
            nonce,
            contributed,
        }
    }

    /// Gets `twitter`.
    #[inline]
    pub fn twitter(&self) -> String {
        self.twitter.clone()
    }
}
