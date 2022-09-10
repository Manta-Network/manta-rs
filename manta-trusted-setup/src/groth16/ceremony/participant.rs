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
};
use manta_util::serde::{Deserialize, Serialize};

/// Priority
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(
    bound(deserialize = "", serialize = ""),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
pub enum Priority {
    /// High Priority
    High,

    /// Normal Priority
    Normal,
}

impl From<Priority> for usize {
    #[inline]
    fn from(priority: Priority) -> Self {
        match priority {
            Priority::High => 0,
            Priority::Normal => 1,
        }
    }
}

/// Participant
pub struct Participant<S>
where
    S: SignatureScheme,
{
    /// Verifying Key
    verifying_key: S::VerifyingKey,

    /// Twitter Account
    twitter: String,

    /// Priority
    priority: Priority,

    /// Nonce
    nonce: S::Nonce,

    /// Boolean on whether this participant has contributed
    contributed: bool,
}

impl<S> ceremony::Participant for Participant<S>
where
    S: SignatureScheme,
{
    type Identifier = S::VerifyingKey;
    type VerifyingKey = S::VerifyingKey;
    type Priority = Priority;
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
    fn priority(&self) -> Self::Priority {
        self.priority
    }

    #[inline]
    fn reduce_priority(&mut self) {
        self.priority = Priority::Normal;
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
    fn nonce(&self) -> Self::Nonce {
        self.nonce.clone()
    }

    #[inline]
    fn increment_nonce(&mut self) {
        self.nonce.increment();
    }
}

impl<S> Participant<S>
where
    S: SignatureScheme,
{
    /// Builds a new [`Participant`].
    #[inline]
    pub fn new(
        verifying_key: S::VerifyingKey,
        twitter: String,
        priority: Priority,
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
    pub fn twitter(&self) -> &str {
        &self.twitter
    }
}
