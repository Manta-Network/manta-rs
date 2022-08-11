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

//! Groth16 Ceremony Configuration

use crate::{
    ceremony::{
        config::CeremonyConfig,
        queue::{HasIdentifier, Priority},
        server::{HasNonce, HasContributed},
        signature::{
            ed_dalek::{Ed25519, PublicKey as EdPublicKey},
            HasPublicKey,
        },
    },
    groth16,
    groth16::mpc::Groth16Phase2,
};
use manta_crypto::rand::{OsRng, Rand};
use serde::{Deserialize, Serialize};

/// Groth16 Bls12
pub struct Groth16BLS12381;

impl CeremonyConfig for Groth16BLS12381 {
    type Setup = Groth16Phase2<groth16::config::Config>;
    type SignatureScheme = Ed25519;
    type Participant = Participant;
}

/// Priority
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum UserPriority {
    /// High Priority
    High,

    /// Normal Priority
    Normal,
}

/// Participant
#[derive(Clone, Serialize, Deserialize)]
pub struct Participant {
    /// Public Key
    pub public_key: EdPublicKey,

    /// Twitter Account
    pub twitter: String,

    /// Priority
    pub priority: UserPriority,

    /// Nonce
    pub nonce: u64,

    /// Boolean on whether this participant has contributed
    pub contributed: bool,
}

impl Participant {
    /// Builds a new [`Participant`] from `public_key`, `twitter`, and `priority`.
    pub fn new(public_key: EdPublicKey, twitter: &str, priority: UserPriority) -> Self {
        Self {
            public_key,
            twitter: twitter.to_string(),
            priority,
            nonce: OsRng.gen(),
            contributed: false,
        }
    }
}

impl Priority for Participant {
    fn priority(&self) -> usize {
        match self.priority {
            UserPriority::Normal => 0,
            UserPriority::High => 1,
        }
    }
}

impl HasIdentifier for Participant {
    type Identifier = EdPublicKey;

    fn identifier(&self) -> Self::Identifier {
        self.public_key
    }
}

impl HasPublicKey<Ed25519> for Participant {
    fn public_key(&self) -> EdPublicKey {
        self.public_key
    }
}

impl HasNonce<Ed25519> for Participant {
    fn nonce(&self) -> u64 {
        self.nonce
    }

    fn set_nonce(&mut self, nonce: u64) {
        self.nonce = nonce;
    }
}

impl HasContributed for Participant {
    fn has_contributed(&self) -> bool {
        self.contributed
    }

    fn set_contributed(&mut self) {
        self.contributed = true;
    }
}