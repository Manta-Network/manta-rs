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
        queue::{Identifier, Priority},
        server::HasNonce,
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
pub struct Groth16Bls12;

impl CeremonyConfig for Groth16Bls12 {
    type Setup = Groth16Phase2<groth16::config::Config>;
    type SignatureScheme = Ed25519;
    type Participant = Participant;
}

/// Priority
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum UserPriority {
    /// Normal Priority
    Normal,
    /// High Priority
    High,
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
    ///
    pub fn new(public_key: EdPublicKey, twitter: &str, priority: UserPriority) -> Self {
        let mut rng = OsRng;
        let nonce = rng.gen();
        Self {
            public_key,
            twitter: twitter.to_string(),
            priority,
            nonce,
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

impl Identifier for Participant {
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

    fn update_nonce(&mut self) {
        self.nonce = self.nonce.wrapping_add(1);
    }
}
