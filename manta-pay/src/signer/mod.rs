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

//! Manta Pay Signer Tools

use crate::config::{Config, MerkleTreeConfiguration};
use manta_accounting::wallet::{ledger, signer};
use manta_util::Array;

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

pub mod client;

#[cfg(feature = "wallet")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "wallet")))]
pub mod base;

/// Synchronization Request
pub type SyncRequest = signer::SyncRequest<Config>;

/// Synchronization Response
pub type SyncResponse = signer::SyncResponse;

/// Synchronization Error
pub type SyncError = signer::SyncError;

/// Sign Request
pub type SignRequest = signer::SignRequest<Config>;

/// Sign Response
pub type SignResponse = signer::SignResponse<Config>;

/// Sign Error
pub type SignError = signer::SignError<Config>;

/// Receiving Key Request
pub type ReceivingKeyRequest = signer::ReceivingKeyRequest;

/// Checkpoint
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Checkpoint {
    /// Receiver Index
    pub receiver_index: Array<usize, { MerkleTreeConfiguration::FOREST_WIDTH }>,

    /// Sender Index
    pub sender_index: usize,
}

impl Checkpoint {
    /// Builds a new [`Checkpoint`] from `receiver_index` and `sender_index`.
    #[inline]
    pub fn new(
        receiver_index: Array<usize, { MerkleTreeConfiguration::FOREST_WIDTH }>,
        sender_index: usize,
    ) -> Self {
        Self {
            receiver_index,
            sender_index,
        }
    }
}

impl Default for Checkpoint {
    #[inline]
    fn default() -> Self {
        Self::new([0; MerkleTreeConfiguration::FOREST_WIDTH].into(), 0)
    }
}

impl ledger::Checkpoint for Checkpoint {
    #[inline]
    fn receiver_index(&self) -> usize {
        self.receiver_index.iter().sum()
    }
}
