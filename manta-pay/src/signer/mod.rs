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
pub type SyncRequest = signer::SyncRequest<Config, Checkpoint>;

/// Synchronization Response
pub type SyncResponse = signer::SyncResponse<Checkpoint>;

/// Synchronization Error
pub type SyncError = signer::SyncError<Checkpoint>;

/// Synchronization Result
pub type SyncResult = signer::SyncResult<Checkpoint>;

/// Signing Request
pub type SignRequest = signer::SignRequest<Config>;

/// Signing Response
pub type SignResponse = signer::SignResponse<Config>;

/// Signing Error
pub type SignError = signer::SignError<Config>;

/// Signing Result
pub type SignResult = signer::SignResult<Config>;

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

impl From<RawCheckpoint> for Checkpoint {
    #[inline]
    fn from(checkpoint: RawCheckpoint) -> Self {
        Self::new(
            checkpoint.receiver_index.map(|i| i as usize).into(),
            checkpoint.sender_index as usize,
        )
    }
}

impl ledger::Checkpoint for Checkpoint {}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl scale_codec::Decode for Checkpoint {
    #[inline]
    fn decode<I>(input: &mut I) -> Result<Self, scale_codec::Error>
    where
        I: scale_codec::Input,
    {
        RawCheckpoint::decode(input).map(Into::into)
    }
}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl scale_codec::Encode for Checkpoint {
    #[inline]
    fn using_encoded<R, Encoder>(&self, f: Encoder) -> R
    where
        Encoder: FnOnce(&[u8]) -> R,
    {
        RawCheckpoint::from(*self).using_encoded(f)
    }
}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl scale_codec::EncodeLike for Checkpoint {}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl scale_codec::MaxEncodedLen for Checkpoint {
    #[inline]
    fn max_encoded_len() -> usize {
        RawCheckpoint::max_encoded_len()
    }
}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl scale_info::TypeInfo for Checkpoint {
    type Identity = RawCheckpoint;

    #[inline]
    fn type_info() -> scale_info::Type {
        Self::Identity::type_info()
    }
}

/// Raw Checkpoint for Encoding and Decoding
#[cfg_attr(
    feature = "scale",
    derive(
        scale_codec::Decode,
        scale_codec::Encode,
        scale_codec::MaxEncodedLen,
        scale_info::TypeInfo
    )
)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RawCheckpoint {
    /// Receiver Index
    pub receiver_index: [u64; MerkleTreeConfiguration::FOREST_WIDTH],

    /// Sender Index
    pub sender_index: u64,
}

impl RawCheckpoint {
    /// Builds a new [`RawCheckpoint`] from `receiver_index` and `sender_index`.
    #[inline]
    pub fn new(
        receiver_index: [u64; MerkleTreeConfiguration::FOREST_WIDTH],
        sender_index: u64,
    ) -> Self {
        Self {
            receiver_index,
            sender_index,
        }
    }
}

impl Default for RawCheckpoint {
    #[inline]
    fn default() -> Self {
        Self::new([0; MerkleTreeConfiguration::FOREST_WIDTH], 0)
    }
}

impl From<Checkpoint> for RawCheckpoint {
    #[inline]
    fn from(checkpoint: Checkpoint) -> Self {
        Self::new(
            (*checkpoint.receiver_index).map(|i| i as u64),
            checkpoint.sender_index as u64,
        )
    }
}
