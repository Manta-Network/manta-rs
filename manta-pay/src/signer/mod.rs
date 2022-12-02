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

use alloc::{format, string::String};
use core::ops::Div;
use manta_accounting::wallet::signer;

#[cfg(feature = "groth16")]
use crate::config::{utxo::Checkpoint, Config};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

pub mod client;

#[cfg(feature = "wallet")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "wallet")))]
pub mod base;

/// Synchronization Request
pub type SyncRequest = signer::SyncRequest<Config, Checkpoint>;

/// Synchronization Response
pub type SyncResponse = signer::SyncResponse<Config, Checkpoint>;

/// Synchronization Error
pub type SyncError = signer::SyncError<Checkpoint>;

/// Synchronization Result
pub type SyncResult = signer::SyncResult<Config, Checkpoint>;

/// Signing Request
pub type SignRequest = signer::SignRequest<AssetMetadata, Config>;

/// Signing Response
pub type SignResponse = signer::SignResponse<Config>;

/// Signing Error
pub type SignError = signer::SignError<Config>;

/// Signing Result
pub type SignResult = signer::SignResult<Config>;

/// Receiving Key Request
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GetRequest {
    /// GET
    #[default]
    Get,
}

/// Asset Type
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde")
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TokenType {
    /// Fungible Token
    FT(u32),

    /// Non-fungible Token
    NFT,
}

impl Default for TokenType {
    fn default() -> Self {
        TokenType::FT(Default::default())
    }
}

/// Asset Metadata. To describe an [`Asset`](manta_accounting::asset::Asset) with a
/// particular `AssetId` we use [`AssetMetadata`] to assign a symbol and distinguish between
/// FTs and NFTs. For FTs we assign decimals for human-readable display purposes.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde")
)]
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct AssetMetadata {
    /// TokenType
    pub token_type: TokenType,

    /// Asset Symbol
    pub symbol: String,
}

impl AssetMetadata {
    /// Returns a string formatting of only the `value` interpreted using `self` as the metadata.
    #[inline]
    pub fn display_value<V>(&self, value: V) -> Option<String>
    where
        for<'v> &'v V: Div<u128, Output = u128>,
    {
        // TODO: What if we want more than three `FRACTIONAL_DIGITS`? How do we make this method
        //       more general?
        match self.token_type {
            TokenType::FT(decimals) => {
                const FRACTIONAL_DIGITS: u32 = 3;
                let value_base_units = &value / (10u128.pow(decimals));
                let fractional_digits = &value / (10u128.pow(decimals - FRACTIONAL_DIGITS))
                    % (10u128.pow(FRACTIONAL_DIGITS));
                Some(format!("{value_base_units}.{fractional_digits:0>3}"))
            }
            TokenType::NFT => None,
        }
    }
    /// Returns a string formatting of `value` interpreted using `self` as the metadata including
    /// the symbol.
    #[inline]
    pub fn display<V>(&self, value: V) -> String
    where
        for<'v> &'v V: Div<u128, Output = u128>,
    {
        match self.display_value(value) {
            Some(str) => format!("{} {}", str, self.symbol),
            _ => format!("{} {}", "NFT", self.symbol),
        }
    }
}
