// Copyright 2019-2021 Manta Network.
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

//! Manta Pay Base Wallet Implementation

use crate::{
    config::{Config, HierarchicalKeyDerivationFunction, MerkleTreeConfiguration},
    key::TestnetKeySecret,
};
use manta_accounting::{
    asset::HashAssetMap,
    key,
    transfer::canonical::MultiProvingContext,
    wallet::{
        self,
        signer::{self, AssetMapKey},
    },
};
use manta_crypto::merkle_tree;

/// Signer UTXO Set
pub type UtxoSet = merkle_tree::forest::TreeArrayMerkleForest<
    MerkleTreeConfiguration,
    merkle_tree::fork::ForkedTree<
        MerkleTreeConfiguration,
        merkle_tree::full::Full<MerkleTreeConfiguration>,
    >,
    256,
>;

impl signer::Configuration for Config {
    type HierarchicalKeyDerivationScheme =
        key::Map<TestnetKeySecret, HierarchicalKeyDerivationFunction>;
    type UtxoSet = UtxoSet;
    type AssetMap = HashAssetMap<AssetMapKey<Self>>;
    type ProvingContextCache = MultiProvingContext<Self>;
    type Rng = rand_chacha::ChaCha20Rng;
}

/// Signer
pub type Signer = signer::Signer<Config>;

/// Wallet
pub type Wallet<L> = wallet::Wallet<Config, L, Signer>;
