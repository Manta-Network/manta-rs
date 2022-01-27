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

//! Manta Pay Wallet Implementation

// TODO: Build websockets wallet.

use crate::{
    config::{Bls12_381_Edwards, Config, MerkleTreeConfiguration, SecretKey},
    crypto::constraint::arkworks::Fp,
    key::TestnetKeySecret,
};
use ark_ec::ProjectiveCurve;
use ark_ff::PrimeField;
use manta_accounting::{
    asset::HashAssetMap,
    key::{self, HierarchicalKeyDerivationScheme},
    wallet::{
        self,
        signer::{self, AssetMapKey},
    },
};
use manta_crypto::{key::KeyDerivationFunction, merkle_tree};
use manta_util::pointer::ThreadSafe;

pub mod cache;

/// Hierarchical Key Derivation Function
pub struct HierarchicalKeyDerivationFunction;

impl KeyDerivationFunction for HierarchicalKeyDerivationFunction {
    type Key = <TestnetKeySecret as HierarchicalKeyDerivationScheme>::SecretKey;
    type Output = SecretKey;

    #[inline]
    fn derive(secret_key: &Self::Key) -> Self::Output {
        // FIXME: Check that this conversion is logical/safe.
        let bytes: [u8; 32] = secret_key
            .private_key()
            .to_bytes()
            .try_into()
            .expect("The secret key has 32 bytes.");
        Fp(<Bls12_381_Edwards as ProjectiveCurve>::ScalarField::from_le_bytes_mod_order(&bytes))
    }
}

/// Signer UTXO Set
pub type UtxoSet = merkle_tree::forest::TreeArrayMerkleForest<
    MerkleTreeConfiguration,
    merkle_tree::fork::ForkedTree<
        MerkleTreeConfiguration,
        merkle_tree::full::Full<MerkleTreeConfiguration>,
        ThreadSafe,
    >,
    { MerkleTreeConfiguration::FOREST_WIDTH },
>;

impl signer::Configuration for Config {
    type HierarchicalKeyDerivationScheme =
        key::Map<TestnetKeySecret, HierarchicalKeyDerivationFunction>;
    type UtxoSet = UtxoSet;
    type AssetMap = HashAssetMap<AssetMapKey<Self>>;
    type ProvingContextCache = cache::OnDiskMultiProvingContext;
    type Rng = rand_chacha::ChaCha20Rng;
}

/// Signer
pub type Signer = signer::Signer<Config>;

/// Wallet
pub type Wallet<L> = wallet::Wallet<Config, L, Signer>;
