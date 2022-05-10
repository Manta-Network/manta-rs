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

//! Manta Pay Signer Configuration

use crate::{
    config::{Bls12_381_Edwards, Config, EncryptedNote, MerkleTreeConfiguration, SecretKey, Utxo},
    crypto::constraint::arkworks::Fp,
    key::{CoinType, KeySecret, Testnet, TestnetKeySecret},
    signer::Checkpoint,
};
use alloc::collections::BTreeMap;
use ark_ec::ProjectiveCurve;
use ark_ff::PrimeField;
use core::{marker::PhantomData, mem};
use manta_accounting::{
    asset::HashAssetMap,
    key::{self, HierarchicalKeyDerivationScheme},
    wallet::{
        self,
        signer::{AssetMapKey, SyncData},
    },
};
use manta_crypto::{key::KeyDerivationFunction, merkle_tree, merkle_tree::forest::Configuration};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Hierarchical Key Derivation Function
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HierarchicalKeyDerivationFunction<C = Testnet>(PhantomData<C>)
where
    C: CoinType;

impl<C> KeyDerivationFunction for HierarchicalKeyDerivationFunction<C>
where
    C: CoinType,
{
    type Key = <KeySecret<C> as HierarchicalKeyDerivationScheme>::SecretKey;
    type Output = SecretKey;

    #[inline]
    fn derive_in(&self, key: &Self::Key, _: &mut ()) -> Self::Output {
        // FIXME: Check that this conversion is logical/safe.
        let bytes: [u8; 32] = key
            .private_key()
            .to_bytes()
            .try_into()
            .expect("The secret key has 32 bytes.");
        Fp(<Bls12_381_Edwards as ProjectiveCurve>::ScalarField::from_le_bytes_mod_order(&bytes))
    }
}

/// Signer UTXO Accumulator
pub type UtxoAccumulator = merkle_tree::forest::TreeArrayMerkleForest<
    MerkleTreeConfiguration,
    merkle_tree::fork::ForkedTree<
        MerkleTreeConfiguration,
        merkle_tree::full::Full<MerkleTreeConfiguration>,
    >,
    { MerkleTreeConfiguration::FOREST_WIDTH },
>;

impl wallet::signer::Configuration for Config {
    type Checkpoint = Checkpoint;
    type HierarchicalKeyDerivationScheme =
        key::Map<TestnetKeySecret, HierarchicalKeyDerivationFunction>;
    type UtxoAccumulator = UtxoAccumulator;
    type AssetMap = HashAssetMap<AssetMapKey<Self>>;
    type Rng = rand_chacha::ChaCha20Rng;

    #[inline]
    fn update_checkpoint(
        checkpoint: &Self::Checkpoint,
        utxo_accumulator: &Self::UtxoAccumulator,
    ) -> Self::Checkpoint {
        Checkpoint::new(
            utxo_accumulator
                .forest
                .as_ref()
                .iter()
                .map(move |t| t.len())
                .collect(),
            checkpoint.sender_index,
        )
    }

    #[inline]
    fn prune_sync_data(
        data: &mut SyncData<Config>,
        origin: &Self::Checkpoint,
        checkpoint: &Self::Checkpoint,
    ) -> bool {
        const PRUNE_PANIC_MESSAGE: &str = "Invalid pruning conditions.";
        if checkpoint < origin {
            return false;
        }
        match checkpoint.sender_index.checked_sub(origin.sender_index) {
            Some(diff) => drop(data.senders.drain(0..diff)),
            _ => panic!("{}", PRUNE_PANIC_MESSAGE),
        }
        let mut data_map = BTreeMap::<u8, Vec<(Utxo, EncryptedNote)>>::new();
        for receiver in mem::take(&mut data.receivers) {
            let key = MerkleTreeConfiguration::tree_index(&receiver.0);
            match data_map.get_mut(&key) {
                Some(entry) => entry.push(receiver),
                _ => {
                    data_map.insert(key, vec![receiver]);
                }
            }
        }
        let mut has_pruned = false;
        for (i, (origin_index, index)) in origin
            .receiver_index
            .into_iter()
            .zip(checkpoint.receiver_index)
            .enumerate()
        {
            match index.checked_sub(origin_index) {
                Some(diff) if diff == 0 => {}
                Some(diff) => {
                    data.receivers.extend(
                        data_map
                            .remove(&(i as u8))
                            .expect(PRUNE_PANIC_MESSAGE)
                            .into_iter()
                            .skip(diff),
                    );
                    has_pruned = true;
                }
                _ => panic!("{}", PRUNE_PANIC_MESSAGE),
            }
        }
        has_pruned
    }
}

/// Signer Parameters Type
pub type SignerParameters = wallet::signer::SignerParameters<Config>;

/// Signer State Type
pub type SignerState = wallet::signer::SignerState<Config>;

/// Signer Base Type
pub type Signer = wallet::signer::Signer<Config>;
