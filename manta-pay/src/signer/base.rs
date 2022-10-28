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
    config::{
        utxo::{v2 as protocol_pay, v2::MerkleTreeConfiguration},
        Config,
    },
    key::Manta,
    signer::Checkpoint,
};
use alloc::collections::BTreeMap;
use core::{cmp, mem};
use manta_accounting::{
    asset::HashAssetMap,
    transfer::Identifier,
    wallet::{
        self,
        signer::{self, SyncData},
    },
};
use manta_crypto::{
    accumulator::ItemHashFunction,
    merkle_tree::{self, forest::Configuration},
    rand::ChaCha20Rng,
};

// #[cfg(feature = "serde")]
// use manta_util::serde::{Deserialize, Serialize};

// /// Hierarchical Key Derivation Function
// #[cfg_attr(
//     feature = "serde",
//     derive(Deserialize, Serialize),
//     serde(crate = "manta_util::serde", deny_unknown_fields)
// )]
// #[derive(derivative::Derivative)]
// #[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
// pub struct HierarchicalKeyDerivationFunction<C = Testnet>(PhantomData<C>)
// where
//     C: CoinType;

// impl<C> KeyDerivationFunction for HierarchicalKeyDerivationFunction<C>
// where
//     C: CoinType,
// {
//     type Key = <KeySecret<C> as HierarchicalKeyDerivationScheme>::SecretKey;
//     type Output = SecretKey;

//     #[inline]
//     fn derive(&self, key: &Self::Key, _: &mut ()) -> Self::Output {
//         // FIXME: Check that this conversion is logical/safe.
//         let bytes: [u8; 32] = key
//             .private_key()
//             .to_bytes()
//             .try_into()
//             .expect("The secret key has 32 bytes.");
//         Fp(<Bn254_Edwards as ProjectiveCurve>::ScalarField::from_le_bytes_mod_order(&bytes))
//     }
// }

/// Signer UTXO Accumulator
pub type UtxoAccumulator = merkle_tree::forest::TreeArrayMerkleForest<
    MerkleTreeConfiguration,
    merkle_tree::fork::ForkedTree<
        MerkleTreeConfiguration,
        merkle_tree::full::Full<MerkleTreeConfiguration>,
    >,
    { MerkleTreeConfiguration::FOREST_WIDTH },
>;

// /// Account Type
// type Account: Account<SpendingKey = SpendingKey<Self>, Parameters = Self::Parameters>
// + DeriveAddress<Parameters = Self::Parameters, Address = Self::Address>;

// /// Account Map Type
// type AccountMap: AccountMap<Account = Self::Account>;

// /// Asset Map Type
// type AssetMap: AssetMap<Self::AssetId, Self::AssetValue, Key = Identifier<Self>>;

// AssetMapKey = (KeyIndex, SecretKey);

impl wallet::signer::Configuration for Config {
    type Account = crate::key::KeySecret<Manta>;
    type Checkpoint = Checkpoint;
    type UtxoAccumulator = UtxoAccumulator;
    type AssetMap = HashAssetMap<Identifier<Self>, Self::AssetId, Self::AssetValue>;
    type Rng = ChaCha20Rng;
}

impl signer::Checkpoint<Config> for Checkpoint {
    type UtxoAccumulator = UtxoAccumulator;
    type UtxoAccumulatorItemHash = protocol_pay::UtxoAccumulatorItemHash;

    #[inline]
    fn update_from_nullifiers(&mut self, count: usize) {
        self.sender_index += count;
    }

    #[inline]
    fn update_from_utxo_accumulator(&mut self, utxo_accumulator: &Self::UtxoAccumulator) {
        self.receiver_index = self
            .receiver_index
            .into_iter()
            .zip(utxo_accumulator.forest.as_ref())
            .map(move |(i, t)| cmp::max(i, t.len()))
            .collect();
    }

    /// Prunes the `data` by comparing `origin` and `signer_checkpoint` and checks if updating the
    /// `origin` checkpoint by viewing `data` would exceed the current `signer_checkpoint`. If not,
    /// then we can prune all the data. Otherwise, we take each entry in `data` and remove by shard
    /// index or by global void number index until we reach some pruned data that is at least newer
    /// than `signer_checkpoint`.
    #[inline]
    fn prune(
        parameters: &Self::UtxoAccumulatorItemHash,
        data: &mut SyncData<Config>,
        origin: &Self,
        signer_checkpoint: &Self,
    ) -> bool {
        const PRUNE_PANIC_MESSAGE: &str = "ERROR: Invalid pruning conditions";
        if signer_checkpoint <= origin {
            return false;
        }
        let mut updated_origin = *origin;
        for receiver in &data.utxo_note_data {
            let key =
                MerkleTreeConfiguration::tree_index(&parameters.item_hash(&receiver.0, &mut ()));
            updated_origin.receiver_index[key as usize] += 1;
        }
        updated_origin.sender_index += data.nullifier_data.len();
        if signer_checkpoint > &updated_origin {
            *data = Default::default();
            return true;
        }
        let mut has_pruned = false;
        match signer_checkpoint
            .sender_index
            .checked_sub(origin.sender_index)
        {
            Some(diff) => {
                drop(data.nullifier_data.drain(0..diff));
                if diff > 0 {
                    has_pruned = true;
                }
            }
            _ => panic!(
                "{}: Sender Pruning: {:?} {:?} {:?}",
                PRUNE_PANIC_MESSAGE, data, origin, signer_checkpoint
            ),
        }
        let mut data_map = BTreeMap::<_, Vec<_>>::new();
        for receiver in mem::take(&mut data.utxo_note_data) {
            let key =
                MerkleTreeConfiguration::tree_index(&parameters.item_hash(&receiver.0, &mut ()));
            match data_map.get_mut(&key) {
                Some(entry) => entry.push(receiver),
                _ => {
                    data_map.insert(key, vec![receiver]);
                }
            }
        }
        for (i, (origin_index, index)) in origin
            .receiver_index
            .into_iter()
            .zip(signer_checkpoint.receiver_index)
            .enumerate()
        {
            match index.checked_sub(origin_index) {
                Some(diff) => {
                    if let Some(entries) = data_map.remove(&(i as u8)) {
                        data.utxo_note_data.extend(entries.into_iter().skip(diff));
                        if diff > 0 {
                            has_pruned = true;
                        }
                    }
                }
                _ => panic!(
                    "{}: Receiver Pruning: {:?} {:?} {:?}",
                    PRUNE_PANIC_MESSAGE, data, origin, signer_checkpoint
                ),
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
