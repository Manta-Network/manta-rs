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

//! Ledger Implementation

// FIXME: Migrate this to new ledger abstraction. This will most likely go to `wallet` since it
//        represents the "native" ledger rather than the blockchain ledger.

use crate::{
    accounting::{
        config::Configuration,
        identity::{Parameters, Root, Utxo},
    },
    crypto::merkle_tree::ConfigConverter,
};
use alloc::{collections::BTreeSet, vec, vec::Vec};
use blake2::{
    digest::{Update, VariableOutput},
    VarBlake2s,
};
use manta_crypto::merkle_tree::{single_path::SinglePath, Tree};
use manta_util::{as_bytes, into_array_unchecked};

/// UTXO Shard
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct UtxoShard {
    /// Shard Root
    root: Root,

    /// Unspent Transaction Outputs
    utxos: SinglePath<ConfigConverter<Configuration>>,
}

/// UTXO Set Ledger
#[derive(Clone)]
pub struct UtxoSetLedger {
    /// UTXO Shards
    pub shards: [UtxoShard; Self::SHARD_COUNT],

    /// UTXO Set
    pub utxos: BTreeSet<[u8; 32]>,

    /// Merkle Tree Parameters
    pub parameters: Parameters,
}

impl UtxoSetLedger {
    const SHARD_COUNT: usize = 256;

    /// Builds a new [`UtxoSetLedger`].
    #[inline]
    pub fn new(parameters: Parameters) -> Self {
        Self {
            shards: into_array_unchecked(vec![Default::default(); Self::SHARD_COUNT]),
            utxos: Default::default(),
            parameters,
        }
    }

    /// Computes the shard index of this `utxo`.
    #[inline]
    fn shard_index(utxo: &Utxo) -> usize {
        let mut hasher = VarBlake2s::new(1).expect("Failed to generate Variable Blake2s hasher.");
        hasher.update(&as_bytes!(utxo));
        let mut res: usize = 0;
        hasher.finalize_variable(|x| res = x[0] as usize);
        res
    }

    /// Returns a shared reference to the shard which this `utxo` would be stored in.
    #[inline]
    pub fn shard(&self, utxo: &Utxo) -> &UtxoShard {
        &self.shards[Self::shard_index(utxo)]
    }

    /// Returns `true` if the `root` belongs to some shard.
    #[inline]
    pub fn root_exists(&self, root: &Root) -> bool {
        self.shards.iter().any(move |s| s.root == *root)
    }

    /// Returns `true` if the `utxo` belongs to the shard it would be stored in.
    #[inline]
    pub fn utxo_exists(&self, utxo: &Utxo) -> bool {
        self.utxos.contains(as_bytes!(utxo).as_slice())
    }

    ///
    #[inline]
    pub fn insert(&mut self, utxo: &Utxo) -> bool {
        if self.utxo_exists(utxo) {
            return false;
        }
        if !self.shards[Self::shard_index(utxo)]
            .utxos
            .push(&self.parameters, utxo)
        {
            return false;
        }
        self.utxos.insert(into_array_unchecked(as_bytes!(utxo)));
        true
    }
}
