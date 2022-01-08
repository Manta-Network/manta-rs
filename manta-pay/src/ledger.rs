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

use crate::config::{
    Config, EncryptedNote, MerkleTreeConfiguration, ProofSystem, Utxo, VerifyingContext, VoidNumber,
};
use manta_accounting::{
    asset::{AssetId, AssetValue},
    transfer::{
        self, InsufficientPublicBalance, Proof, ReceiverLedger, ReceiverPostingKey, SenderLedger,
        SenderPostingKey, TransferLedger, TransferLedgerSuperPostingKey, UtxoSetOutput,
    },
};
use manta_crypto::{
    constraint::{Input as ProofSystemInput, ProofSystem as _},
    merkle_tree,
    merkle_tree::forest::Configuration,
};
use std::collections::{HashMap, HashSet};

/// UTXO Merkle Forest Type
pub type UtxoMerkleForest = merkle_tree::forest::TreeArrayMerkleForest<
    MerkleTreeConfiguration,
    merkle_tree::single_path::SinglePath<MerkleTreeConfiguration>,
    256,
>;

/// Wrap Type
#[derive(Clone, Copy)]
pub struct Wrap<T>(T);

/// Ledger
pub struct Ledger {
    /// Void Numbers
    void_numbers: HashSet<VoidNumber>,

    /// UTXOs
    utxos: HashSet<Utxo>,

    /// Shards
    shards: HashMap<u8, HashMap<u64, (Utxo, EncryptedNote)>>,

    /// UTXO Forest
    utxo_forest: UtxoMerkleForest,

    /// Verifying Contexts
    verifying_context: transfer::canonical::VerifyingContext<Config>,
}

impl SenderLedger<Config> for Ledger {
    type ValidVoidNumber = Wrap<VoidNumber>;
    type ValidUtxoSetOutput = Wrap<UtxoSetOutput<Config>>;
    type SuperPostingKey = (Wrap<()>, ());

    #[inline]
    fn is_unspent(&self, void_number: VoidNumber) -> Option<Self::ValidVoidNumber> {
        if self.void_numbers.contains(&void_number) {
            None
        } else {
            Some(Wrap(void_number))
        }
    }

    #[inline]
    fn has_matching_utxo_set_output(
        &self,
        output: UtxoSetOutput<Config>,
    ) -> Option<Self::ValidUtxoSetOutput> {
        for tree in self.utxo_forest.forest.as_ref() {
            if tree.root() == &output {
                return Some(Wrap(output));
            }
        }
        None
    }

    #[inline]
    fn spend(
        &mut self,
        utxo_set_output: Self::ValidUtxoSetOutput,
        void_number: Self::ValidVoidNumber,
        super_key: &Self::SuperPostingKey,
    ) {
        let _ = (utxo_set_output, super_key);
        self.void_numbers.insert(void_number.0);
    }
}

impl ReceiverLedger<Config> for Ledger {
    type ValidUtxo = Wrap<Utxo>;
    type SuperPostingKey = (Wrap<()>, ());

    #[inline]
    fn is_not_registered(&self, utxo: Utxo) -> Option<Self::ValidUtxo> {
        if self.utxos.contains(&utxo) {
            None
        } else {
            Some(Wrap(utxo))
        }
    }

    #[inline]
    fn register(
        &mut self,
        utxo: Self::ValidUtxo,
        note: EncryptedNote,
        super_key: &Self::SuperPostingKey,
    ) {
        let _ = super_key;
        let shard = self
            .shards
            .get_mut(&MerkleTreeConfiguration::tree_index(&utxo.0))
            .unwrap();
        let len = shard.len();
        shard.insert(len as u64, (utxo.0, note));
    }
}

impl TransferLedger<Config> for Ledger {
    type ValidSourceBalance = Wrap<AssetValue>;
    type ValidProof = Wrap<()>;
    type SuperPostingKey = ();

    #[inline]
    fn check_source_balances(
        &self,
        sources: Vec<AssetValue>,
    ) -> Result<Vec<Self::ValidSourceBalance>, InsufficientPublicBalance> {
        // FIXME: This can only be implemented on the actual ledger.
        Ok(sources.into_iter().map(Wrap).collect())
    }

    #[inline]
    fn is_valid(
        &self,
        asset_id: Option<AssetId>,
        sources: &[Self::ValidSourceBalance],
        senders: &[SenderPostingKey<Config, Self>],
        receivers: &[ReceiverPostingKey<Config, Self>],
        sinks: &[AssetValue],
        proof: Proof<Config>,
    ) -> Option<Self::ValidProof> {
        let verifying_context = self.verifying_context.select(
            asset_id.is_some(),
            sources.len(),
            senders.len(),
            receivers.len(),
            sinks.len(),
        )?;

        let mut input = Default::default();
        if let Some(asset_id) = asset_id {
            ProofSystem::extend(&mut input, &asset_id);
        }
        sources
            .iter()
            .for_each(|source| ProofSystem::extend(&mut input, &source.0));
        senders.iter().for_each(|sender| {
            // ...
            todo!()
        });
        receivers.iter().for_each(|receiver| {
            // ...
            todo!()
        });
        sinks
            .iter()
            .for_each(|sink| ProofSystem::extend(&mut input, sink));

        ProofSystem::verify(&input, &proof, verifying_context)
            .ok()?
            .then(move || Wrap(()))
    }

    #[inline]
    fn update_public_balances(
        &mut self,
        asset_id: AssetId,
        sources: Vec<Self::ValidSourceBalance>,
        sinks: Vec<AssetValue>,
        proof: Self::ValidProof,
        super_key: &TransferLedgerSuperPostingKey<Config, Self>,
    ) {
        // FIXME: This can only be implemented on the real ledger.
        let _ = (asset_id, sources, sinks, proof, super_key);
    }
}
