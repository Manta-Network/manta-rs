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
    Config, EncryptedNote, MerkleTreeConfiguration, ProofSystem, Utxo, VoidNumber,
};
use manta_accounting::{
    asset::{AssetId, AssetValue},
    transfer::{
        self, AccountBalance, InvalidSinkAccounts, InvalidSourceAccounts, Proof, ReceiverLedger,
        ReceiverPostingKey, SenderLedger, SenderPostingKey, SinkPostingKey, SourcePostingKey,
        TransferLedger, TransferLedgerSuperPostingKey, TransferPostingKey, UtxoSetOutput,
    },
};
use manta_crypto::{constraint::ProofSystem as _, merkle_tree, merkle_tree::forest::Configuration};
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

impl<T> AsRef<T> for Wrap<T> {
    #[inline]
    fn as_ref(&self) -> &T {
        &self.0
    }
}

/// Wrap Pair Type
#[derive(Clone, Copy)]
pub struct WrapPair<L, R>(L, R);

impl<L, R> AsRef<R> for WrapPair<L, R> {
    #[inline]
    fn as_ref(&self) -> &R {
        &self.1
    }
}

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

    /// Account Table
    accounts: HashMap<u128, HashMap<AssetId, AssetValue>>,

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
    type AccountId = u128;
    type ValidSourceAccount = WrapPair<Self::AccountId, AssetValue>;
    type ValidSinkAccount = WrapPair<Self::AccountId, AssetValue>;
    type ValidProof = Wrap<()>;
    type SuperPostingKey = ();

    #[inline]
    fn check_source_accounts(
        &self,
        asset_id: Option<AssetId>,
        accounts: Vec<Self::AccountId>,
        sources: Vec<AssetValue>,
    ) -> Result<Vec<Self::ValidSourceAccount>, InvalidSourceAccounts<Self::AccountId>> {
        if let Some(asset_id) = asset_id {
            let mut valid_source_accounts = Vec::new();
            for (account_id, withdraw) in accounts.into_iter().zip(sources) {
                match self.accounts.get(&account_id) {
                    Some(map) => match map.get(&asset_id) {
                        Some(balance) => {
                            if balance >= &withdraw {
                                valid_source_accounts.push(WrapPair(account_id, withdraw));
                            } else {
                                return Err(InvalidSourceAccounts::BadAccount {
                                    account_id,
                                    balance: AccountBalance::Known(*balance),
                                    withdraw,
                                });
                            }
                        }
                        _ => {
                            // FIXME: What about zero values in `sources`?
                            return Err(InvalidSourceAccounts::BadAccount {
                                account_id,
                                balance: AccountBalance::Known(AssetValue(0)),
                                withdraw,
                            });
                        }
                    },
                    _ => {
                        return Err(InvalidSourceAccounts::BadAccount {
                            account_id,
                            balance: AccountBalance::UnknownAccount,
                            withdraw,
                        });
                    }
                }
            }
            Ok(valid_source_accounts)
        } else if accounts.is_empty() && sources.is_empty() {
            Ok(Vec::new())
        } else {
            Err(InvalidSourceAccounts::InvalidShape)
        }
    }

    #[inline]
    fn check_sink_accounts(
        &self,
        asset_id: Option<AssetId>,
        accounts: Vec<Self::AccountId>,
        sinks: Vec<AssetValue>,
    ) -> Result<Vec<Self::ValidSinkAccount>, InvalidSinkAccounts<Self::AccountId>> {
        if asset_id.is_some() {
            let mut valid_sink_accounts = Vec::new();
            for (account_id, deposit) in accounts.into_iter().zip(sinks) {
                if self.accounts.contains_key(&account_id) {
                    valid_sink_accounts.push(WrapPair(account_id, deposit));
                } else {
                    return Err(InvalidSinkAccounts::BadAccount { account_id });
                }
            }
            Ok(valid_sink_accounts)
        } else if accounts.is_empty() && sinks.is_empty() {
            Ok(Vec::new())
        } else {
            Err(InvalidSinkAccounts::InvalidShape)
        }
    }

    #[inline]
    fn is_valid(
        &self,
        asset_id: Option<AssetId>,
        sources: &[SourcePostingKey<Config, Self>],
        senders: &[SenderPostingKey<Config, Self>],
        receivers: &[ReceiverPostingKey<Config, Self>],
        sinks: &[SinkPostingKey<Config, Self>],
        proof: Proof<Config>,
    ) -> Option<Self::ValidProof> {
        let verifying_context = self.verifying_context.select(
            asset_id.is_some(),
            sources.len(),
            senders.len(),
            receivers.len(),
            sinks.len(),
        )?;
        ProofSystem::verify(
            &TransferPostingKey::generate_proof_input(asset_id, sources, senders, receivers, sinks),
            &proof,
            verifying_context,
        )
        .ok()?
        .then(move || Wrap(()))
    }

    #[inline]
    fn update_public_balances(
        &mut self,
        asset_id: AssetId,
        sources: Vec<SourcePostingKey<Config, Self>>,
        sinks: Vec<SinkPostingKey<Config, Self>>,
        proof: Self::ValidProof,
        super_key: &TransferLedgerSuperPostingKey<Config, Self>,
    ) {
        let _ = (proof, super_key);
        for WrapPair(account_id, withdraw) in sources {
            *self
                .accounts
                .get_mut(&account_id)
                .expect("We checked that this account exists.")
                .get_mut(&asset_id)
                .expect("We checked that this account has enough balance to withdraw.") -= withdraw;
        }
        for WrapPair(account_id, deposit) in sinks {
            *self
                .accounts
                .get_mut(&account_id)
                .expect("We checked that this account exists.")
                .entry(asset_id)
                .or_default() += deposit;
        }
    }
}
