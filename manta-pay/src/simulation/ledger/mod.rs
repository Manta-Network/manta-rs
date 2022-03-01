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

//! Ledger Simulation

use crate::{
    config::{
        Config, EncryptedNote, MerkleTreeConfiguration, MultiVerifyingContext, ProofSystem,
        TransferPost, Utxo, UtxoAccumulatorModel, VoidNumber,
    },
    signer::Checkpoint,
};
use alloc::{sync::Arc, vec::Vec};
use core::convert::Infallible;
use indexmap::IndexSet;
use manta_accounting::{
    asset::{Asset, AssetId, AssetList, AssetValue},
    transfer::{
        canonical::TransferShape, AccountBalance, InvalidSinkAccount, InvalidSourceAccount, Proof,
        ReceiverLedger, ReceiverPostingKey, SenderLedger, SenderPostingKey, SinkPostingKey,
        SourcePostingKey, TransferLedger, TransferLedgerSuperPostingKey, TransferPostingKey,
        UtxoAccumulatorOutput,
    },
    wallet::{
        ledger::{self, PullResponse, PullResult, PushResponse, PushResult},
        test::PublicBalanceOracle,
    },
};
use manta_crypto::{
    constraint::ProofSystem as _,
    merkle_tree::{
        self,
        forest::{Configuration, FixedIndex},
        Tree,
    },
};
use manta_util::Array;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

#[cfg(feature = "http")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "http")))]
pub mod client;

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
pub mod server;

/// Merkle Forest Index
pub type MerkleForestIndex = <MerkleTreeConfiguration as Configuration>::Index;

/// UTXO Merkle Forest Type
pub type UtxoMerkleForest = merkle_tree::forest::TreeArrayMerkleForest<
    MerkleTreeConfiguration,
    merkle_tree::single_path::SinglePath<MerkleTreeConfiguration>,
    { MerkleTreeConfiguration::FOREST_WIDTH },
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

/// Account Id
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields, transparent)
)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AccountId(pub u64);

/// Ledger
#[derive(Debug)]
pub struct Ledger {
    /// Void Numbers
    void_numbers: IndexSet<VoidNumber>,

    /// UTXOs
    utxos: HashSet<Utxo>,

    /// Shards
    shards: HashMap<MerkleForestIndex, IndexSet<(Utxo, EncryptedNote)>>,

    /// UTXO Forest
    utxo_forest: UtxoMerkleForest,

    /// Account Table
    accounts: HashMap<AccountId, HashMap<AssetId, AssetValue>>,

    /// Verifying Contexts
    verifying_context: MultiVerifyingContext,
}

impl Ledger {
    /// Builds an empty [`Ledger`].
    #[inline]
    pub fn new(
        utxo_accumulator_model: UtxoAccumulatorModel,
        verifying_context: MultiVerifyingContext,
    ) -> Self {
        Self {
            void_numbers: Default::default(),
            utxos: Default::default(),
            shards: (0..MerkleTreeConfiguration::FOREST_WIDTH)
                .map(move |i| (MerkleForestIndex::from_index(i), Default::default()))
                .collect(),
            utxo_forest: UtxoMerkleForest::new(utxo_accumulator_model),
            accounts: Default::default(),
            verifying_context,
        }
    }

    /// Sets the public balance of `account` in assets with `id` to `value`.
    #[inline]
    pub fn set_public_balance(&mut self, account: AccountId, id: AssetId, value: AssetValue) {
        self.accounts.entry(account).or_default().insert(id, value);
    }
}

impl SenderLedger<Config> for Ledger {
    type ValidVoidNumber = Wrap<VoidNumber>;
    type ValidUtxoAccumulatorOutput = Wrap<UtxoAccumulatorOutput<Config>>;
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
    fn has_matching_utxo_accumulator_output(
        &self,
        output: UtxoAccumulatorOutput<Config>,
    ) -> Option<Self::ValidUtxoAccumulatorOutput> {
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
        utxo_accumulator_output: Self::ValidUtxoAccumulatorOutput,
        void_number: Self::ValidVoidNumber,
        super_key: &Self::SuperPostingKey,
    ) {
        let _ = (utxo_accumulator_output, super_key);
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
            .expect("All shards exist when the ledger is constructed.");
        shard.insert((utxo.0, note));
        self.utxos.insert(utxo.0);
        self.utxo_forest.push(&utxo.0);
    }
}

impl TransferLedger<Config> for Ledger {
    type AccountId = AccountId;
    type Event = ();
    type ValidSourceAccount = WrapPair<Self::AccountId, AssetValue>;
    type ValidSinkAccount = WrapPair<Self::AccountId, AssetValue>;
    type ValidProof = Wrap<()>;
    type SuperPostingKey = ();

    #[inline]
    fn check_source_accounts<I>(
        &self,
        asset_id: AssetId,
        sources: I,
    ) -> Result<Vec<Self::ValidSourceAccount>, InvalidSourceAccount<Self::AccountId>>
    where
        I: Iterator<Item = (Self::AccountId, AssetValue)>,
    {
        sources
            .map(|(account_id, withdraw)| {
                match self.accounts.get(&account_id) {
                    Some(map) => match map.get(&asset_id) {
                        Some(balance) => {
                            if balance >= &withdraw {
                                Ok(WrapPair(account_id, withdraw))
                            } else {
                                Err(InvalidSourceAccount {
                                    account_id,
                                    balance: AccountBalance::Known(*balance),
                                    withdraw,
                                })
                            }
                        }
                        _ => {
                            // FIXME: What about zero values in `sources`?
                            Err(InvalidSourceAccount {
                                account_id,
                                balance: AccountBalance::Known(AssetValue(0)),
                                withdraw,
                            })
                        }
                    },
                    _ => Err(InvalidSourceAccount {
                        account_id,
                        balance: AccountBalance::UnknownAccount,
                        withdraw,
                    }),
                }
            })
            .collect()
    }

    #[inline]
    fn check_sink_accounts<I>(
        &self,
        sinks: I,
    ) -> Result<Vec<Self::ValidSinkAccount>, InvalidSinkAccount<Self::AccountId>>
    where
        I: Iterator<Item = (Self::AccountId, AssetValue)>,
    {
        sinks
            .map(move |(account_id, deposit)| {
                if self.accounts.contains_key(&account_id) {
                    Ok(WrapPair(account_id, deposit))
                } else {
                    Err(InvalidSinkAccount { account_id })
                }
            })
            .collect()
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
    ) -> Option<(Self::ValidProof, Self::Event)> {
        let verifying_context = self.verifying_context.select(TransferShape::select(
            asset_id.is_some(),
            sources.len(),
            senders.len(),
            receivers.len(),
            sinks.len(),
        )?);
        ProofSystem::verify(
            verifying_context,
            &TransferPostingKey::generate_proof_input(asset_id, sources, senders, receivers, sinks),
            &proof,
        )
        .ok()?
        .then(move || (Wrap(()), ()))
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

/// Shared Ledger
pub type SharedLedger = Arc<RwLock<Ledger>>;

/// Ledger Connection
pub struct LedgerConnection {
    /// Ledger Account
    account: AccountId,

    /// Ledger Accessor
    ledger: SharedLedger,
}

impl LedgerConnection {
    /// Builds a new [`LedgerConnection`] for `account` and `ledger`.
    #[inline]
    pub fn new(account: AccountId, ledger: SharedLedger) -> Self {
        Self { account, ledger }
    }
}

impl ledger::Connection<Config> for LedgerConnection {
    type Checkpoint = Checkpoint;
    type ReceiverChunk = Vec<(Utxo, EncryptedNote)>;
    type SenderChunk = Vec<VoidNumber>;
    type Error = Infallible;

    #[inline]
    fn pull(&mut self, checkpoint: &Self::Checkpoint) -> PullResult<Config, Self> {
        let ledger = self.ledger.read();
        let mut receivers = Vec::new();
        for (i, mut index) in checkpoint.receiver_index.iter().copied().enumerate() {
            let shard = &ledger.shards[&MerkleForestIndex::from_index(i)];
            while let Some(entry) = shard.get_index(index) {
                receivers.push(*entry);
                index += 1;
            }
        }
        let senders = ledger
            .void_numbers
            .iter()
            .skip(checkpoint.sender_index)
            .copied()
            .collect();
        Ok(PullResponse {
            should_continue: false,
            checkpoint: Checkpoint::new(
                Array::from_unchecked(
                    ledger
                        .utxo_forest
                        .forest
                        .as_ref()
                        .iter()
                        .map(move |t| t.len())
                        .collect::<Vec<_>>(),
                ),
                ledger.void_numbers.len(),
            ),
            receivers,
            senders,
        })
    }

    #[inline]
    fn push(&mut self, posts: Vec<TransferPost>) -> PushResult<Config, Self> {
        let mut ledger = self.ledger.write();
        for post in posts {
            let (sources, sinks) = match TransferShape::from_post(&post) {
                Some(TransferShape::Mint) => (vec![self.account], vec![]),
                Some(TransferShape::PrivateTransfer) => (vec![], vec![]),
                Some(TransferShape::Reclaim) => (vec![], vec![self.account]),
                _ => return Ok(PushResponse { success: false }),
            };
            match post.validate(sources, sinks, &*ledger) {
                Ok(posting_key) => {
                    posting_key.post(&(), &mut *ledger);
                }
                Err(err) => {
                    println!("ERROR: {:?}", err);
                    return Ok(PushResponse { success: false });
                }
            }
        }
        Ok(PushResponse { success: true })
    }
}

impl PublicBalanceOracle for LedgerConnection {
    #[inline]
    fn public_balances(&self) -> Option<AssetList> {
        Some(
            self.ledger
                .read()
                .accounts
                .get(&self.account)?
                .iter()
                .map(|(id, value)| Asset::new(*id, *value))
                .collect(),
        )
    }
}
