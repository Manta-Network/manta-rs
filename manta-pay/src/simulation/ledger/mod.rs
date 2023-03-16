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

// TODO: How to model existential deposits and fee payments?
// TODO: Add in some concurrency (and measure how much we need it).

use crate::{
    config::{
        utxo::{
            AssetId, AssetValue, Checkpoint, FullIncomingNote, MerkleTreeConfiguration, Parameters,
        },
        AccountId, Config, MultiVerifyingContext, Nullifier, ProofSystem, TransferPost, Utxo,
        UtxoAccumulatorModel,
    },
    signer::InitialSyncData,
};
use alloc::{sync::Arc, vec::Vec};
use core::convert::Infallible;
use indexmap::IndexSet;
use manta_accounting::{
    asset::{Asset, AssetList},
    transfer::{
        canonical::TransferShape,
        receiver::{ReceiverLedger, ReceiverPostError},
        sender::{SenderLedger, SenderPostError},
        InvalidAuthorizationSignature, InvalidSinkAccount, InvalidSourceAccount, SinkPostingKey,
        SourcePostingKey, TransferLedger, TransferLedgerSuperPostingKey, TransferPostError,
        TransferPostingKeyRef, UtxoAccumulatorOutput,
    },
    wallet::{
        ledger::{self, ReadResponse},
        signer::SyncData,
        test::PublicBalanceOracle,
    },
};
use manta_crypto::{
    accumulator::ItemHashFunction,
    constraint::ProofSystem as _,
    merkle_tree::{
        self,
        forest::{Configuration, FixedIndex, Forest},
    },
};
use manta_util::future::{LocalBoxFuture, LocalBoxFutureResult};
use std::collections::{HashMap, HashSet};
use tokio::sync::RwLock;

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

#[cfg(feature = "http")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "http")))]
pub mod http;

/// Merkle Forest Index
pub type MerkleForestIndex = <MerkleTreeConfiguration as Configuration>::Index;

/// UTXO Merkle Forest Type
pub type UtxoMerkleForest = merkle_tree::forest::TreeArrayMerkleForest<
    MerkleTreeConfiguration,
    merkle_tree::single_path::SinglePath<MerkleTreeConfiguration>,
    { MerkleTreeConfiguration::FOREST_WIDTH },
>;

/// Wrap Type
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Wrap<T>(T);

impl<T> AsRef<T> for Wrap<T> {
    #[inline]
    fn as_ref(&self) -> &T {
        &self.0
    }
}

/// Wrap Pair Type
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WrapPair<L, R>(L, R);

impl<L, R> AsRef<R> for WrapPair<L, R> {
    #[inline]
    fn as_ref(&self) -> &R {
        &self.1
    }
}

/// Ledger
#[derive(Debug)]
pub struct Ledger {
    /// Nullifier
    nullifiers: IndexSet<Nullifier>,

    /// UTXOs
    utxos: HashSet<Utxo>,

    /// Shards
    shards: HashMap<MerkleForestIndex, IndexSet<(Utxo, FullIncomingNote)>>,

    /// UTXO Forest
    utxo_forest: UtxoMerkleForest,

    /// Account Table
    accounts: HashMap<AccountId, HashMap<AssetId, AssetValue>>,

    /// Verifying Contexts
    verifying_context: MultiVerifyingContext,

    /// UTXO Configuration Parameters
    parameters: Parameters,
}

impl Ledger {
    /// Builds an empty [`Ledger`].
    #[inline]
    pub fn new(
        utxo_accumulator_model: UtxoAccumulatorModel,
        verifying_context: MultiVerifyingContext,
        parameters: Parameters,
    ) -> Self {
        Self {
            nullifiers: Default::default(),
            utxos: Default::default(),
            shards: (0..MerkleTreeConfiguration::FOREST_WIDTH)
                .map(move |i| (MerkleForestIndex::from_index(i), Default::default()))
                .collect(),
            utxo_forest: UtxoMerkleForest::new(utxo_accumulator_model),
            accounts: Default::default(),
            verifying_context,
            parameters,
        }
    }

    /// Returns the public balances of `account` if it exists.
    #[inline]
    pub fn public_balances(&self, account: AccountId) -> Option<AssetList<AssetId, AssetValue>> {
        Some(
            self.accounts
                .get(&account)?
                .iter()
                .map(|(id, value)| Asset::new(*id, *value))
                .collect(),
        )
    }

    /// Sets the public balance of `account` in assets with `id` to `value`.
    #[inline]
    pub fn set_public_balance(&mut self, account: AccountId, id: AssetId, value: AssetValue) {
        assert_ne!(id, Default::default(), "Asset id can't be zero!");
        self.accounts.entry(account).or_default().insert(id, value);
    }

    /// Pulls the data from the ledger later than the given `checkpoint`.
    #[inline]
    pub fn pull(&self, checkpoint: &Checkpoint) -> ReadResponse<SyncData<Config>> {
        let mut receivers = Vec::new();
        for (i, mut index) in checkpoint.receiver_index.iter().copied().enumerate() {
            let shard = &self.shards[&MerkleForestIndex::from_index(i)];
            while let Some(entry) = shard.get_index(index) {
                receivers.push(entry.clone());
                index += 1;
            }
        }
        let senders = self
            .nullifiers
            .iter()
            .skip(checkpoint.sender_index)
            .cloned()
            .collect();
        ReadResponse {
            should_continue: false,
            data: SyncData {
                utxo_note_data: receivers,
                nullifier_data: senders,
            },
        }
    }

    /// Pushes the data from `posts` to the ledger.
    #[inline]
    pub fn push(&mut self, account: AccountId, posts: Vec<TransferPost>) -> bool {
        for post in posts {
            let (sources, sinks) = match TransferShape::from_post(&post) {
                Some(TransferShape::ToPrivate) => (vec![account], vec![]),
                Some(TransferShape::PrivateTransfer) => (vec![], vec![]),
                Some(TransferShape::ToPublic) => (vec![], vec![account]),
                _ => return false,
            };
            match post.validate(&self.parameters, &*self, sources, sinks) {
                Ok(posting_key) => posting_key.post(&mut *self, &()).unwrap(),
                _ => return false,
            }
        }
        true
    }

    ///
    #[inline]
    pub fn initial_read(&self) -> ReadResponse<InitialSyncData> {
        let mut utxos = Vec::new();
        for (i, mut index) in (0..MerkleTreeConfiguration::FOREST_WIDTH).enumerate() {
            let shard = &self.shards[&MerkleForestIndex::from_index(i)];
            while let Some(entry) = shard.get_index(index) {
                utxos.push(entry.0.clone());
                index += 1;
            }
        }
        let senders = self.nullifiers.iter().cloned().collect::<Vec<_>>();
        let utxo_merkle_forest = self.utxo_forest.clone();
        let mut membership_proof_data = Vec::new();
        for index in (0..MerkleTreeConfiguration::FOREST_WIDTH) {
            membership_proof_data.push(
                utxo_merkle_forest
                    .forest
                    .get(index as u8)
                    .current_path()
                    .clone()
                    .into(),
            )
        }
        ReadResponse {
            should_continue: false,
            data: InitialSyncData {
                utxo_data: utxos,
                nullifier_data: senders,
                membership_proof_data,
            },
        }
    }

    ///
    #[inline]
    pub fn utxos(&self) -> &HashSet<Utxo> {
        &self.utxos
    }
}

/// Sender Ledger Error
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SenderLedgerError {
    /// Invalid UTXO Accumulator Output Error
    ///
    /// The sender was not constructed under the current state of the UTXO accumulator.
    InvalidUtxoAccumulatorOutput,

    /// Asset Spent Error
    ///
    /// The asset has already been spent.
    AssetSpent,

    /// Unexpected Error
    UnexpectedError,
}

impl From<SenderLedgerError> for SenderPostError<SenderLedgerError> {
    #[inline]
    fn from(value: SenderLedgerError) -> Self {
        match value {
            SenderLedgerError::AssetSpent => Self::AssetSpent,
            SenderLedgerError::InvalidUtxoAccumulatorOutput => Self::InvalidUtxoAccumulatorOutput,
            SenderLedgerError::UnexpectedError => {
                Self::UnexpectedError(SenderLedgerError::UnexpectedError)
            }
        }
    }
}

/// Receiver Ledger Error
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReceiverLedgerError {
    /// Asset Registered Error
    ///
    /// The asset has already been registered with the ledger.
    AssetRegistered,

    /// Unexpected Error
    UnexpectedError,
}

impl From<ReceiverLedgerError> for ReceiverPostError<ReceiverLedgerError> {
    #[inline]
    fn from(value: ReceiverLedgerError) -> Self {
        match value {
            ReceiverLedgerError::AssetRegistered => Self::AssetRegistered,
            ReceiverLedgerError::UnexpectedError => {
                Self::UnexpectedError(ReceiverLedgerError::UnexpectedError)
            }
        }
    }
}

/// Transfer Ledger Error
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TransferLedgerError {
    /// Invalid Transfer Post Shape
    InvalidShape,

    /// Invalid Authorization Signature
    ///
    /// The authorization signature for the [`TransferPost`] was not valid.
    InvalidAuthorizationSignature(InvalidAuthorizationSignature),

    /// Invalid Source Accounts
    InvalidSourceAccount(InvalidSourceAccount<Config, AccountId>),

    /// Invalid Sink Accounts
    InvalidSinkAccount(InvalidSinkAccount<Config, AccountId>),

    /// Sender Ledger Error
    Sender(SenderLedgerError),

    /// Receiver Ledger Error
    Receiver(ReceiverLedgerError),

    /// Duplicate Spend Error
    DuplicateSpend,

    /// Duplicate Mint Error
    DuplicateMint,

    /// Invalid Transfer Proof Error
    ///
    /// Validity of the transfer could not be proved by the ledger.
    InvalidProof,

    /// Unexpected Error
    ///
    /// An unexpected error occured.
    UnexpectedError,
}

impl From<TransferLedgerError>
    for TransferPostError<
        Config,
        AccountId,
        SenderLedgerError,
        ReceiverLedgerError,
        TransferLedgerError,
    >
{
    #[inline]
    fn from(value: TransferLedgerError) -> Self {
        match value {
            TransferLedgerError::InvalidShape => Self::InvalidShape,
            TransferLedgerError::InvalidAuthorizationSignature(err) => {
                Self::InvalidAuthorizationSignature(err)
            }
            TransferLedgerError::InvalidSourceAccount(err) => Self::InvalidSourceAccount(err),
            TransferLedgerError::InvalidSinkAccount(err) => Self::InvalidSinkAccount(err),
            TransferLedgerError::Sender(err) => Self::Sender(err.into()),
            TransferLedgerError::Receiver(err) => Self::Receiver(err.into()),
            TransferLedgerError::DuplicateSpend => Self::DuplicateSpend,
            TransferLedgerError::DuplicateMint => Self::DuplicateMint,
            TransferLedgerError::InvalidProof => Self::InvalidProof,
            TransferLedgerError::UnexpectedError => {
                Self::UnexpectedError(TransferLedgerError::UnexpectedError)
            }
        }
    }
}

impl From<ReceiverLedgerError> for TransferLedgerError {
    #[inline]
    fn from(value: ReceiverLedgerError) -> Self {
        Self::Receiver(value)
    }
}

impl From<SenderLedgerError> for TransferLedgerError {
    #[inline]
    fn from(value: SenderLedgerError) -> Self {
        Self::Sender(value)
    }
}

impl SenderLedger<Parameters> for Ledger {
    type ValidNullifier = Wrap<Nullifier>;
    type ValidUtxoAccumulatorOutput = Wrap<UtxoAccumulatorOutput<Config>>;
    type SuperPostingKey = (Wrap<()>, ());
    type Error = SenderLedgerError;

    #[inline]
    fn is_unspent(&self, nullifier: Nullifier) -> Result<Self::ValidNullifier, Self::Error> {
        if self.nullifiers.contains(&nullifier) {
            Err(SenderLedgerError::AssetSpent)
        } else {
            Ok(Wrap(nullifier))
        }
    }

    #[inline]
    fn has_matching_utxo_accumulator_output(
        &self,
        output: UtxoAccumulatorOutput<Config>,
    ) -> Result<Self::ValidUtxoAccumulatorOutput, Self::Error> {
        if output == Default::default() {
            return Ok(Wrap(output));
        }
        for tree in self.utxo_forest.forest.as_ref() {
            if tree.root() == &output {
                return Ok(Wrap(output));
            }
        }
        Err(SenderLedgerError::InvalidUtxoAccumulatorOutput)
    }

    #[inline]
    fn spend(
        &mut self,
        super_key: &Self::SuperPostingKey,
        utxo_accumulator_output: Self::ValidUtxoAccumulatorOutput,
        nullifier: Self::ValidNullifier,
    ) -> Result<(), Self::Error> {
        let _ = (utxo_accumulator_output, super_key);
        self.nullifiers.insert(nullifier.0);
        Ok(())
    }
}

impl ReceiverLedger<Parameters> for Ledger {
    type ValidUtxo = Wrap<Utxo>;
    type SuperPostingKey = (Wrap<()>, ());
    type Error = ReceiverLedgerError;

    #[inline]
    fn is_not_registered(&self, utxo: Utxo) -> Result<Self::ValidUtxo, Self::Error> {
        if self.utxos.contains(&utxo) {
            Err(ReceiverLedgerError::AssetRegistered)
        } else {
            Ok(Wrap(utxo))
        }
    }

    #[inline]
    fn register(
        &mut self,
        super_key: &Self::SuperPostingKey,
        utxo: Self::ValidUtxo,
        note: FullIncomingNote,
    ) -> Result<(), Self::Error> {
        let _ = super_key;
        let utxo_hash = self.parameters.item_hash(&utxo.0, &mut ());
        self.shards
            .get_mut(&MerkleTreeConfiguration::tree_index(&utxo_hash))
            .ok_or(ReceiverLedgerError::UnexpectedError)?
            .insert((utxo.0, note));
        self.utxos.insert(utxo.0);
        self.utxo_forest.push(&utxo_hash);
        Ok(())
    }
}

impl TransferLedger<Config> for Ledger {
    type Event = ();
    type ValidSourceAccount = WrapPair<AccountId, AssetValue>;
    type ValidSinkAccount = WrapPair<AccountId, AssetValue>;
    type ValidProof = Wrap<()>;
    type SuperPostingKey = ();
    type Error = TransferLedgerError;

    #[inline]
    fn check_source_accounts<I>(
        &self,
        asset_id: &AssetId,
        sources: I,
    ) -> Result<Vec<Self::ValidSourceAccount>, InvalidSourceAccount<Config, AccountId>>
    where
        I: Iterator<Item = (AccountId, AssetValue)>,
    {
        sources
            .map(|(account_id, withdraw)| {
                match self.accounts.get(&account_id) {
                    Some(map) => match map.get(asset_id) {
                        Some(balance) => {
                            if balance >= &withdraw {
                                Ok(WrapPair(account_id, withdraw))
                            } else {
                                Err(InvalidSourceAccount {
                                    account_id,
                                    asset_id: *asset_id,
                                    withdraw,
                                })
                            }
                        }
                        _ => {
                            // FIXME: What about zero values in `sources`?
                            Err(InvalidSourceAccount {
                                account_id,
                                asset_id: *asset_id,
                                withdraw,
                            })
                        }
                    },
                    _ => Err(InvalidSourceAccount {
                        account_id,
                        asset_id: *asset_id,
                        withdraw,
                    }),
                }
            })
            .collect()
    }

    #[inline]
    fn check_sink_accounts<I>(
        &self,
        asset_id: &AssetId,
        sinks: I,
    ) -> Result<Vec<Self::ValidSinkAccount>, InvalidSinkAccount<Config, AccountId>>
    where
        I: Iterator<Item = (AccountId, AssetValue)>,
    {
        sinks
            .map(move |(account_id, deposit)| {
                if self.accounts.contains_key(&account_id) {
                    Ok(WrapPair(account_id, deposit))
                } else {
                    Err(InvalidSinkAccount {
                        account_id,
                        asset_id: *asset_id,
                        deposit,
                    })
                }
            })
            .collect()
    }

    #[inline]
    fn is_valid(
        &self,
        posting_key: TransferPostingKeyRef<Config, Self>,
    ) -> Result<(Self::ValidProof, Self::Event), <Self as TransferLedger<Config>>::Error> {
        let transfershape = TransferShape::select(
            posting_key.authorization_key.is_some(),
            posting_key.asset_id.is_some(),
            posting_key.sources.len(),
            posting_key.senders.len(),
            posting_key.receivers.len(),
            posting_key.sinks.len(),
        );
        if transfershape.is_none() {
            return Err(TransferLedgerError::InvalidShape);
        }
        let verifying_context = self
            .verifying_context
            .select(transfershape.expect("This never fails because of the check above."));
        ProofSystem::verify(
            verifying_context,
            &posting_key.generate_proof_input(),
            &posting_key.proof,
        )
        .map_err(|_| TransferLedgerError::InvalidProof)?;
        Ok((Wrap(()), ()))
    }

    #[inline]
    fn update_public_balances(
        &mut self,
        super_key: &TransferLedgerSuperPostingKey<Config, Self>,
        asset_id: AssetId,
        sources: Vec<SourcePostingKey<Config, Self>>,
        sinks: Vec<SinkPostingKey<Config, Self>>,
        proof: Self::ValidProof,
    ) -> Result<(), <Self as TransferLedger<Config>>::Error> {
        let _ = (proof, super_key);
        for WrapPair(account_id, withdraw) in sources {
            *self
                .accounts
                .get_mut(&account_id)
                .ok_or(TransferLedgerError::InvalidSourceAccount(
                    InvalidSourceAccount {
                        account_id,
                        asset_id,
                        withdraw,
                    },
                ))?
                .get_mut(&asset_id)
                .ok_or(TransferLedgerError::InvalidSourceAccount(
                    InvalidSourceAccount {
                        account_id,
                        asset_id,
                        withdraw,
                    },
                ))? -= withdraw;
        }
        for WrapPair(account_id, deposit) in sinks {
            *self
                .accounts
                .get_mut(&account_id)
                .ok_or(TransferLedgerError::InvalidSinkAccount(
                    InvalidSinkAccount {
                        account_id,
                        asset_id,
                        deposit,
                    },
                ))?
                .entry(asset_id)
                .or_default() += deposit;
        }
        Ok(())
    }
}

/// Shared Ledger
pub type SharedLedger = Arc<RwLock<Ledger>>;

/// Ledger Connection
#[derive(Clone, Debug)]
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

impl ledger::Connection for LedgerConnection {
    type Error = Infallible;
}

impl ledger::Read<SyncData<Config>> for LedgerConnection {
    type Checkpoint = Checkpoint;

    #[inline]
    fn read<'s>(
        &'s mut self,
        checkpoint: &'s Self::Checkpoint,
    ) -> LocalBoxFutureResult<'s, ReadResponse<SyncData<Config>>, Self::Error> {
        Box::pin(async move { Ok(self.ledger.read().await.pull(checkpoint)) })
    }
}

impl ledger::Read<InitialSyncData> for LedgerConnection {
    type Checkpoint = Checkpoint;

    #[inline]
    fn read<'s>(
        &'s mut self,
        checkpoint: &'s Self::Checkpoint,
    ) -> LocalBoxFutureResult<'s, ReadResponse<InitialSyncData>, Self::Error> {
        let _ = checkpoint;
        Box::pin(async move { Ok(self.ledger.read().await.initial_read()) })
    }
}

impl ledger::Write<Vec<TransferPost>> for LedgerConnection {
    type Response = bool;

    #[inline]
    fn write(
        &mut self,
        posts: Vec<TransferPost>,
    ) -> LocalBoxFutureResult<Self::Response, Self::Error> {
        Box::pin(async move { Ok(self.ledger.write().await.push(self.account, posts)) })
    }
}

impl PublicBalanceOracle<Config> for LedgerConnection {
    #[inline]
    fn public_balances(&self) -> LocalBoxFuture<Option<AssetList<AssetId, AssetValue>>> {
        Box::pin(async move { self.ledger.read().await.public_balances(self.account) })
    }
}
