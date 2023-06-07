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

//! Wallet Signer

// TODO:  Should have a mode on the signer where we return a generic error which reveals no detail
//        about what went wrong during signing. The kind of error returned from a signing could
//        reveal information about the internal state (privacy leak, not a secrecy leak).
// TODO:  Move `sync` to a streaming algorithm.
// TODO:  Add self-destruct feature for clearing all secret and private data.
// TODO:  Compress the `BalanceUpdate` data before sending (improves privacy and bandwidth).
// TODO:  Improve asynchronous interfaces internally in the signer, instead of just blocking
//        internally.

use crate::{
    asset::{self, AssetMap},
    key::{self, Account, AccountCollection, DeriveAddresses},
    transfer::{
        self,
        canonical::{MultiProvingContext, Transaction, TransactionData},
        Address, Asset, AuthorizationContext, IdentifiedAsset, Identifier, IdentityProof, Note,
        Nullifier, Parameters, ProofSystemError, SpendingKey, TransferPost, Utxo,
        UtxoAccumulatorItem, UtxoAccumulatorModel, UtxoAccumulatorWitness, UtxoMembershipProof,
    },
    wallet::ledger::{self, Data},
};
use alloc::{boxed::Box, vec::Vec};
use core::{convert::Infallible, fmt::Debug, hash::Hash};
use manta_crypto::{
    accumulator::{
        Accumulator, BatchInsertion, ExactSizeAccumulator, FromItemsAndWitnesses, ItemHashFunction,
        OptimizedAccumulator,
    },
    rand::{CryptoRng, FromEntropy, RngCore},
};
use manta_util::{
    future::LocalBoxFutureResult,
    num::{CheckedAdd, CheckedSub},
    persistence::Rollback,
};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

pub mod functions;
pub mod nullifier_map;

/// Signer Connection
pub trait Connection<C>
where
    C: transfer::Configuration,
{
    /// Asset Metadata Type
    type AssetMetadata;

    /// Checkpoint Type
    ///
    /// This checkpoint is used by the signer to stay synchronized with wallet and the ledger.
    type Checkpoint: ledger::Checkpoint;

    /// Error Type
    ///
    /// This is the error type for the connection itself, not for an error produced during one of
    /// the signer methods.
    type Error;

    /// Pushes updates from the ledger to the wallet, synchronizing it with the ledger state and
    /// returning an updated asset distribution.
    fn sync(
        &mut self,
        request: SyncRequest<C, Self::Checkpoint>,
    ) -> LocalBoxFutureResult<SyncResult<C, Self::Checkpoint>, Self::Error>;

    /// Pushes updates from the ledger to the wallet, synchronizing it with the ledger state and
    /// returning an updated asset distribution.
    ///
    /// # Implementation Note
    ///
    /// Implementations of this method must return the same updated asset distribution and the same
    /// balance update as [`sync`](Connection::sync). However, they do not have to update the [`Utxo`]
    /// accumulator, thus making the new assets effectively non-spendable. Therefore, this method should
    /// only be used when the pallet does not allow [`PrivateTransfer`]s or [`ToPublic`] transactions,
    /// for example in the case of a pallet for Soul-Bound Tokens (SBTs).
    ///
    /// [`PrivateTransfer`]: transfer::canonical::PrivateTransfer
    /// [`ToPublic`]: transfer::canonical::ToPublic
    fn sbt_sync(
        &mut self,
        request: SyncRequest<C, Self::Checkpoint>,
    ) -> LocalBoxFutureResult<SyncResult<C, Self::Checkpoint>, Self::Error>;

    /// Performs the initial synchronization of a new signer with the ledger data.
    ///
    /// # Implementation Note
    ///
    /// Using this method to synchronize a signer will make it impossibile to spend any
    /// [`Utxo`](crate::transfer::Utxo)s already on the ledger at the time of synchronization.
    /// Therefore, this method should only be used for the initial synchronization of a
    /// new signer.
    fn initial_sync(
        &mut self,
        request: InitialSyncRequest<C>,
    ) -> LocalBoxFutureResult<SyncResult<C, Self::Checkpoint>, Self::Error>;

    /// Signs a transaction and returns the ledger transfer posts if successful.
    fn sign(
        &mut self,
        request: SignRequest<Self::AssetMetadata, C>,
    ) -> LocalBoxFutureResult<SignResult<C>, Self::Error>;

    /// Returns the [`Address`] corresponding to `self`.
    fn address(&mut self) -> LocalBoxFutureResult<Option<Address<C>>, Self::Error>;

    /// Returns the [`TransactionData`] of the [`TransferPost`]s in `request` owned by `self`.
    fn transaction_data(
        &mut self,
        request: TransactionDataRequest<C>,
    ) -> LocalBoxFutureResult<TransactionDataResponse<C>, Self::Error>;

    /// Generates an [`IdentityProof`] which can be verified against the [`IdentifiedAsset`]s in
    /// `request`.
    fn identity_proof(
        &mut self,
        request: IdentityRequest<C>,
    ) -> LocalBoxFutureResult<IdentityResponse<C>, Self::Error>;

    /// Signs a transaction and returns the ledger transfer posts and the
    /// associated [`TransactionData`] if successful.
    fn sign_with_transaction_data(
        &mut self,
        request: SignRequest<Self::AssetMetadata, C>,
    ) -> LocalBoxFutureResult<SignWithTransactionDataResult<C>, Self::Error>
    where
        TransferPost<C>: Clone;

    /// Returns the transfer [`Parameters`] corresponding to `self`.
    fn transfer_parameters(&mut self) -> LocalBoxFutureResult<Parameters<C>, Self::Error>;

    ///
    fn consolidate(
        &mut self,
        request: ConsolidationPrerequest<C>,
    ) -> LocalBoxFutureResult<SignResult<C>, Self::Error>;
}

/// Signer Initial Synchronization Data
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = r"
                Utxo<C>: Deserialize<'de>,
                UtxoAccumulatorWitness<C>: Deserialize<'de>,
                Nullifier<C>: Deserialize<'de>,
            ",
            serialize = r"
                Utxo<C>: Serialize,
                UtxoAccumulatorWitness<C>: Serialize,
                Nullifier<C>: Serialize,
            ",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "Utxo<C>: Clone, UtxoAccumulatorWitness<C>: Clone, Nullifier<C>: Clone"),
    Debug(bound = "Utxo<C>: Debug, UtxoAccumulatorWitness<C>: Debug, Nullifier<C>: Debug"),
    Eq(bound = "Utxo<C>: Eq, UtxoAccumulatorWitness<C>: Eq, Nullifier<C>: Eq"),
    Hash(bound = "Utxo<C>: Hash, UtxoAccumulatorWitness<C>: Hash, Nullifier<C>: Hash"),
    PartialEq(
        bound = "Utxo<C>: PartialEq, UtxoAccumulatorWitness<C>: PartialEq, Nullifier<C>: PartialEq"
    )
)]
pub struct InitialSyncData<C>
where
    C: transfer::Configuration + ?Sized,
{
    /// UTXO Data
    pub utxo_data: Vec<Utxo<C>>,

    /// Membership Proof Data
    ///
    /// # Note
    ///
    /// Each [`UtxoAccumulatorWitness`] here is the membership proof of the last item
    /// of each subaccumulator in the [`UtxoAccumulator`](Configuration::UtxoAccumulator).
    pub membership_proof_data: Vec<UtxoAccumulatorWitness<C>>,

    /// Nullifier Count
    pub nullifier_count: u128,
}

/// Signer Initial Synchronization Request
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = r"
                UtxoAccumulatorItem<C>: Deserialize<'de>,
                UtxoAccumulatorWitness<C>: Deserialize<'de>,
                Nullifier<C>: Deserialize<'de>,
            ",
            serialize = r"
                UtxoAccumulatorItem<C>: Serialize,
                UtxoAccumulatorWitness<C>: Serialize,
                Nullifier<C>: Serialize,
            ",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(
        bound = "UtxoAccumulatorItem<C>: Clone, UtxoAccumulatorWitness<C>: Clone, Nullifier<C>: Clone"
    ),
    Debug(
        bound = "UtxoAccumulatorItem<C>: Debug, UtxoAccumulatorWitness<C>: Debug, Nullifier<C>: Debug"
    ),
    Eq(bound = "UtxoAccumulatorItem<C>: Eq, UtxoAccumulatorWitness<C>: Eq, Nullifier<C>: Eq"),
    Hash(
        bound = "UtxoAccumulatorItem<C>: Hash, UtxoAccumulatorWitness<C>: Hash, Nullifier<C>: Hash"
    ),
    PartialEq(
        bound = "UtxoAccumulatorItem<C>: PartialEq, UtxoAccumulatorWitness<C>: PartialEq, Nullifier<C>: PartialEq"
    )
)]
pub struct InitialSyncRequest<C>
where
    C: transfer::Configuration + ?Sized,
{
    /// UTXO Data
    pub utxo_data: Vec<Vec<UtxoAccumulatorItem<C>>>,

    /// Membership Proof Data
    ///
    /// # Note
    ///
    /// Each [`UtxoAccumulatorWitness`] here is the membership proof of the last item
    /// of each subaccumulator in the [`UtxoAccumulator`](Configuration::UtxoAccumulator).
    pub membership_proof_data: Vec<UtxoAccumulatorWitness<C>>,

    /// Nullifier Count
    pub nullifier_count: u128,
}

impl<C> InitialSyncRequest<C>
where
    C: Configuration,
{
    /// Builds a new [`InitialSyncRequest`] from `parameters` and `data`.
    #[inline]
    pub fn from_initial_sync_data(parameters: &Parameters<C>, data: InitialSyncData<C>) -> Self {
        Self {
            utxo_data: C::UtxoAccumulator::sort_items(
                data.utxo_data
                    .iter()
                    .map(|utxo| functions::item_hash::<C>(parameters, utxo))
                    .collect(),
            ),
            membership_proof_data: data.membership_proof_data,
            nullifier_count: data.nullifier_count,
        }
    }

    /// Extends `self` with `request`.
    #[inline]
    pub fn extend(&mut self, request: InitialSyncRequest<C>) {
        for (old_vector, new_vector) in self.utxo_data.iter_mut().zip(request.utxo_data.into_iter())
        {
            old_vector.extend(new_vector)
        }
        self.membership_proof_data = request.membership_proof_data;
        self.nullifier_count = request.nullifier_count;
    }

    /// Extends `self` with `parameters` and `data`.
    #[inline]
    pub fn extend_with_data(&mut self, parameters: &Parameters<C>, data: InitialSyncData<C>) {
        let new_request = Self::from_initial_sync_data(parameters, data);
        self.extend(new_request);
    }
}

impl<C> Default for InitialSyncRequest<C>
where
    C: Configuration,
{
    #[inline]
    fn default() -> Self {
        let mut utxo_data = Vec::<Vec<_>>::default();
        let mut membership_proof_data = Vec::new();
        utxo_data.resize_with(
            C::UtxoAccumulator::NUMBER_OF_SUBACCUMULATORS,
            Default::default,
        );
        membership_proof_data.resize_with(
            C::UtxoAccumulator::NUMBER_OF_SUBACCUMULATORS,
            Default::default,
        );
        Self {
            utxo_data,
            membership_proof_data,
            nullifier_count: Default::default(),
        }
    }
}

/// Signer Synchronization Data
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = r"
                Utxo<C>: Deserialize<'de>,
                Note<C>: Deserialize<'de>,
                Nullifier<C>: Deserialize<'de>
            ",
            serialize = r"
                Utxo<C>: Serialize,
                Note<C>: Serialize,
                Nullifier<C>: Serialize
            ",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "Utxo<C>: Clone, Note<C>: Clone, Nullifier<C>: Clone"),
    Debug(bound = "Utxo<C>: Debug, Note<C>: Debug, Nullifier<C>: Debug"),
    Default(bound = ""),
    Eq(bound = "Utxo<C>: Eq, Note<C>: Eq, Nullifier<C>: Eq"),
    Hash(bound = "Utxo<C>: Hash, Note<C>: Hash, Nullifier<C>: Hash"),
    PartialEq(bound = "Utxo<C>: PartialEq, Note<C>: PartialEq, Nullifier<C>: PartialEq")
)]
pub struct SyncData<C>
where
    C: transfer::Configuration + ?Sized,
{
    /// UTXO-Note Data
    pub utxo_note_data: Vec<(Utxo<C>, Note<C>)>,

    /// Nullifier Data
    pub nullifier_data: Vec<Nullifier<C>>,
}

impl<C> Data<C::Checkpoint> for SyncData<C>
where
    C: Configuration + ?Sized,
{
    type Parameters = C::UtxoAccumulatorItemHash;

    #[inline]
    fn prune(
        &mut self,
        parameters: &Self::Parameters,
        origin: &C::Checkpoint,
        checkpoint: &C::Checkpoint,
    ) -> bool {
        C::Checkpoint::prune(parameters, self, origin, checkpoint)
    }
}

/// Signer Synchronization Request
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "T: Deserialize<'de>, SyncData<C>: Deserialize<'de>",
            serialize = "T: Serialize, SyncData<C>: Serialize",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "T: Clone, SyncData<C>: Clone"),
    Debug(bound = "T: Debug, SyncData<C>: Debug"),
    Default(bound = "T: Default, SyncData<C>: Default"),
    Eq(bound = "T: Eq, SyncData<C>: Eq"),
    Hash(bound = "T: Hash, SyncData<C>: Hash"),
    PartialEq(bound = "T: PartialEq, SyncData<C>: PartialEq")
)]
pub struct SyncRequest<C, T>
where
    C: transfer::Configuration,
    T: ledger::Checkpoint,
{
    /// Origin Checkpoint
    ///
    /// This checkpoint was the one that was used to retrieve the [`data`](Self::data) from the
    /// ledger.
    pub origin_checkpoint: T,

    /// Ledger Synchronization Data
    pub data: SyncData<C>,
}

impl<C, T> SyncRequest<C, T>
where
    C: transfer::Configuration,
    T: ledger::Checkpoint,
{
    /// Prunes the [`data`] in `self` according to the target `checkpoint` given that
    /// [`origin_checkpoint`] was the origin of the data.
    ///
    /// [`data`]: Self::data
    /// [`origin_checkpoint`]: Self::origin_checkpoint
    #[inline]
    pub fn prune(
        &mut self,
        parameters: &<SyncData<C> as Data<T>>::Parameters,
        checkpoint: &T,
    ) -> bool
    where
        SyncData<C>: Data<T>,
    {
        self.data
            .prune(parameters, &self.origin_checkpoint, checkpoint)
    }

    /// Returns the [`Utxo`] count of `self`.
    #[inline]
    pub fn utxo_count(&self, parameters: &Parameters<C>) -> Vec<usize>
    where
        C: Configuration,
    {
        C::UtxoAccumulator::sort_items(
            self.data
                .utxo_note_data
                .iter()
                .map(|(utxo, _)| functions::item_hash::<C>(parameters, utxo))
                .collect(),
        )
        .into_iter()
        .map(|utxos| utxos.len())
        .collect()
    }
}

/// Signer Synchronization Response
///
/// This `struct` is created by the [`sync`](Connection::sync) method on [`Connection`].
/// See its documentation for more.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "T: Deserialize<'de>, BalanceUpdate<C>: Deserialize<'de>",
            serialize = "T: Serialize, BalanceUpdate<C>: Serialize",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "T: Clone, BalanceUpdate<C>: Clone"),
    Copy(bound = "T: Copy, BalanceUpdate<C>: Copy"),
    Debug(bound = "T: Debug, BalanceUpdate<C>: Debug"),
    Default(bound = "T: Default, BalanceUpdate<C>: Default"),
    Eq(bound = "T: Eq, BalanceUpdate<C>: Eq"),
    Hash(bound = "T: Hash, BalanceUpdate<C>: Hash"),
    PartialEq(bound = "T: PartialEq, BalanceUpdate<C>: PartialEq")
)]
pub struct SyncResponse<C, T>
where
    C: transfer::Configuration,
    T: ledger::Checkpoint,
{
    /// Checkpoint
    pub checkpoint: T,

    /// Balance Update
    pub balance_update: BalanceUpdate<C>,
}

/// Transaction Data Request
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "TransferPost<C>: Deserialize<'de>",
            serialize = "TransferPost<C>: Serialize",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "TransferPost<C>: Clone"),
    Debug(bound = "TransferPost<C>: Debug"),
    Default(bound = "TransferPost<C>: Default"),
    Eq(bound = "TransferPost<C>: Eq"),
    Hash(bound = "TransferPost<C>: Hash"),
    PartialEq(bound = "TransferPost<C>: PartialEq")
)]
pub struct TransactionDataRequest<C>(pub Vec<TransferPost<C>>)
where
    C: transfer::Configuration;

/// Transaction Data Response
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "TransactionData<C>: Deserialize<'de>",
            serialize = "TransactionData<C>: Serialize",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "TransactionData<C>: Clone"),
    Debug(bound = "TransactionData<C>: Debug"),
    Default(bound = "TransactionData<C>: Default"),
    Eq(bound = "TransactionData<C>: Eq"),
    Hash(bound = "TransactionData<C>: Hash"),
    PartialEq(bound = "TransactionData<C>: PartialEq")
)]
pub struct TransactionDataResponse<C>(pub Vec<Option<TransactionData<C>>>)
where
    C: transfer::Configuration;

/// Sign with Transaction Data Response
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "TransferPost<C>: Deserialize<'de>, TransactionData<C>: Deserialize<'de>",
            serialize = "TransferPost<C>: Serialize, TransactionData<C>: Serialize",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "TransferPost<C>: Clone, TransactionData<C>: Clone"),
    Debug(bound = "TransferPost<C>: Debug, TransactionData<C>: Debug"),
    Eq(bound = "TransferPost<C>: Eq, TransactionData<C>: Eq"),
    Hash(bound = "TransferPost<C>: Hash, TransactionData<C>: Hash"),
    PartialEq(bound = "TransferPost<C>: PartialEq, TransactionData<C>: PartialEq")
)]
pub struct SignWithTransactionDataResponse<C>(pub Vec<(TransferPost<C>, TransactionData<C>)>)
where
    C: transfer::Configuration;

/// Balance Update
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "Asset<C>: Deserialize<'de>",
            serialize = "Asset<C>: Serialize",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "Asset<C>: Clone"),
    Debug(bound = "Asset<C>: Debug"),
    Eq(bound = "Asset<C>: Eq"),
    Hash(bound = "Asset<C>: Hash"),
    PartialEq(bound = "Asset<C>: PartialEq")
)]
pub enum BalanceUpdate<C>
where
    C: transfer::Configuration,
{
    /// Partial Update
    ///
    /// This is the typical response from the [`Signer`]. In rare de-synchronization cases, we may
    /// need to perform a [`Full`](Self::Full) update.
    Partial {
        /// Assets Deposited in the Last Update
        deposit: Vec<Asset<C>>,

        /// Assets Withdrawn in the Last Update
        withdraw: Vec<Asset<C>>,
    },

    /// Full Update
    ///
    /// Whenever the [`Signer`] gets ahead of the synchronization point, it would have updated its
    /// internal balance state further along than any connection following its updates. In this
    /// case, the entire balance state needs to be sent to catch up.
    Full {
        /// Full Balance State
        assets: Vec<Asset<C>>,
    },
}

/// Signer Synchronization Error
///
/// This `enum` is the error state for the [`sync`](Connection::sync) method on [`Connection`].
/// See its documentation for more.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SyncError<T>
where
    T: ledger::Checkpoint,
{
    /// Inconsistent Synchronization
    ///
    /// This error occurs whenever the signer checkpoint gets behind the wallet checkpoint and
    /// cannot safely process the incoming data. The data is dropped and the signer checkpoint is
    /// sent back up to the wallet. If the wallet determines that it can safely re-synchronize with
    /// this older checkpoint then it will try again and fetch older data from the ledger.
    InconsistentSynchronization {
        /// Signer Checkpoint
        checkpoint: T,
    },

    /// Missing Proof Authorization Key
    MissingProofAuthorizationKey,

    /// Inconsistent Balance
    InconsistentBalance,
}

/// Synchronization Result
pub type SyncResult<C, T> = Result<SyncResponse<C, T>, SyncError<T>>;

/// Signer Signing Request
///
/// This `struct` is used by the [`sign`](Connection::sign) method on [`Connection`].
/// See its documentation for more.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "Transaction<C>: Deserialize<'de>, A: Deserialize<'de>",
            serialize = "Transaction<C>: Serialize, A: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "Transaction<C>: Clone, A: Clone"),
    Debug(bound = "Transaction<C>: Debug, A: Debug"),
    Eq(bound = "Transaction<C>: Eq, A: Eq"),
    Hash(bound = "Transaction<C>: Hash, A: Hash"),
    PartialEq(bound = "Transaction<C>: PartialEq, A: PartialEq")
)]
pub struct SignRequest<A, C>
where
    C: transfer::Configuration,
{
    /// Transaction Data
    pub transaction: Transaction<C>,

    /// Asset Metadata
    pub metadata: Option<A>,
}

/// Signer Signing Response
///
/// This `struct` is created by the [`sign`](Connection::sign) method on [`Connection`].
/// See its documentation for more.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "TransferPost<C>: Deserialize<'de>",
            serialize = "TransferPost<C>: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "TransferPost<C>: Clone"),
    Debug(bound = "TransferPost<C>: Debug"),
    Eq(bound = "TransferPost<C>: Eq"),
    Hash(bound = "TransferPost<C>: Hash"),
    PartialEq(bound = "TransferPost<C>: PartialEq")
)]
pub struct SignResponse<C>
where
    C: transfer::Configuration,
{
    /// Transfer Posts
    pub posts: Vec<TransferPost<C>>,
}

/// Identity Request
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = r"Asset<C>: Deserialize<'de>, 
                Identifier<C>: Deserialize<'de>, 
                C::AccountId: Deserialize<'de>",
            serialize = r"Asset<C>: Serialize, 
                Identifier<C>: Serialize, 
                C::AccountId: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "Asset<C>: Clone, Identifier<C>: Clone, C::AccountId: Clone"),
    Debug(bound = "Asset<C>: Debug, Identifier<C>: Debug, C::AccountId: Debug"),
    Eq(bound = "Asset<C>: Eq, Identifier<C>: Eq, C::AccountId: Eq"),
    Hash(bound = "Asset<C>: Hash, Identifier<C>: Hash, C::AccountId: Hash"),
    PartialEq(bound = "Asset<C>: PartialEq, Identifier<C>: PartialEq, C::AccountId: PartialEq")
)]
pub struct IdentityRequest<C>(pub Vec<(IdentifiedAsset<C>, C::AccountId)>)
where
    C: transfer::Configuration;

/// Identity Response
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "TransferPost<C>: Deserialize<'de>, UtxoMembershipProof<C>: Deserialize<'de>",
            serialize = "TransferPost<C>: Serialize, UtxoMembershipProof<C>: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "TransferPost<C>: Clone, UtxoMembershipProof<C>: Clone"),
    Debug(bound = "TransferPost<C>: Debug, UtxoMembershipProof<C>: Debug"),
    Eq(bound = "TransferPost<C>: Eq, UtxoMembershipProof<C>: Eq"),
    Hash(bound = "TransferPost<C>: Hash, UtxoMembershipProof<C>: Hash"),
    PartialEq(bound = "TransferPost<C>: PartialEq, UtxoMembershipProof<C>: PartialEq")
)]
pub struct IdentityResponse<C>(pub Vec<Option<IdentityProof<C>>>)
where
    C: transfer::Configuration;

impl<C> IdentityResponse<C>
where
    C: transfer::Configuration,
{
    /// Builds a new [`IdentityResponse`] from a vector of [`IdentityProof`]s.
    pub fn new(identity_proofs: Vec<Option<IdentityProof<C>>>) -> Self {
        Self(identity_proofs)
    }
}

impl<C> SignResponse<C>
where
    C: transfer::Configuration,
{
    /// Builds a new [`SignResponse`] from `posts`.
    #[inline]
    pub fn new(posts: Vec<TransferPost<C>>) -> Self {
        Self { posts }
    }
}

/// Signer Signing Error
///
/// This `enum` is the error state for the [`sign`](Connection::sign) method on [`Connection`].
/// See its documentation for more.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "Asset<C>: Deserialize<'de>, ProofSystemError<C>: Deserialize<'de>",
            serialize = "Asset<C>: Serialize, ProofSystemError<C>: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "Asset<C>: Clone, ProofSystemError<C>: Clone"),
    Copy(bound = "Asset<C>: Copy, ProofSystemError<C>: Copy"),
    Debug(bound = "Asset<C>: Debug, ProofSystemError<C>: Debug"),
    Eq(bound = "Asset<C>: Eq, ProofSystemError<C>: Eq"),
    Hash(bound = "Asset<C>: Hash, ProofSystemError<C>: Hash"),
    PartialEq(bound = "Asset<C>: PartialEq, ProofSystemError<C>: PartialEq")
)]
pub enum SignError<C>
where
    C: transfer::Configuration,
{
    /// Insufficient Balance
    InsufficientBalance(Asset<C>),

    /// Proof System Error
    ProofSystemError(ProofSystemError<C>),

    /// Missing Spending Key
    MissingSpendingKey,

    /// Missing Proof Authorization Key
    MissingProofAuthorizationKey,

    /// Invalid Consolidation Request
    InvalidConsolidationRequest,
}

/// Asset List Response
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = r"Asset<C>: Deserialize<'de>, 
                Identifier<C>: Deserialize<'de>",
            serialize = r"Asset<C>: Serialize, 
                Identifier<C>: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "Asset<C>: Clone, Identifier<C>: Clone"),
    Debug(bound = "Asset<C>: Debug, Identifier<C>: Debug"),
    Eq(bound = "Asset<C>: Eq, Identifier<C>: Eq"),
    Hash(bound = "Asset<C>: Hash, Identifier<C>: Hash"),
    PartialEq(bound = "Asset<C>: PartialEq, Identifier<C>: PartialEq")
)]
pub struct AssetListResponse<C>(pub Vec<IdentifiedAsset<C>>)
where
    C: transfer::Configuration + ?Sized;

/// Consolidation prerequest
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = r"Asset<C>: Deserialize<'de>, 
                Identifier<C>: Deserialize<'de>",
            serialize = r"Asset<C>: Serialize, 
                Identifier<C>: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "Asset<C>: Clone, Identifier<C>: Clone"),
    Debug(bound = "Asset<C>: Debug, Identifier<C>: Debug"),
    Eq(bound = "Asset<C>: Eq, Identifier<C>: Eq"),
    Hash(bound = "Asset<C>: Hash, Identifier<C>: Hash"),
    PartialEq(bound = "Asset<C>: PartialEq, Identifier<C>: PartialEq")
)]
pub struct ConsolidationPrerequest<C>(pub Vec<IdentifiedAsset<C>>)
where
    C: transfer::Configuration + ?Sized;

/// Consolidation request
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = r"Asset<C>: Deserialize<'de>, 
                Identifier<C>: Deserialize<'de>",
            serialize = r"Asset<C>: Serialize, 
                Identifier<C>: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "Asset<C>: Clone, Identifier<C>: Clone"),
    Debug(bound = "Asset<C>: Debug, Identifier<C>: Debug"),
    Eq(bound = "Asset<C>: Eq, Identifier<C>: Eq"),
    Hash(bound = "Asset<C>: Hash, Identifier<C>: Hash"),
    PartialEq(bound = "Asset<C>: PartialEq, Identifier<C>: PartialEq")
)]
pub struct ConsolidationRequest<C>(Vec<IdentifiedAsset<C>>)
where
    C: transfer::Configuration + ?Sized;

impl<C> ConsolidationRequest<C>
where
    C: transfer::Configuration,
    IdentifiedAsset<C>: PartialEq,
{
    /// Builds a new [`ConsolidationRequest`] from `assets`.
    #[inline]
    fn new_unchecked(assets: Vec<IdentifiedAsset<C>>) -> Self {
        Self(assets)
    }

    /// Builds a new [`ConsolidationRequest`] from `assets`, ensuring that:
    /// 1) There are at least two [`IdentifiedAsset`]s in `assets`.
    /// 2) There are no duplicates in `assets`.
    /// 3) All assets in `assets` have the same asset id.
    /// 4) No asset in `assets` has zero value.
    #[inline]
    pub fn new(assets: Vec<IdentifiedAsset<C>>) -> Option<Self> {
        let number_of_assets = assets.len();
        if number_of_assets < 2 {
            return None;
        }
        let asset_id = &assets
            .first()
            .expect("This cannot fail because of the check above.")
            .asset
            .id;
        (!(1..number_of_assets).any(|i| {
            assets[i..].contains(&assets[i - 1])
                && assets[i].asset.id.ne(asset_id)
                && assets[i].asset.value.eq(&Default::default())
        }))
        .then_some(Self::new_unchecked(assets))
    }

    ///
    #[inline]
    pub fn id(&self) -> &C::AssetId {
        &self
            .0
            .first()
            .expect("Consolidation requests must have at least 2 elements")
            .asset
            .id
    }

    ///
    #[inline]
    pub fn asset(&self) -> Asset<C> {
        Asset::<C>::new(
            self.id().clone(),
            self.0
                .iter()
                .map(|identified_asset| identified_asset.asset.value.clone())
                .sum(),
        )
    }

    ///
    #[inline]
    pub fn check_consolidation_request<M>(&self, asset_map: &M) -> bool
    where
        M: AssetMap<C::AssetId, C::AssetValue, Key = Identifier<C>>,
    {
        let id = &self
            .0
            .first()
            .expect("Consolidation requests must have at least 2 elements")
            .asset
            .id;
        let asset_map_assets = asset_map
            .asset_vector_with_id(id)
            .into_iter()
            .map(|(identifier, asset)| IdentifiedAsset::<C>::new(identifier, asset))
            .collect::<Vec<_>>();
        self.0.iter().all(|asset| asset_map_assets.contains(asset))
    }

    ///
    #[inline]
    pub fn select<M>(self) -> asset::Selection<C::AssetId, C::AssetValue, M>
    where
        M: AssetMap<C::AssetId, C::AssetValue, Key = Identifier<C>>,
    {
        asset::Selection::new(
            Default::default(),
            self.0
                .into_iter()
                .map(|identified_asset| (identified_asset.identifier, identified_asset.asset.value))
                .collect::<Vec<_>>(),
        )
    }
}

impl<C> TryFrom<ConsolidationPrerequest<C>> for ConsolidationRequest<C>
where
    C: transfer::Configuration,
    IdentifiedAsset<C>: PartialEq,
{
    type Error = SignError<C>;

    #[inline]
    fn try_from(value: ConsolidationPrerequest<C>) -> Result<Self, Self::Error> {
        Self::new(value.0).ok_or(SignError::InvalidConsolidationRequest)
    }
}

/// Signing Result
pub type SignResult<C> = Result<SignResponse<C>, SignError<C>>;

/// Signing with Transaction Data Error
pub type SignWithTransactionDataResult<C> =
    Result<SignWithTransactionDataResponse<C>, SignError<C>>;

/// Signer Checkpoint
pub trait Checkpoint<C>: ledger::Checkpoint
where
    C: transfer::Configuration + ?Sized,
{
    /// UTXO Accumulator Type
    type UtxoAccumulator: Accumulator<
        Item = UtxoAccumulatorItem<C>,
        Model = UtxoAccumulatorModel<C>,
    >;

    /// UTXO Accumulator Hash Type
    type UtxoAccumulatorItemHash: ItemHashFunction<Utxo<C>, Item = UtxoAccumulatorItem<C>>;

    /// Updates `self` by viewing `count`-many nullifiers.
    fn update_from_nullifiers(&mut self, count: usize);

    /// Updates `self` by viewing a new `accumulator`.
    fn update_from_utxo_accumulator(&mut self, accumulator: &Self::UtxoAccumulator);

    /// Updates `self` by viewing `utxo_count`-many [`Utxo`]s.
    fn update_from_utxo_count(&mut self, utxo_count: Vec<usize>);

    /// Computes a best-effort [`Checkpoint`] from the current `accumulator` state.
    #[inline]
    fn from_utxo_accumulator(accumulator: &Self::UtxoAccumulator) -> Self {
        let mut checkpoint = Self::default();
        checkpoint.update_from_utxo_accumulator(accumulator);
        checkpoint
    }

    /// Prunes the `data` required for a [`sync`](Connection::sync) call against `origin` and
    /// `signer_checkpoint`, returning `true` if the data was pruned.
    fn prune(
        parameters: &Self::UtxoAccumulatorItemHash,
        data: &mut SyncData<C>,
        origin: &Self,
        signer_checkpoint: &Self,
    ) -> bool;
}

/// Signer Configuration
pub trait Configuration: transfer::Configuration {
    /// Checkpoint Type
    type Checkpoint: Checkpoint<
        Self,
        UtxoAccumulator = Self::UtxoAccumulator,
        UtxoAccumulatorItemHash = Self::UtxoAccumulatorItemHash,
    >;

    /// Account Type
    type Account: AccountCollection<SpendingKey = SpendingKey<Self>>
        + Clone
        + DeriveAddresses<Parameters = Self::Parameters, Address = Self::Address>;

    /// [`Utxo`] Accumulator Type
    type UtxoAccumulator: Accumulator<
            Item = UtxoAccumulatorItem<Self>,
            Model = UtxoAccumulatorModel<Self>,
            Witness = UtxoAccumulatorWitness<Self>,
        > + BatchInsertion
        + ExactSizeAccumulator
        + FromItemsAndWitnesses
        + OptimizedAccumulator
        + Rollback;

    /// Asset Map Type
    type AssetMap: AssetMap<Self::AssetId, Self::AssetValue, Key = Identifier<Self>>;

    /// Nullifier Map Type
    type NullifierMap: nullifier_map::NullifierMap<Self::Nullifier>;

    /// Asset Metadata Type
    type AssetMetadata;

    /// Random Number Generator Type
    type Rng: CryptoRng + FromEntropy + RngCore;
}

/// Account Table Type
pub type AccountTable<C> = key::AccountTable<<C as Configuration>::Account>;

/// Signer Parameters
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "Parameters<C>: Deserialize<'de>, MultiProvingContext<C>: Deserialize<'de>",
            serialize = "Parameters<C>: Serialize, MultiProvingContext<C>: Serialize",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "Parameters<C>: Clone, MultiProvingContext<C>: Clone"),
    Debug(bound = "Parameters<C>: Debug, MultiProvingContext<C>: Debug"),
    Eq(bound = "Parameters<C>: Eq, MultiProvingContext<C>: Eq"),
    Hash(bound = "Parameters<C>: Hash, MultiProvingContext<C>: Hash"),
    PartialEq(bound = "Parameters<C>: PartialEq, MultiProvingContext<C>: PartialEq")
)]
pub struct SignerParameters<C>
where
    C: Configuration,
{
    /// Parameters
    pub parameters: Parameters<C>,

    /// Proving Context
    pub proving_context: MultiProvingContext<C>,
}

impl<C> SignerParameters<C>
where
    C: Configuration,
{
    /// Builds a new [`SignerParameters`] from `parameters` and `proving_context`.
    #[inline]
    pub fn new(parameters: Parameters<C>, proving_context: MultiProvingContext<C>) -> Self {
        Self {
            parameters,
            proving_context,
        }
    }
}

/// Signer State
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = r"
                AccountTable<C>: Deserialize<'de>,
                AuthorizationContext<C>: Deserialize<'de>,
                C::UtxoAccumulator: Deserialize<'de>,
                C::AssetMap: Deserialize<'de>,
                C::NullifierMap: Deserialize<'de>,
                C::Checkpoint: Deserialize<'de>,
                C::AccountId: Deserialize<'de>,
            ",
            serialize = r"
                AccountTable<C>: Serialize,
                AuthorizationContext<C>: Serialize,
                C::UtxoAccumulator: Serialize,
                C::AssetMap: Serialize,
                C::NullifierMap: Serialize,
                C::Checkpoint: Serialize,
                C::AccountId: Serialize,
            ",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Debug(bound = r"
        AccountTable<C>: Debug,
        AuthorizationContext<C>: Debug,
        C::UtxoAccumulator: Debug,
        C::AssetMap: Debug,
        C::NullifierMap: Debug,
        C::Checkpoint: Debug,
        C::Rng: Debug
    "),
    Default(bound = r"
        AccountTable<C>: Default,
        AuthorizationContext<C>: Default,
        C::UtxoAccumulator: Default,
        C::AssetMap: Default,
        C::NullifierMap: Default,
        C::Checkpoint: Default,
        C::Rng: Default
    "),
    Eq(bound = r"
        AccountTable<C>: Eq,
        AuthorizationContext<C>: Eq,
        C::UtxoAccumulator: Eq,
        C::AssetMap: Eq,
        C::NullifierMap: Eq,
        C::Checkpoint: Eq,
        C::Rng: Eq
    "),
    Hash(bound = r"
        AccountTable<C>: Hash,
        AuthorizationContext<C>: Hash,
        C::UtxoAccumulator: Hash,
        C::AssetMap: Hash,
        C::NullifierMap: Hash,
        C::Checkpoint: Hash,
        C::Rng: Hash
    "),
    PartialEq(bound = r"
        AccountTable<C>: PartialEq,
        AuthorizationContext<C>: PartialEq,
        C::UtxoAccumulator: PartialEq,
        C::AssetMap: PartialEq,
        C::NullifierMap: PartialEq,
        C::Checkpoint: PartialEq,
        C::Rng: PartialEq
    ")
)]
pub struct SignerState<C>
where
    C: Configuration,
{
    /// Account Table
    ///
    /// # Implementation Note
    ///
    /// For now, we only use the default account, and the rest of the storage data is related to
    /// this account. Eventually, we want to have a global `utxo_accumulator` for all accounts and
    /// a local `assets` map for each account.
    accounts: Option<AccountTable<C>>,

    /// Authorization Context
    authorization_context: Option<AuthorizationContext<C>>,

    /// UTXO Accumulator
    utxo_accumulator: C::UtxoAccumulator,

    /// Asset Distribution
    assets: C::AssetMap,

    /// Nullifier Map
    nullifiers: C::NullifierMap,

    /// Current Checkpoint
    checkpoint: C::Checkpoint,

    /// Random Number Generator
    ///
    /// We use this entropy source to add randomness to various cryptographic constructions. The
    /// state of the RNG should not be saved to the file system and instead should be resampled
    /// from local entropy whenever the [`SignerState`] is deserialized.
    #[cfg_attr(feature = "serde", serde(skip, default = "FromEntropy::from_entropy"))]
    rng: C::Rng,
}

impl<C> SignerState<C>
where
    C: Configuration,
{
    /// Builds a new [`SignerState`] from `utxo_accumulator`, `assets`, and `rng`.
    #[inline]
    fn build(
        utxo_accumulator: C::UtxoAccumulator,
        assets: C::AssetMap,
        nullifiers: C::NullifierMap,
        rng: C::Rng,
    ) -> Self {
        Self {
            accounts: None,
            authorization_context: None,
            checkpoint: C::Checkpoint::from_utxo_accumulator(&utxo_accumulator),
            utxo_accumulator,
            assets,
            nullifiers,
            rng,
        }
    }

    /// Builds a new [`SignerState`] from `utxo_accumulator`.
    #[inline]
    pub fn new(utxo_accumulator: C::UtxoAccumulator) -> Self {
        Self::build(
            utxo_accumulator,
            Default::default(),
            Default::default(),
            FromEntropy::from_entropy(),
        )
    }

    /// Loads `accounts` to `self`.
    #[inline]
    pub fn load_accounts(&mut self, accounts: AccountTable<C>) {
        self.accounts = Some(accounts)
    }

    /// Drops `self.accounts`.
    #[inline]
    pub fn drop_accounts(&mut self) {
        self.accounts = None
    }

    /// Tries to load `authorization_context_option` to `self`.
    #[inline]
    pub fn try_load_authorization_context(
        &mut self,
        authorization_context_option: Option<AuthorizationContext<C>>,
    ) -> bool {
        if let Some(authorization_context) = authorization_context_option {
            self.load_authorization_context(authorization_context);
            return true;
        }
        false
    }

    /// Loads `authorization_context` to `self`.
    #[inline]
    pub fn load_authorization_context(&mut self, authorization_context: AuthorizationContext<C>) {
        self.authorization_context = Some(authorization_context)
    }

    /// Drops `self.authorization_context`.
    #[inline]
    pub fn drop_authorization_context(&mut self) {
        self.authorization_context = None
    }

    /// Returns the [`AccountTable`].
    #[inline]
    pub fn accounts(&self) -> Option<&AccountTable<C>> {
        self.accounts.as_ref()
    }

    /// Returns the [`AuthorizationContext`].
    #[inline]
    pub fn authorization_context(&self) -> Option<&AuthorizationContext<C>> {
        self.authorization_context.as_ref()
    }

    /// Returns the default account for `self`.
    #[inline]
    pub fn default_account(&self) -> Option<Account<C::Account>> {
        Some(self.accounts.as_ref()?.get_default())
    }

    ///
    #[inline]
    pub fn asset_list(&self) -> AssetListResponse<C> {
        AssetListResponse(
            self.assets
                .asset_vector()
                .into_iter()
                .filter(|(_, asset)| !asset.is_zero())
                .map(|(identifier, asset)| IdentifiedAsset::<C>::new(identifier, asset))
                .collect(),
        )
    }
}

impl<C> Clone for SignerState<C>
where
    C: Configuration,
    AccountTable<C>: Clone,
    AuthorizationContext<C>: Clone,
    C::UtxoAccumulator: Clone,
    C::AssetMap: Clone,
    C::NullifierMap: Clone,
{
    #[inline]
    fn clone(&self) -> Self {
        let mut signer_state = Self::build(
            self.utxo_accumulator.clone(),
            self.assets.clone(),
            self.nullifiers.clone(),
            FromEntropy::from_entropy(),
        );
        if self.accounts.is_some() {
            signer_state.load_accounts(self.accounts.as_ref().unwrap().clone());
        }
        if self.authorization_context.is_some() {
            signer_state
                .load_authorization_context(self.authorization_context.as_ref().unwrap().clone());
        }
        signer_state
    }
}

/// Signer
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "SignerParameters<C>: Deserialize<'de>, SignerState<C>: Deserialize<'de>",
            serialize = "SignerParameters<C>: Serialize, SignerState<C>: Serialize",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "SignerParameters<C>: Clone, SignerState<C>: Clone"),
    Debug(bound = "SignerParameters<C>: Debug, SignerState<C>: Debug"),
    Eq(bound = "SignerParameters<C>: Eq, SignerState<C>: Eq"),
    Hash(bound = "SignerParameters<C>: Hash, SignerState<C>: Hash"),
    PartialEq(bound = "SignerParameters<C>: PartialEq, SignerState<C>: PartialEq")
)]
pub struct Signer<C>
where
    C: Configuration,
{
    /// Signer Parameters
    parameters: SignerParameters<C>,

    /// Signer State
    state: SignerState<C>,
}

impl<C> Signer<C>
where
    C: Configuration,
{
    /// Builds a new [`Signer`] from `parameters` and `state`.
    #[inline]
    pub fn from_parts(parameters: SignerParameters<C>, state: SignerState<C>) -> Self {
        Self { parameters, state }
    }

    /// Builds a new [`Signer`].
    #[inline]
    fn new_inner(
        parameters: Parameters<C>,
        proving_context: MultiProvingContext<C>,
        utxo_accumulator: C::UtxoAccumulator,
        assets: C::AssetMap,
        nullifiers: C::NullifierMap,
        rng: C::Rng,
    ) -> Self {
        Self::from_parts(
            SignerParameters {
                parameters,
                proving_context,
            },
            SignerState::build(utxo_accumulator, assets, nullifiers, rng),
        )
    }

    /// Builds a new [`Signer`].
    #[inline]
    pub fn new(
        parameters: Parameters<C>,
        proving_context: MultiProvingContext<C>,
        utxo_accumulator: C::UtxoAccumulator,
        rng: C::Rng,
    ) -> Self {
        Self::new_inner(
            parameters,
            proving_context,
            utxo_accumulator,
            Default::default(),
            Default::default(),
            rng,
        )
    }

    /// Returns a shared reference to the signer parameters.
    #[inline]
    pub fn parameters(&self) -> &SignerParameters<C> {
        &self.parameters
    }

    /// Returns a shared reference to the signer state.
    #[inline]
    pub fn state(&self) -> &SignerState<C> {
        &self.state
    }

    /// Loads `accounts` to `self` and updates the authorization context.
    #[inline]
    pub fn load_accounts(&mut self, accounts: AccountTable<C>) {
        self.state.load_accounts(accounts);
        self.update_authorization_context();
    }

    /// Drops `self.state.accounts`
    #[inline]
    pub fn drop_accounts(&mut self) {
        self.state.drop_accounts()
    }

    /// Tries to load `authorization_context_option` to `self`.
    #[inline]
    pub fn try_load_authorization_context(
        &mut self,
        authorization_context_option: Option<AuthorizationContext<C>>,
    ) -> bool {
        self.state
            .try_load_authorization_context(authorization_context_option)
    }

    /// Loads `authorization_context` to `self`.
    #[inline]
    pub fn load_authorization_context(&mut self, authorization_context: AuthorizationContext<C>) {
        self.state.load_authorization_context(authorization_context)
    }

    /// Updates `self.state.authorization_context` from `self.state.accounts`, if possible.
    #[inline]
    fn update_authorization_context(&mut self) -> bool {
        match self.state.accounts() {
            Some(accounts) => {
                self.load_authorization_context(functions::default_authorization_context::<C>(
                    accounts,
                    &self.parameters.parameters,
                ));
                true
            }
            None => false,
        }
    }

    /// Drops `self.state.authorization_context` and `self.state.accounts`.
    #[inline]
    pub fn drop_authorization_context(&mut self) {
        self.state.drop_authorization_context();
        self.drop_accounts()
    }

    /// Updates the internal ledger state, returning the new asset distribution.
    #[inline]
    pub fn sync(
        &mut self,
        request: SyncRequest<C, C::Checkpoint>,
    ) -> Result<SyncResponse<C, C::Checkpoint>, SyncError<C::Checkpoint>>
    where
        C::AssetValue: CheckedAdd<Output = C::AssetValue> + CheckedSub<Output = C::AssetValue>,
    {
        functions::sync(
            &self.parameters,
            self.state
                .authorization_context
                .as_mut()
                .ok_or(SyncError::MissingProofAuthorizationKey)?,
            &mut self.state.assets,
            &mut self.state.nullifiers,
            &mut self.state.checkpoint,
            &mut self.state.utxo_accumulator,
            request,
            &mut self.state.rng,
        )
    }

    /// Performs the initial synchronization of a new signer with the ledger data.
    ///
    /// # Implementation Note
    ///
    /// Using this method to synchronize a signer will make it impossibile to spend any
    /// [`Utxo`](crate::transfer::Utxo)s already on the ledger at the time of synchronization.
    /// Therefore, this method should only be used for the initial synchronization of a
    /// new signer.
    #[inline]
    pub fn initial_sync(
        &mut self,
        request: InitialSyncRequest<C>,
    ) -> Result<SyncResponse<C, C::Checkpoint>, SyncError<C::Checkpoint>> {
        functions::intial_sync(
            &mut self.state.assets,
            &mut self.state.checkpoint,
            &mut self.state.utxo_accumulator,
            request,
        )
    }

    /// Generates an [`IdentityProof`] for `identified_asset` by
    /// signing a virtual [`ToPublic`](transfer::canonical::ToPublic) transaction.
    #[inline]
    pub fn identity_proof(
        &mut self,
        identified_asset: IdentifiedAsset<C>,
        public_account: C::AccountId,
    ) -> Option<IdentityProof<C>> {
        functions::identity_proof(
            &self.parameters,
            self.state.accounts.as_ref()?,
            self.state.utxo_accumulator.model(),
            identified_asset,
            public_account,
            &mut self.state.rng,
        )
    }

    /// Signs the `transaction`, generating transfer posts.
    #[inline]
    pub fn sign(&mut self, transaction: Transaction<C>) -> Result<SignResponse<C>, SignError<C>> {
        functions::sign(
            &self.parameters,
            self.state.accounts.as_ref(),
            self.state.authorization_context.as_mut(),
            &self.state.assets,
            &mut self.state.utxo_accumulator,
            transaction,
            &mut self.state.rng,
        )
    }

    ///
    #[inline]
    pub fn consolidate(
        &mut self,
        request: ConsolidationPrerequest<C>,
    ) -> Result<SignResponse<C>, SignError<C>>
    where
        C::Identifier: PartialEq,
    {
        functions::consolidate(
            &self.parameters,
            self.state.accounts.as_ref(),
            &self.state.assets,
            &mut self.state.utxo_accumulator,
            request,
            &mut self.state.rng,
        )
    }

    /// Returns a vector with the [`IdentityProof`] corresponding to each [`IdentifiedAsset`] in `identified_assets`.
    #[inline]
    pub fn batched_identity_proof(
        &mut self,
        request: Vec<(IdentifiedAsset<C>, C::AccountId)>,
    ) -> IdentityResponse<C> {
        IdentityResponse(
            request
                .into_iter()
                .map(|(identified_asset, public_address)| {
                    self.identity_proof(identified_asset, public_address)
                })
                .collect(),
        )
    }

    /// Returns the [`Address`] corresponding to `self`.
    #[inline]
    pub fn address(&mut self) -> Option<Address<C>> {
        Some(functions::address(
            &self.parameters,
            self.state.authorization_context.as_mut()?,
        ))
    }

    /// Returns the [`AuthorizationContext`] corresponding to `self`.
    #[inline]
    pub fn authorization_context(&self) -> Option<&AuthorizationContext<C>> {
        self.state.authorization_context.as_ref()
    }

    /// Returns the associated [`TransactionData`] of `post`, namely the [`Asset`] and the
    /// [`Identifier`]. Returns `None` if `post` has an invalid shape, or if `self` doesn't own the
    /// underlying assets in `post`.
    #[inline]
    pub fn transaction_data(&mut self, post: TransferPost<C>) -> Option<TransactionData<C>> {
        functions::transaction_data(
            &self.parameters,
            self.state.authorization_context.as_mut()?,
            post,
        )
    }

    /// Returns a vector with the [`TransactionData`] of each well-formed [`TransferPost`] owned by
    /// `self`.
    #[inline]
    pub fn batched_transaction_data(
        &mut self,
        posts: Vec<TransferPost<C>>,
    ) -> TransactionDataResponse<C> {
        TransactionDataResponse(
            posts
                .into_iter()
                .map(|p| self.transaction_data(p))
                .collect(),
        )
    }

    /// Signs the `transaction`, generating transfer posts and returning their associated [`TransactionData`].
    #[inline]
    pub fn sign_with_transaction_data(
        &mut self,
        transaction: Transaction<C>,
    ) -> Result<SignWithTransactionDataResponse<C>, SignError<C>>
    where
        TransferPost<C>: Clone,
    {
        functions::sign_with_transaction_data(
            &self.parameters,
            self.state.accounts.as_ref(),
            self.state
                .authorization_context
                .as_mut()
                .ok_or(SignError::MissingProofAuthorizationKey)?,
            &self.state.assets,
            &mut self.state.utxo_accumulator,
            transaction,
            &mut self.state.rng,
        )
    }

    /// Builds a new [`StorageStateOption`] from `self`.
    #[inline]
    pub fn get_storage(&self) -> StorageStateOption<C>
    where
        C::UtxoAccumulator: Clone,
        C::AssetMap: Clone,
        C::NullifierMap: Clone,
    {
        Some(StorageState::from_signer(self))
    }

    /// Tries to update `self` from `storage_state`.
    #[inline]
    pub fn set_storage(&mut self, storage_state: &StorageStateOption<C>) -> bool
    where
        C::UtxoAccumulator: Clone,
        C::AssetMap: Clone,
        C::NullifierMap: Clone,
    {
        if let Some(storage_state) = storage_state {
            storage_state.update_signer(self);
            return true;
        }
        false
    }

    /// Returns the transfer [`Parameters`] corresponding to `self`.
    #[inline]
    pub fn transfer_parameters(&self) -> &Parameters<C> {
        &self.parameters.parameters
    }

    /// Updates the internal ledger state, returning the new asset distribution.
    ///
    /// # Note
    ///
    /// This method updates the checkpoint and assetmap, but it does not update
    /// the [`UtxoAccumulator`](Configuration::UtxoAccumulator). Therefore, it should
    /// only be used for non-spendable assets such as SBTs.
    #[inline]
    pub fn sbt_sync(
        &mut self,
        request: SyncRequest<C, C::Checkpoint>,
    ) -> Result<SyncResponse<C, C::Checkpoint>, SyncError<C::Checkpoint>> {
        functions::sbt_sync(
            &self.parameters,
            self.state
                .authorization_context
                .as_mut()
                .ok_or(SyncError::MissingProofAuthorizationKey)?,
            &mut self.state.assets,
            &mut self.state.checkpoint,
            request,
        )
    }

    /// Prunes the [`UtxoAccumulator`](Configuration::UtxoAccumulator), deleting any data which
    /// cannot be used to [`sign`](Self::sign) or [`sync`](Self::sync).
    #[inline]
    pub fn prune(&mut self) {
        self.state.utxo_accumulator.prune()
    }

    ///
    #[inline]
    pub fn asset_list(&self) -> AssetListResponse<C> {
        self.state.asset_list()
    }
}

impl<C> Connection<C> for Signer<C>
where
    C: Configuration,
    C::AssetValue: CheckedAdd<Output = C::AssetValue> + CheckedSub<Output = C::AssetValue>,
    C::Identifier: PartialEq,
{
    type AssetMetadata = C::AssetMetadata;
    type Checkpoint = C::Checkpoint;
    type Error = Infallible;

    #[inline]
    fn sync(
        &mut self,
        request: SyncRequest<C, C::Checkpoint>,
    ) -> LocalBoxFutureResult<SyncResult<C, C::Checkpoint>, Self::Error> {
        Box::pin(async move { Ok(self.sync(request)) })
    }

    #[inline]
    fn sbt_sync(
        &mut self,
        request: SyncRequest<C, Self::Checkpoint>,
    ) -> LocalBoxFutureResult<SyncResult<C, Self::Checkpoint>, Self::Error> {
        Box::pin(async move { Ok(self.sbt_sync(request)) })
    }

    #[inline]
    fn initial_sync(
        &mut self,
        request: InitialSyncRequest<C>,
    ) -> LocalBoxFutureResult<SyncResult<C, Self::Checkpoint>, Self::Error> {
        Box::pin(async move { Ok(self.initial_sync(request)) })
    }

    #[inline]
    fn sign(
        &mut self,
        request: SignRequest<Self::AssetMetadata, C>,
    ) -> LocalBoxFutureResult<SignResult<C>, Self::Error> {
        Box::pin(async move { Ok(self.sign(request.transaction)) })
    }

    #[inline]
    fn address(&mut self) -> LocalBoxFutureResult<Option<Address<C>>, Self::Error> {
        Box::pin(async move { Ok(self.address()) })
    }

    #[inline]
    fn transaction_data(
        &mut self,
        request: TransactionDataRequest<C>,
    ) -> LocalBoxFutureResult<TransactionDataResponse<C>, Self::Error> {
        Box::pin(async move { Ok(self.batched_transaction_data(request.0)) })
    }

    #[inline]
    fn identity_proof(
        &mut self,
        request: IdentityRequest<C>,
    ) -> LocalBoxFutureResult<IdentityResponse<C>, Self::Error> {
        Box::pin(async move { Ok(self.batched_identity_proof(request.0)) })
    }

    #[inline]
    fn sign_with_transaction_data(
        &mut self,
        request: SignRequest<Self::AssetMetadata, C>,
    ) -> LocalBoxFutureResult<SignWithTransactionDataResult<C>, Self::Error>
    where
        TransferPost<C>: Clone,
    {
        Box::pin(async move { Ok(self.sign_with_transaction_data(request.transaction)) })
    }

    #[inline]
    fn transfer_parameters(&mut self) -> LocalBoxFutureResult<Parameters<C>, Self::Error> {
        Box::pin(async move { Ok(Signer::transfer_parameters(self).clone()) })
    }

    #[inline]
    fn consolidate(
        &mut self,
        request: ConsolidationPrerequest<C>,
    ) -> LocalBoxFutureResult<SignResult<C>, Self::Error> {
        Box::pin(async move { Ok(self.consolidate(request)) })
    }
}

/// Storage State
///
/// This struct stores the [`Checkpoint`],
/// [`UtxoAccumulator`](Configuration::UtxoAccumulator) and [`AssetMap`] of
/// a [`SignerState`].
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = r"
                C::UtxoAccumulator: Deserialize<'de>,
                C::AssetMap: Deserialize<'de>,
                C::NullifierMap: Deserialize<'de>,
                C::Checkpoint: Deserialize<'de>,
            ",
            serialize = r"
                C::UtxoAccumulator: Serialize,
                C::AssetMap: Serialize,
                C::NullifierMap: Serialize,
                C::Checkpoint: Serialize,
            ",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = r"
        C::UtxoAccumulator: Clone,
        C::AssetMap: Clone,
        C::NullifierMap: Clone,
        C::Checkpoint: Clone,
    "),
    Debug(bound = r"
        C::UtxoAccumulator: Debug,
        C::AssetMap: Debug,
        C::NullifierMap: Debug,
        C::Checkpoint: Debug,
    "),
    Default(bound = r"
        C::UtxoAccumulator: Default,
        C::AssetMap: Default,
        C::NullifierMap: Default,
        C::Checkpoint: Default,
    "),
    Eq(bound = r"
        C::UtxoAccumulator: Eq,
        C::AssetMap: Eq,
        C::NullifierMap: Eq,
        C::Checkpoint: Eq,
    "),
    Hash(bound = r"
        C::UtxoAccumulator: Hash,
        C::AssetMap: Hash,
        C::NullifierMap: Hash,
        C::Checkpoint: Hash,
    "),
    PartialEq(bound = r"
        C::UtxoAccumulator: PartialEq,
        C::AssetMap: PartialEq,
        C::NullifierMap: PartialEq,
        C::Checkpoint: PartialEq,
    ")
)]
pub struct StorageState<C>
where
    C: Configuration,
{
    /// Checkpoint
    checkpoint: C::Checkpoint,

    /// Utxo Accumulator
    utxo_accumulator: C::UtxoAccumulator,

    /// Assets
    assets: C::AssetMap,

    /// Nullifiers
    nullifiers: C::NullifierMap,
}

impl<C> StorageState<C>
where
    C: Configuration,
{
    /// Builds a new [`StorageState`] with default values from `utxo_accumulator_model`.
    #[inline]
    pub fn new(utxo_accumulator_model: &UtxoAccumulatorModel<C>) -> Self {
        let utxo_accumulator = Accumulator::empty(utxo_accumulator_model);
        Self {
            checkpoint: Checkpoint::from_utxo_accumulator(&utxo_accumulator),
            utxo_accumulator,
            assets: Default::default(),
            nullifiers: Default::default(),
        }
    }

    /// Updates `self` from `signer`
    #[inline]
    pub fn update_from_signer(&mut self, signer: &Signer<C>)
    where
        C::UtxoAccumulator: Clone,
        C::AssetMap: Clone,
        C::NullifierMap: Clone,
    {
        self.checkpoint = signer.state.checkpoint.clone();
        self.utxo_accumulator = signer.state.utxo_accumulator.clone();
        self.assets = signer.state.assets.clone();
        self.nullifiers = signer.state.nullifiers.clone();
    }

    /// Builds a new [`StorageState`] from `signer`.
    #[inline]
    pub fn from_signer(signer: &Signer<C>) -> Self
    where
        C::UtxoAccumulator: Clone,
        C::AssetMap: Clone,
        C::NullifierMap: Clone,
    {
        Self {
            checkpoint: signer.state.checkpoint.clone(),
            utxo_accumulator: signer.state.utxo_accumulator.clone(),
            assets: signer.state.assets.clone(),
            nullifiers: signer.state.nullifiers.clone(),
        }
    }

    /// Updates `signer` from `self`.
    #[inline]
    pub fn update_signer(&self, signer: &mut Signer<C>)
    where
        C::UtxoAccumulator: Clone,
        C::AssetMap: Clone,
        C::NullifierMap: Clone,
    {
        signer.state.checkpoint = self.checkpoint.clone();
        signer.state.utxo_accumulator = self.utxo_accumulator.clone();
        signer.state.assets = self.assets.clone();
        signer.state.nullifiers = self.nullifiers.clone();
    }

    /// Initializes a [`Signer`] from `self`, `accounts`, `parameters` and `proving_context`.
    #[inline]
    pub fn initialize_signer(
        &self,
        parameters: Parameters<C>,
        proving_context: MultiProvingContext<C>,
    ) -> Signer<C>
    where
        C::UtxoAccumulator: Clone,
        C::AssetMap: Clone,
        C::NullifierMap: Clone,
    {
        let mut signer = Signer::new(
            parameters,
            proving_context,
            self.utxo_accumulator.clone(),
            FromEntropy::from_entropy(),
        );
        self.update_signer(&mut signer);
        signer
    }
}

/// Storage State Option
pub type StorageStateOption<C> = Option<StorageState<C>>;
