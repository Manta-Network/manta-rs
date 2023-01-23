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
    asset::{AssetMap, AssetMetadata},
    key::{self, Account, AccountCollection, DeriveAddress, DeriveAddresses},
    transfer::{
        self,
        batch::Join,
        canonical::{
            MultiProvingContext, PrivateTransfer, PrivateTransferShape, Selection, ToPrivate,
            ToPublic, Transaction, TransactionData, TransferShape,
        },
        receiver::ReceiverPost,
        requires_authorization,
        utxo::{auth::DeriveContext, DeriveDecryptionKey, DeriveSpend, Spend, UtxoReconstruct},
        Address, Asset, AssociatedData, Authorization, AuthorizationContext, FullParametersRef,
        IdentifiedAsset, Identifier, IdentityProof, Note, Nullifier, Parameters, PreSender,
        ProofSystemError, ProvingContext, Receiver, Sender, Shape, SpendingKey, Transfer,
        TransferPost, Utxo, UtxoAccumulatorItem, UtxoAccumulatorModel, UtxoMembershipProof,
    },
    wallet::ledger::{self, Data},
};
use alloc::{boxed::Box, vec, vec::Vec};
use core::{convert::Infallible, fmt::Debug, hash::Hash};
use manta_crypto::{
    accumulator::{Accumulator, ExactSizeAccumulator, ItemHashFunction, OptimizedAccumulator},
    rand::{CryptoRng, FromEntropy, Rand, RngCore},
};
use manta_util::{
    array_map, cmp::Independence, future::LocalBoxFutureResult, into_array_unchecked,
    iter::IteratorExt, persistence::Rollback, vec::VecExt,
};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Signer Connection
pub trait Connection<C>
where
    C: transfer::Configuration,
{
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

    /// Signs a transaction and returns the ledger transfer posts if successful.
    fn sign(
        &mut self,
        request: SignRequest<C>,
    ) -> LocalBoxFutureResult<Result<SignResponse<C>, SignError<C>>, Self::Error>;

    /// Returns the [`Address`] corresponding to `self`.
    fn address(&mut self) -> LocalBoxFutureResult<Address<C>, Self::Error>;

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
            deserialize = "Transaction<C>: Deserialize<'de>",
            serialize = "Transaction<C>: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "Transaction<C>: Clone"),
    Debug(bound = "Transaction<C>: Debug"),
    Eq(bound = "Transaction<C>: Eq"),
    Hash(bound = "Transaction<C>: Hash"),
    PartialEq(bound = "Transaction<C>: PartialEq")
)]
pub struct SignRequest<C>
where
    C: transfer::Configuration,
{
    /// Transaction Data
    pub transaction: Transaction<C>,

    /// Asset Metadata
    pub metadata: Option<AssetMetadata>,
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
///
/// # Note
///
/// The [`IdentifiedAsset`]s must be opaque.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "Asset<C>: Deserialize<'de>, Identifier<C>: Deserialize<'de>",
            serialize = "Asset<C>: Serialize, Identifier<C>: Serialize"
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
pub struct IdentityRequest<C>(pub Vec<IdentifiedAsset<C>>)
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
}

/// Signing Result
pub type SignResult<C> = Result<SignResponse<C>, SignError<C>>;

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
    type UtxoAccumulator: Accumulator<Item = UtxoAccumulatorItem<Self>, Model = UtxoAccumulatorModel<Self>>
        + ExactSizeAccumulator
        + OptimizedAccumulator
        + Rollback;

    /// Asset Map Type
    type AssetMap: AssetMap<Self::AssetId, Self::AssetValue, Key = Identifier<Self>>;

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
                C::UtxoAccumulator: Deserialize<'de>,
                C::AssetMap: Deserialize<'de>,
                C::Checkpoint: Deserialize<'de>
            ",
            serialize = r"
                AccountTable<C>: Serialize,
                C::UtxoAccumulator: Serialize,
                C::AssetMap: Serialize,
                C::Checkpoint: Serialize
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
        C::UtxoAccumulator: Debug,
        C::AssetMap: Debug,
        C::Checkpoint: Debug,
        C::Rng: Debug
    "),
    Default(bound = r"
        AccountTable<C>: Default,
        C::UtxoAccumulator: Default,
        C::AssetMap: Default,
        C::Checkpoint: Default,
        C::Rng: Default
    "),
    Eq(bound = r"
        AccountTable<C>: Eq,
        C::UtxoAccumulator: Eq,
        C::AssetMap: Eq,
        C::Checkpoint: Eq,
        C::Rng: Eq
    "),
    Hash(bound = r"
        AccountTable<C>: Hash,
        C::UtxoAccumulator: Hash,
        C::AssetMap: Hash,
        C::Checkpoint: Hash,
        C::Rng: Hash
    "),
    PartialEq(bound = r"
        AccountTable<C>: PartialEq,
        C::UtxoAccumulator: PartialEq,
        C::AssetMap: PartialEq,
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
    accounts: AccountTable<C>,

    /// UTXO Accumulator
    utxo_accumulator: C::UtxoAccumulator,

    /// Asset Distribution
    assets: C::AssetMap,

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
    /// Builds a new [`SignerState`] from `accounts`, `utxo_accumulator`, `assets`, and `rng`.
    #[inline]
    fn build(
        accounts: AccountTable<C>,
        utxo_accumulator: C::UtxoAccumulator,
        assets: C::AssetMap,
        rng: C::Rng,
    ) -> Self {
        Self {
            accounts,
            checkpoint: C::Checkpoint::from_utxo_accumulator(&utxo_accumulator),
            utxo_accumulator,
            assets,
            rng,
        }
    }

    /// Builds a new [`SignerState`] from `keys` and `utxo_accumulator`.
    #[inline]
    pub fn new(keys: C::Account, utxo_accumulator: C::UtxoAccumulator) -> Self {
        Self::build(
            AccountTable::<C>::new(keys),
            utxo_accumulator,
            Default::default(),
            FromEntropy::from_entropy(),
        )
    }

    /// Returns the [`AccountTable`].
    #[inline]
    pub fn accounts(&self) -> &AccountTable<C> {
        &self.accounts
    }

    /// Returns the default account for `self`.
    #[inline]
    pub fn default_account(&self) -> Account<C::Account> {
        self.accounts.get_default()
    }

    /// Returns the default spending key for `self`.
    #[inline]
    fn default_spending_key(&self, parameters: &C::Parameters) -> SpendingKey<C> {
        let _ = parameters;
        self.accounts.get_default().spending_key()
    }

    /// Returns the default authorization context for `self`.
    #[inline]
    fn default_authorization_context(&self, parameters: &C::Parameters) -> AuthorizationContext<C> {
        parameters.derive_context(&self.default_spending_key(parameters))
    }

    /// Returns the authorization for the default spending key of `self`.
    #[inline]
    fn authorization_for_default_spending_key(
        &mut self,
        parameters: &C::Parameters,
    ) -> Authorization<C> {
        Authorization::<C>::from_spending_key(
            parameters,
            &self.default_spending_key(parameters),
            &mut self.rng,
        )
    }

    /// Returns the address for the default account of `self`.
    #[inline]
    fn default_address(&mut self, parameters: &C::Parameters) -> Address<C> {
        self.accounts.get_default().address(parameters)
    }

    /// Hashes `utxo` using the [`UtxoAccumulatorItemHash`](transfer::Configuration::UtxoAccumulatorItemHash)
    /// in the transfer [`Configuration`](transfer::Configuration).
    #[inline]
    fn item_hash(parameters: &C::Parameters, utxo: &Utxo<C>) -> UtxoAccumulatorItem<C> {
        parameters
            .utxo_accumulator_item_hash()
            .item_hash(utxo, &mut ())
    }

    /// Inserts the hash of `utxo` in `utxo_accumulator`.
    #[allow(clippy::too_many_arguments)] // FIXME: Use a better abstraction here.
    #[inline]
    fn insert_next_item<R>(
        authorization_context: &mut AuthorizationContext<C>,
        utxo_accumulator: &mut C::UtxoAccumulator,
        assets: &mut C::AssetMap,
        parameters: &Parameters<C>,
        utxo: Utxo<C>,
        identified_asset: IdentifiedAsset<C>,
        nullifiers: &mut Vec<Nullifier<C>>,
        deposit: &mut Vec<Asset<C>>,
        rng: &mut R,
    ) where
        R: CryptoRng + RngCore + ?Sized,
    {
        let IdentifiedAsset::<C> { identifier, asset } = identified_asset;
        let (_, computed_utxo, nullifier) = parameters.derive_spend(
            authorization_context,
            identifier.clone(),
            asset.clone(),
            rng,
        );
        if computed_utxo.is_related(&utxo) {
            if let Some(index) = nullifiers
                .iter()
                .position(move |n| n.is_related(&nullifier))
            {
                nullifiers.remove(index);
            } else {
                utxo_accumulator.insert(&Self::item_hash(parameters, &utxo));
                if !asset.is_zero() {
                    deposit.push(asset.clone());
                }
                assets.insert(identifier, asset);
                return;
            }
        }
        utxo_accumulator.insert_nonprovable(&Self::item_hash(parameters, &utxo));
    }

    /// Checks if `asset` matches with `nullifier`, removing it from the `utxo_accumulator` and
    /// inserting it into the `withdraw` set if this is the case.
    #[allow(clippy::too_many_arguments)] // FIXME: Use a better abstraction here.
    #[inline]
    fn is_asset_unspent<R>(
        authorization_context: &mut AuthorizationContext<C>,
        utxo_accumulator: &mut C::UtxoAccumulator,
        parameters: &Parameters<C>,
        identifier: Identifier<C>,
        asset: Asset<C>,
        nullifiers: &mut Vec<Nullifier<C>>,
        withdraw: &mut Vec<Asset<C>>,
        rng: &mut R,
    ) -> bool
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let (_, utxo, nullifier) =
            parameters.derive_spend(authorization_context, identifier, asset.clone(), rng);
        if let Some(index) = nullifiers
            .iter()
            .position(move |n| n.is_related(&nullifier))
        {
            nullifiers.remove(index);
            utxo_accumulator.remove_proof(&Self::item_hash(parameters, &utxo));
            if !asset.is_zero() {
                withdraw.push(asset);
            }
            false
        } else {
            true
        }
    }

    /// Updates the internal ledger state, returning the new asset distribution.
    #[inline]
    fn sync_with<I>(
        &mut self,
        parameters: &Parameters<C>,
        inserts: I,
        mut nullifiers: Vec<Nullifier<C>>,
        is_partial: bool,
    ) -> SyncResponse<C, C::Checkpoint>
    where
        I: Iterator<Item = (Utxo<C>, Note<C>)>,
    {
        let nullifier_count = nullifiers.len();
        let mut deposit = Vec::new();
        let mut withdraw = Vec::new();
        let mut authorization_context = self.default_authorization_context(parameters);
        let decryption_key = parameters.derive_decryption_key(&mut authorization_context);
        for (utxo, note) in inserts {
            if let Some((identifier, asset)) =
                parameters.open_with_check(&decryption_key, &utxo, note)
            {
                Self::insert_next_item(
                    &mut authorization_context,
                    &mut self.utxo_accumulator,
                    &mut self.assets,
                    parameters,
                    utxo,
                    transfer::utxo::IdentifiedAsset::new(identifier, asset),
                    &mut nullifiers,
                    &mut deposit,
                    &mut self.rng,
                );
            } else {
                self.utxo_accumulator
                    .insert_nonprovable(&Self::item_hash(parameters, &utxo));
            }
        }
        self.assets.retain(|identifier, assets| {
            assets.retain(|asset| {
                Self::is_asset_unspent(
                    &mut authorization_context,
                    &mut self.utxo_accumulator,
                    parameters,
                    identifier.clone(),
                    asset.clone(),
                    &mut nullifiers,
                    &mut withdraw,
                    &mut self.rng,
                )
            });
            !assets.is_empty()
        });
        self.checkpoint.update_from_nullifiers(nullifier_count);
        self.checkpoint
            .update_from_utxo_accumulator(&self.utxo_accumulator);
        SyncResponse {
            checkpoint: self.checkpoint.clone(),
            balance_update: if is_partial {
                // TODO: Whenever we are doing a full update, don't even build the `deposit` and
                //       `withdraw` vectors, since we won't be needing them.
                BalanceUpdate::Partial { deposit, withdraw }
            } else {
                BalanceUpdate::Full {
                    assets: self.assets.assets().into(),
                }
            },
        }
    }

    /// Builds the [`PreSender`] associated to `identifier` and `asset`.
    #[inline]
    fn build_pre_sender(
        &mut self,
        parameters: &Parameters<C>,
        identifier: Identifier<C>,
        asset: Asset<C>,
    ) -> PreSender<C> {
        PreSender::<C>::sample(
            parameters,
            &mut self.default_authorization_context(parameters),
            identifier,
            asset,
            &mut self.rng,
        )
    }

    /// Builds the [`Receiver`] associated with `address` and `asset`.
    #[inline]
    fn receiver(
        &mut self,
        parameters: &Parameters<C>,
        address: Address<C>,
        asset: Asset<C>,
        associated_data: AssociatedData<C>,
    ) -> Receiver<C> {
        Receiver::<C>::sample(parameters, address, asset, associated_data, &mut self.rng)
    }

    /// Builds the [`Receiver`] associated with the default address and `asset`.
    #[inline]
    fn default_receiver(&mut self, parameters: &Parameters<C>, asset: Asset<C>) -> Receiver<C> {
        let default_address = self.default_address(parameters);
        self.receiver(parameters, default_address, asset, Default::default())
    }

    /// Selects the pre-senders which collectively own at least `asset`, returning any change.
    #[inline]
    fn select(
        &mut self,
        parameters: &Parameters<C>,
        asset: &Asset<C>,
    ) -> Result<Selection<C>, SignError<C>> {
        let selection = self.assets.select(asset);
        if !asset.is_zero() && selection.is_empty() {
            return Err(SignError::InsufficientBalance(asset.clone()));
        }
        Selection::new(selection, move |k, v| {
            Ok(self.build_pre_sender(parameters, k, Asset::<C>::new(asset.id.clone(), v)))
        })
    }

    /// Builds a [`TransferPost`] for the given `transfer`.
    #[inline]
    fn build_post_inner<
        const SOURCES: usize,
        const SENDERS: usize,
        const RECEIVERS: usize,
        const SINKS: usize,
    >(
        parameters: FullParametersRef<C>,
        proving_context: &ProvingContext<C>,
        spending_key: Option<&SpendingKey<C>>,
        transfer: Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>,
        rng: &mut C::Rng,
    ) -> Result<TransferPost<C>, SignError<C>> {
        transfer
            .into_post(parameters, proving_context, spending_key, rng)
            .map(|p| p.expect("Internally, all transfer posts are constructed correctly."))
            .map_err(SignError::ProofSystemError)
    }

    /// Builds a [`TransferPost`] for the given `transfer`.
    #[inline]
    fn build_post<
        const SOURCES: usize,
        const SENDERS: usize,
        const RECEIVERS: usize,
        const SINKS: usize,
    >(
        &mut self,
        parameters: &Parameters<C>,
        proving_context: &ProvingContext<C>,
        transfer: Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>,
    ) -> Result<TransferPost<C>, SignError<C>> {
        let spending_key = self.default_spending_key(parameters);
        Self::build_post_inner(
            FullParametersRef::<C>::new(parameters, self.utxo_accumulator.model()),
            proving_context,
            requires_authorization(SENDERS).then_some(&spending_key),
            transfer,
            &mut self.rng,
        )
    }

    /// Computes the next [`Join`](Join) element for an asset rebalancing round.
    #[allow(clippy::type_complexity)] // NOTE: Clippy is too harsh here.
    #[inline]
    fn next_join(
        &mut self,
        parameters: &Parameters<C>,
        asset_id: &C::AssetId,
        total: C::AssetValue,
    ) -> Result<([Receiver<C>; PrivateTransferShape::RECEIVERS], Join<C>), SignError<C>> {
        Ok(Join::new(
            parameters,
            &mut self.default_authorization_context(parameters),
            self.default_address(parameters),
            Asset::<C>::new(asset_id.clone(), total),
            &mut self.rng,
        ))
    }

    /// Prepares the final pre-senders for the last part of the transaction.
    #[inline]
    fn prepare_final_pre_senders(
        &mut self,
        parameters: &Parameters<C>,
        asset_id: &C::AssetId,
        mut new_zeroes: Vec<PreSender<C>>,
        pre_senders: Vec<PreSender<C>>,
    ) -> Result<Vec<Sender<C>>, SignError<C>> {
        let mut senders = pre_senders
            .into_iter()
            .map(|s| s.try_upgrade(parameters, &self.utxo_accumulator))
            .collect::<Option<Vec<_>>>()
            .expect("Unable to upgrade expected UTXOs.");
        let mut needed_zeroes = PrivateTransferShape::SENDERS - senders.len();
        if needed_zeroes == 0 {
            return Ok(senders);
        }
        let zeroes = self.assets.zeroes(needed_zeroes, asset_id);
        needed_zeroes -= zeroes.len();
        for zero in zeroes {
            let pre_sender = self.build_pre_sender(
                parameters,
                zero,
                Asset::<C>::new(asset_id.clone(), Default::default()),
            );
            senders.push(
                pre_sender
                    .try_upgrade(parameters, &self.utxo_accumulator)
                    .expect("Unable to upgrade expected UTXOs."),
            );
        }
        if needed_zeroes == 0 {
            return Ok(senders);
        }
        let needed_fake_zeroes = needed_zeroes.saturating_sub(new_zeroes.len());
        for _ in 0..needed_zeroes {
            match new_zeroes.pop() {
                Some(zero) => senders.push(
                    zero.try_upgrade(parameters, &self.utxo_accumulator)
                        .expect("Unable to upgrade expected UTXOs."),
                ),
                _ => break,
            }
        }
        if needed_fake_zeroes == 0 {
            return Ok(senders);
        }
        for _ in 0..needed_fake_zeroes {
            let identifier = self.rng.gen();
            senders.push(
                self.build_pre_sender(
                    parameters,
                    identifier,
                    Asset::<C>::new(asset_id.clone(), Default::default()),
                )
                .upgrade_unchecked(Default::default()),
            );
        }
        Ok(senders)
    }

    /// Builds two virtual [`Sender`]s for `pre_sender`.
    #[inline]
    fn virtual_senders(
        &mut self,
        parameters: &Parameters<C>,
        asset_id: &C::AssetId,
        pre_sender: PreSender<C>,
    ) -> Result<[Sender<C>; PrivateTransferShape::SENDERS], SignError<C>> {
        let mut utxo_accumulator = C::UtxoAccumulator::empty(self.utxo_accumulator.model());
        let sender = pre_sender
            .insert_and_upgrade(parameters, &mut utxo_accumulator)
            .expect("Unable to upgrade expected UTXO.");
        let mut senders = Vec::new();
        senders.push(sender);
        let identifier = self.rng.gen();
        senders.push(
            self.build_pre_sender(
                parameters,
                identifier,
                Asset::<C>::new(asset_id.clone(), Default::default()),
            )
            .upgrade_unchecked(Default::default()),
        );
        Ok(into_array_unchecked(senders))
    }

    /// Computes the batched transactions for rebalancing before a final transfer.
    #[inline]
    fn compute_batched_transactions(
        &mut self,
        parameters: &Parameters<C>,
        proving_context: &MultiProvingContext<C>,
        asset_id: &C::AssetId,
        mut pre_senders: Vec<PreSender<C>>,
        posts: &mut Vec<TransferPost<C>>,
    ) -> Result<[Sender<C>; PrivateTransferShape::SENDERS], SignError<C>> {
        let mut new_zeroes = Vec::new();
        while pre_senders.len() > PrivateTransferShape::SENDERS {
            let mut joins = Vec::new();
            let mut iter = pre_senders
                .into_iter()
                .chunk_by::<{ PrivateTransferShape::SENDERS }>();
            for chunk in &mut iter {
                let senders = array_map(chunk, |s| {
                    s.try_upgrade(parameters, &self.utxo_accumulator)
                        .expect("Unable to upgrade expected UTXO.")
                });
                let (receivers, mut join) = self.next_join(
                    parameters,
                    asset_id,
                    senders.iter().map(|s| s.asset().value).sum(),
                )?;
                let authorization = self.authorization_for_default_spending_key(parameters);
                posts.push(self.build_post(
                    parameters,
                    &proving_context.private_transfer,
                    PrivateTransfer::build(authorization, senders, receivers),
                )?);
                join.insert_utxos(parameters, &mut self.utxo_accumulator);
                joins.push(join.pre_sender);
                new_zeroes.append(&mut join.zeroes);
            }
            joins.append(&mut iter.remainder());
            pre_senders = joins;
        }
        Ok(into_array_unchecked(self.prepare_final_pre_senders(
            parameters,
            asset_id,
            new_zeroes,
            pre_senders,
        )?))
    }
}

impl<C> Clone for SignerState<C>
where
    C: Configuration,
    AccountTable<C>: Clone,
    C::UtxoAccumulator: Clone,
    C::AssetMap: Clone,
{
    #[inline]
    fn clone(&self) -> Self {
        Self::build(
            self.accounts.clone(),
            self.utxo_accumulator.clone(),
            self.assets.clone(),
            FromEntropy::from_entropy(),
        )
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
        accounts: AccountTable<C>,
        parameters: Parameters<C>,
        proving_context: MultiProvingContext<C>,
        utxo_accumulator: C::UtxoAccumulator,
        assets: C::AssetMap,
        rng: C::Rng,
    ) -> Self {
        Self::from_parts(
            SignerParameters {
                parameters,
                proving_context,
            },
            SignerState::build(accounts, utxo_accumulator, assets, rng),
        )
    }

    /// Builds a new [`Signer`] from a fresh set of `accounts`.
    ///
    /// # Warning
    ///
    /// This method assumes that `accounts` has never been used before, and does not attempt
    /// to perform wallet recovery on this table.
    #[inline]
    pub fn new(
        accounts: AccountTable<C>,
        parameters: Parameters<C>,
        proving_context: MultiProvingContext<C>,
        utxo_accumulator: C::UtxoAccumulator,
        rng: C::Rng,
    ) -> Self {
        Self::new_inner(
            accounts,
            parameters,
            proving_context,
            utxo_accumulator,
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

    /// Updates the internal ledger state, returning the new asset distribution.
    #[inline]
    pub fn sync(
        &mut self,
        mut request: SyncRequest<C, C::Checkpoint>,
    ) -> Result<SyncResponse<C, C::Checkpoint>, SyncError<C::Checkpoint>> {
        // TODO: Do a capacity check on the current UTXO accumulator?
        //
        // if self.utxo_accumulator.capacity() < starting_index {
        //    panic!("full capacity")
        // }
        let checkpoint = &self.state.checkpoint;
        if checkpoint < &request.origin_checkpoint {
            Err(SyncError::InconsistentSynchronization {
                checkpoint: checkpoint.clone(),
            })
        } else {
            let has_pruned = request.prune(
                self.parameters.parameters.utxo_accumulator_item_hash(),
                checkpoint,
            );
            let SyncData {
                utxo_note_data,
                nullifier_data,
            } = request.data;
            let response = self.state.sync_with(
                &self.parameters.parameters,
                utxo_note_data.into_iter(),
                nullifier_data,
                !has_pruned,
            );
            self.state.utxo_accumulator.commit();
            Ok(response)
        }
    }

    /// Signs a withdraw transaction for `asset` sent to `address`.
    #[inline]
    fn sign_withdraw(
        &mut self,
        asset: Asset<C>,
        address: Option<Address<C>>,
    ) -> Result<SignResponse<C>, SignError<C>> {
        let selection = self.state.select(&self.parameters.parameters, &asset)?;
        let mut posts = Vec::new();
        let senders = self.state.compute_batched_transactions(
            &self.parameters.parameters,
            &self.parameters.proving_context,
            &asset.id,
            selection.pre_senders,
            &mut posts,
        )?;
        let change = self.state.default_receiver(
            &self.parameters.parameters,
            Asset::<C>::new(asset.id.clone(), selection.change),
        );
        let authorization = self
            .state
            .authorization_for_default_spending_key(&self.parameters.parameters);
        let final_post = match address {
            Some(address) => {
                let receiver = self.state.receiver(
                    &self.parameters.parameters,
                    address,
                    asset,
                    Default::default(),
                );
                self.state.build_post(
                    &self.parameters.parameters,
                    &self.parameters.proving_context.private_transfer,
                    PrivateTransfer::build(authorization, senders, [change, receiver]),
                )?
            }
            _ => self.state.build_post(
                &self.parameters.parameters,
                &self.parameters.proving_context.to_public,
                ToPublic::build(authorization, senders, [change], asset),
            )?,
        };
        posts.push(final_post);
        Ok(SignResponse::new(posts))
    }

    /// Generates an [`IdentityProof`] for `identified_asset` by
    /// signing a virtual [`ToPublic`] transaction.
    #[inline]
    fn sign_virtual_to_public(
        &mut self,
        identified_asset: IdentifiedAsset<C>,
    ) -> Option<IdentityProof<C>> {
        let presender = self.state.build_pre_sender(
            &self.parameters.parameters,
            identified_asset.identifier,
            identified_asset.asset.clone(),
        );
        let senders = self
            .state
            .virtual_senders(
                &self.parameters.parameters,
                &identified_asset.asset.id,
                presender,
            )
            .ok()?;
        let change = self.state.default_receiver(
            &self.parameters.parameters,
            Asset::<C>::new(identified_asset.asset.id.clone(), Default::default()),
        );
        let authorization = self
            .state
            .authorization_for_default_spending_key(&self.parameters.parameters);
        let transfer_post = self
            .state
            .build_post(
                &self.parameters.parameters,
                &self.parameters.proving_context.to_public,
                ToPublic::build(authorization, senders, [change], identified_asset.asset),
            )
            .ok()?;
        Some(IdentityProof { transfer_post })
    }

    /// Signs the `transaction`, generating transfer posts without releasing resources.
    #[inline]
    fn sign_internal(
        &mut self,
        transaction: Transaction<C>,
    ) -> Result<SignResponse<C>, SignError<C>> {
        match transaction {
            Transaction::ToPrivate(asset) => {
                let receiver = self
                    .state
                    .default_receiver(&self.parameters.parameters, asset.clone());
                Ok(SignResponse::new(vec![self.state.build_post(
                    &self.parameters.parameters,
                    &self.parameters.proving_context.to_private,
                    ToPrivate::build(asset, receiver),
                )?]))
            }
            Transaction::PrivateTransfer(asset, address) => {
                self.sign_withdraw(asset, Some(address))
            }
            Transaction::ToPublic(asset) => self.sign_withdraw(asset, None),
        }
    }

    /// Signs the `transaction`, generating transfer posts.
    #[inline]
    pub fn sign(&mut self, transaction: Transaction<C>) -> Result<SignResponse<C>, SignError<C>> {
        let result = self.sign_internal(transaction);
        self.state.utxo_accumulator.rollback();
        result
    }

    /// Generates an [`IdentityProof`] for `identified_asset` by
    /// signing a virtual [`ToPublic`] transaction.
    #[inline]
    pub fn identity_proof(
        &mut self,
        identified_asset: IdentifiedAsset<C>,
    ) -> Option<IdentityProof<C>> {
        let result = self.sign_virtual_to_public(identified_asset);
        self.state.utxo_accumulator.rollback();
        result
    }

    /// Returns a vector with the [`IdentityProof`] corresponding to each [`IdentifiedAsset`] in `identified_assets`.
    #[inline]
    pub fn batched_identity_proof(
        &mut self,
        identified_assets: Vec<IdentifiedAsset<C>>,
    ) -> IdentityResponse<C> {
        IdentityResponse(
            identified_assets
                .into_iter()
                .map(|identified_asset| self.identity_proof(identified_asset))
                .collect(),
        )
    }

    /// Returns the [`Address`] corresponding to `self`.
    #[inline]
    pub fn address(&mut self) -> Address<C> {
        let account = self.state.accounts.get_default();
        account.address(&self.parameters.parameters)
    }

    /// Returns the associated [`TransactionData`] of `post`, namely the [`Asset`] and the
    /// [`Identifier`]. Returns `None` if `post` has an invalid shape, or if `self` doesn't own the
    /// underlying assets in `post`.
    #[inline]
    pub fn transaction_data(&self, post: TransferPost<C>) -> Option<TransactionData<C>> {
        let shape = TransferShape::from_post(&post)?;
        let parameters = &self.parameters.parameters;
        let mut authorization_context = self.state.default_authorization_context(parameters);
        let decryption_key = parameters.derive_decryption_key(&mut authorization_context);
        match shape {
            TransferShape::ToPrivate => {
                let ReceiverPost { utxo, note } = post.body.receiver_posts.take_first();
                let (identifier, asset) =
                    parameters.open_with_check(&decryption_key, &utxo, note)?;
                Some(TransactionData::<C>::ToPrivate(identifier, asset))
            }
            TransferShape::PrivateTransfer => {
                let mut transaction_data = Vec::new();
                let receiver_posts = post.body.receiver_posts;
                for receiver_post in receiver_posts.into_iter() {
                    let ReceiverPost { utxo, note } = receiver_post;
                    if let Some(identified_asset) =
                        parameters.open_with_check(&decryption_key, &utxo, note)
                    {
                        transaction_data.push(identified_asset);
                    }
                }
                if transaction_data.is_empty() {
                    None
                } else {
                    Some(TransactionData::<C>::PrivateTransfer(transaction_data))
                }
            }
            TransferShape::ToPublic => {
                let ReceiverPost { utxo, note } = post.body.receiver_posts.take_first();
                let (identifier, asset) =
                    parameters.open_with_check(&decryption_key, &utxo, note)?;
                Some(TransactionData::<C>::ToPublic(identifier, asset))
            }
        }
    }

    /// Returns a vector with the [`TransactionData`] of each well-formed [`TransferPost`] owned by
    /// `self`.
    #[inline]
    pub fn batched_transaction_data(
        &self,
        posts: Vec<TransferPost<C>>,
    ) -> TransactionDataResponse<C> {
        TransactionDataResponse(
            posts
                .into_iter()
                .map(|p| self.transaction_data(p))
                .collect(),
        )
    }
}

impl<C> Connection<C> for Signer<C>
where
    C: Configuration,
{
    type Checkpoint = C::Checkpoint;
    type Error = Infallible;

    #[inline]
    fn sync(
        &mut self,
        request: SyncRequest<C, C::Checkpoint>,
    ) -> LocalBoxFutureResult<
        Result<SyncResponse<C, C::Checkpoint>, SyncError<C::Checkpoint>>,
        Self::Error,
    > {
        Box::pin(async move { Ok(self.sync(request)) })
    }

    #[inline]
    fn sign(
        &mut self,
        request: SignRequest<C>,
    ) -> LocalBoxFutureResult<Result<SignResponse<C>, SignError<C>>, Self::Error> {
        Box::pin(async move { Ok(self.sign(request.transaction)) })
    }

    #[inline]
    fn address(&mut self) -> LocalBoxFutureResult<Address<C>, Self::Error> {
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
}
