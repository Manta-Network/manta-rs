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
// TODO:  Setup multi-account wallets using `crate::key::AccountTable`.
// TODO:  Move `sync` to a streaming algorithm.
// TODO:  Add self-destruct feature for clearing all secret and private data.
// TODO:  Compress the `BalanceUpdate` data before sending (improves privacy and bandwidth).
// TODO:  Improve asynchronous interfaces internally in the signer, instead of just blocking
//        internally.

use crate::{
    asset::{Asset, AssetId, AssetMap, AssetMetadata, AssetValue},
    key::{
        self, HierarchicalKeyDerivationScheme, KeyIndex, SecretKeyPair, ViewKeySelection,
        ViewKeyTable,
    },
    transfer::{
        self,
        batch::Join,
        canonical::{
            Mint, MultiProvingContext, PrivateTransfer, PrivateTransferShape, Reclaim, Selection,
            Shape, Transaction,
        },
        EncryptedNote, FullParameters, Note, Parameters, PreSender, ProofSystemError,
        ProvingContext, Receiver, ReceivingKey, SecretKey, Sender, SpendingKey, Transfer,
        TransferPost, Utxo, VoidNumber,
    },
    wallet::ledger::{self, Data},
};
use alloc::{boxed::Box, vec, vec::Vec};
use core::{convert::Infallible, fmt::Debug, hash::Hash};
use manta_crypto::{
    accumulator::{Accumulator, ExactSizeAccumulator, OptimizedAccumulator},
    rand::{CryptoRng, FromEntropy, Rand, RngCore},
};
use manta_util::{
    array_map,
    future::LocalBoxFutureResult,
    into_array_unchecked,
    iter::{Finder, IteratorExt},
    persistence::Rollback,
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
    ) -> LocalBoxFutureResult<SyncResult<Self::Checkpoint>, Self::Error>;

    /// Signs a transaction and returns the ledger transfer posts if successful.
    fn sign(
        &mut self,
        request: SignRequest<C>,
    ) -> LocalBoxFutureResult<Result<SignResponse<C>, SignError<C>>, Self::Error>;

    /// Returns public receiving keys according to the `request`.
    fn receiving_keys(
        &mut self,
        request: ReceivingKeyRequest,
    ) -> LocalBoxFutureResult<Vec<ReceivingKey<C>>, Self::Error>;
}

/// Signer Synchronization Data
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = r"
                Utxo<C>: Deserialize<'de>,
                EncryptedNote<C>: Deserialize<'de>,
                VoidNumber<C>: Deserialize<'de>
            ",
            serialize = r"
                Utxo<C>: Serialize,
                EncryptedNote<C>: Serialize,
                VoidNumber<C>: Serialize
            ",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "Utxo<C>: Clone, EncryptedNote<C>: Clone, VoidNumber<C>: Clone"),
    Debug(bound = "Utxo<C>: Debug, EncryptedNote<C>: Debug, VoidNumber<C>: Debug"),
    Default(bound = ""),
    Eq(bound = "Utxo<C>: Eq, EncryptedNote<C>: Eq, VoidNumber<C>: Eq"),
    Hash(bound = "Utxo<C>: Hash, EncryptedNote<C>: Hash, VoidNumber<C>: Hash"),
    PartialEq(bound = "Utxo<C>: PartialEq, EncryptedNote<C>: PartialEq, VoidNumber<C>: PartialEq")
)]
pub struct SyncData<C>
where
    C: transfer::Configuration + ?Sized,
{
    /// Receiver Data
    pub receivers: Vec<(Utxo<C>, EncryptedNote<C>)>,

    /// Sender Data
    pub senders: Vec<VoidNumber<C>>,
}

impl<C> Data<C::Checkpoint> for SyncData<C>
where
    C: Configuration + ?Sized,
{
    #[inline]
    fn prune(&mut self, origin: &C::Checkpoint, checkpoint: &C::Checkpoint) -> bool {
        C::Checkpoint::prune(self, origin, checkpoint)
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
    /// Recovery Flag
    ///
    /// If `with_recovery` is set to `true`, the [`GAP_LIMIT`] is used during sync to perform a full
    /// recovery. See [`Configuration::HierarchicalKeyDerivationScheme`] for the scheme where the
    /// [`GAP_LIMIT`] is configured.
    ///
    /// [`GAP_LIMIT`]: HierarchicalKeyDerivationScheme::GAP_LIMIT
    pub with_recovery: bool,

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
    pub fn prune(&mut self, checkpoint: &T) -> bool
    where
        SyncData<C>: Data<T>,
    {
        self.data.prune(&self.origin_checkpoint, checkpoint)
    }
}

/// Signer Synchronization Response
///
/// This `struct` is created by the [`sync`](Connection::sync) method on [`Connection`].
/// See its documentation for more.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SyncResponse<T>
where
    T: ledger::Checkpoint,
{
    /// Checkpoint
    pub checkpoint: T,

    /// Balance Update
    pub balance_update: BalanceUpdate,
}

/// Balance Update
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum BalanceUpdate {
    /// Partial Update
    ///
    /// This is the typical response from the [`Signer`]. In rare de-synchronization cases, we may
    /// need to perform a [`Full`](Self::Full) update.
    Partial {
        /// Assets Deposited in the Last Update
        deposit: Vec<Asset>,

        /// Assets Withdrawn in the Last Update
        withdraw: Vec<Asset>,
    },

    /// Full Update
    ///
    /// Whenever the [`Signer`] gets ahead of the synchronization point, it would have updated its
    /// internal balance state further along than any connection following its updates. In this
    /// case, the entire balance state needs to be sent to catch up.
    Full {
        /// Full Balance State
        assets: Vec<Asset>,
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
pub type SyncResult<T> = Result<SyncResponse<T>, SyncError<T>>;

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
            deserialize = "ProofSystemError<C>: Deserialize<'de>",
            serialize = "ProofSystemError<C>: Serialize"
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "ProofSystemError<C>: Clone"),
    Copy(bound = "ProofSystemError<C>: Copy"),
    Debug(bound = "ProofSystemError<C>: Debug"),
    Eq(bound = "ProofSystemError<C>: Eq"),
    Hash(bound = "ProofSystemError<C>: Hash"),
    PartialEq(bound = "ProofSystemError<C>: PartialEq")
)]
pub enum SignError<C>
where
    C: transfer::Configuration,
{
    /// Insufficient Balance
    InsufficientBalance(Asset),

    /// Proof System Error
    ProofSystemError(ProofSystemError<C>),
}

/// Signing Result
pub type SignResult<C> = Result<SignResponse<C>, SignError<C>>;

/// Receiving Key Request
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReceivingKeyRequest {
    /// Get Specific Key
    ///
    /// Requests the key at the specific `index`. If the signer's response is an empty key vector,
    /// then the index was out of bounds.
    Get {
        /// Target Key Index
        index: KeyIndex,
    },

    /// Get All Keys
    ///
    /// Requests all the public keys associated to the signer. The signer should always respond to
    /// this request with at least one key, the default public key.
    GetAll,

    /// New Keys
    ///
    /// Requests `count`-many new keys from the hierarchical key derivation scheme. The signer
    /// should always respond with at most `count`-many keys. If there are fewer, this is because,
    /// adding such keys would exceed the [`GAP_LIMIT`](HierarchicalKeyDerivationScheme::GAP_LIMIT).
    New {
        /// Number of New Keys to Generate
        count: usize,
    },
}

/// Signer Checkpoint
pub trait Checkpoint<C>: ledger::Checkpoint
where
    C: transfer::Configuration + ?Sized,
{
    /// UTXO Accumulator Type
    type UtxoAccumulator: Accumulator<Item = C::Utxo, Model = C::UtxoAccumulatorModel>;

    /// Updates `self` by viewing `count`-many void numbers.
    fn update_from_void_numbers(&mut self, count: usize);

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
    fn prune(data: &mut SyncData<C>, origin: &Self, signer_checkpoint: &Self) -> bool;
}

/// Signer Configuration
pub trait Configuration: transfer::Configuration {
    /// Checkpoint Type
    type Checkpoint: Checkpoint<Self, UtxoAccumulator = Self::UtxoAccumulator>;

    /// Hierarchical Key Derivation Scheme
    type HierarchicalKeyDerivationScheme: HierarchicalKeyDerivationScheme<
        SecretKey = SecretKey<Self>,
    >;

    /// [`Utxo`] Accumulator Type
    type UtxoAccumulator: Accumulator<Item = Self::Utxo, Model = Self::UtxoAccumulatorModel>
        + ExactSizeAccumulator
        + OptimizedAccumulator
        + Rollback;

    /// Asset Map Type
    type AssetMap: AssetMap<Key = AssetMapKey<Self>>;

    /// Random Number Generator Type
    type Rng: CryptoRng + FromEntropy + RngCore;
}

/// Account Table Type
pub type AccountTable<C> = key::AccountTable<<C as Configuration>::HierarchicalKeyDerivationScheme>;

/// Asset Map Key Type
pub type AssetMapKey<C> = (KeyIndex, SecretKey<C>);

/// Signer Parameters
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

    /// Converts `keypair` into a [`ReceivingKey`] by using the key-agreement scheme to derive the
    /// public keys associated to `keypair`.
    #[inline]
    fn receiving_key(
        &self,
        keypair: SecretKeyPair<C::HierarchicalKeyDerivationScheme>,
    ) -> ReceivingKey<C> {
        SpendingKey::new(keypair.spend, keypair.view).derive(self.parameters.key_agreement_scheme())
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
pub struct SignerState<C>
where
    C: Configuration,
{
    /// Account Table
    ///
    /// # Note
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
    pub fn new(
        keys: C::HierarchicalKeyDerivationScheme,
        utxo_accumulator: C::UtxoAccumulator,
    ) -> Self {
        Self::build(
            AccountTable::<C>::new(keys),
            utxo_accumulator,
            Default::default(),
            FromEntropy::from_entropy(),
        )
    }

    /// Finds the next viewing key that can decrypt the `encrypted_note` from the `view_key_table`.
    #[inline]
    fn find_next_key<'h>(
        view_key_table: &mut ViewKeyTable<'h, C::HierarchicalKeyDerivationScheme>,
        parameters: &Parameters<C>,
        with_recovery: bool,
        encrypted_note: EncryptedNote<C>,
    ) -> Option<ViewKeySelection<C::HierarchicalKeyDerivationScheme, Note<C>>> {
        let mut finder = Finder::new(encrypted_note);
        view_key_table.find_index_with_maybe_gap(with_recovery, move |k| {
            finder.next(|note| note.decrypt(&parameters.note_encryption_scheme, k, &mut ()))
        })
    }

    /// Inserts the new `utxo`-`note` pair into the `utxo_accumulator` adding the spendable amount
    /// to `assets` if there is no void number to match it.
    #[inline]
    fn insert_next_item(
        utxo_accumulator: &mut C::UtxoAccumulator,
        assets: &mut C::AssetMap,
        parameters: &Parameters<C>,
        utxo: Utxo<C>,
        selection: ViewKeySelection<C::HierarchicalKeyDerivationScheme, Note<C>>,
        void_numbers: &mut Vec<VoidNumber<C>>,
        deposit: &mut Vec<Asset>,
    ) {
        let ViewKeySelection {
            index,
            keypair,
            item: Note {
                ephemeral_secret_key,
                asset,
            },
        } = selection;
        if let Some(void_number) =
            parameters.check_full_asset(&keypair.spend, &ephemeral_secret_key, &asset, &utxo)
        {
            if let Some(index) = void_numbers.iter().position(move |v| v == &void_number) {
                void_numbers.remove(index);
            } else {
                utxo_accumulator.insert(&utxo);
                assets.insert((index, ephemeral_secret_key), asset);
                if !asset.is_zero() {
                    deposit.push(asset);
                }
                return;
            }
        }
        utxo_accumulator.insert_nonprovable(&utxo);
    }

    /// Checks if `asset` matches with `void_number`, removing it from the `utxo_accumulator` and
    /// inserting it into the `withdraw` set if this is the case.
    #[inline]
    fn is_asset_unspent(
        utxo_accumulator: &mut C::UtxoAccumulator,
        parameters: &Parameters<C>,
        secret_spend_key: &SecretKey<C>,
        ephemeral_secret_key: &SecretKey<C>,
        asset: Asset,
        void_numbers: &mut Vec<VoidNumber<C>>,
        withdraw: &mut Vec<Asset>,
    ) -> bool {
        let utxo = parameters.utxo(
            ephemeral_secret_key,
            &parameters.derive(secret_spend_key),
            &asset,
        );
        let void_number = parameters.void_number(secret_spend_key, &utxo);
        if let Some(index) = void_numbers.iter().position(move |v| v == &void_number) {
            void_numbers.remove(index);
            utxo_accumulator.remove_proof(&utxo);
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
        with_recovery: bool,
        inserts: I,
        mut void_numbers: Vec<VoidNumber<C>>,
        is_partial: bool,
    ) -> SyncResponse<C::Checkpoint>
    where
        I: Iterator<Item = (Utxo<C>, EncryptedNote<C>)>,
    {
        let void_number_count = void_numbers.len();
        let mut deposit = Vec::new();
        let mut withdraw = Vec::new();
        let mut view_key_table = self.accounts.get_mut_default().view_key_table();
        for (utxo, encrypted_note) in inserts {
            if let Some(selection) = Self::find_next_key(
                &mut view_key_table,
                parameters,
                with_recovery,
                encrypted_note,
            ) {
                Self::insert_next_item(
                    &mut self.utxo_accumulator,
                    &mut self.assets,
                    parameters,
                    utxo,
                    selection,
                    &mut void_numbers,
                    &mut deposit,
                );
            } else {
                self.utxo_accumulator.insert_nonprovable(&utxo);
            }
        }
        self.assets.retain(|(index, ephemeral_secret_key), assets| {
            assets.retain(
                |asset| match self.accounts.get_default().spend_key(*index) {
                    Some(secret_spend_key) => Self::is_asset_unspent(
                        &mut self.utxo_accumulator,
                        parameters,
                        &secret_spend_key,
                        ephemeral_secret_key,
                        *asset,
                        &mut void_numbers,
                        &mut withdraw,
                    ),
                    _ => true,
                },
            );
            !assets.is_empty()
        });
        self.checkpoint.update_from_void_numbers(void_number_count);
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

    /// Builds the pre-sender associated to `key` and `asset`.
    #[inline]
    fn build_pre_sender(
        &self,
        parameters: &Parameters<C>,
        key: AssetMapKey<C>,
        asset: Asset,
    ) -> Result<PreSender<C>, SignError<C>> {
        let (spend_index, ephemeral_secret_key) = key;
        Ok(PreSender::new(
            parameters,
            self.accounts
                .get_default()
                .spend_key(spend_index)
                .expect("Index is guaranteed to be within bounds."),
            ephemeral_secret_key,
            asset,
        ))
    }

    /// Builds the receiver for `asset`.
    #[inline]
    fn build_receiver(
        &mut self,
        parameters: &Parameters<C>,
        asset: Asset,
    ) -> Result<Receiver<C>, SignError<C>> {
        let keypair = self.accounts.get_default().default_keypair();
        Ok(SpendingKey::new(keypair.spend, keypair.view).receiver(
            parameters,
            self.rng.gen(),
            asset,
        ))
    }

    /// Builds a new internal [`Mint`] for zero assets.
    #[inline]
    fn mint_zero(
        &mut self,
        parameters: &Parameters<C>,
        asset_id: AssetId,
    ) -> Result<(Mint<C>, PreSender<C>), SignError<C>> {
        let asset = Asset::zero(asset_id);
        let keypair = self.accounts.get_default().default_keypair();
        Ok(Mint::internal_pair(
            parameters,
            &SpendingKey::new(keypair.spend, keypair.view),
            asset,
            &mut self.rng,
        ))
    }

    /// Selects the pre-senders which collectively own at least `asset`, returning any change.
    #[inline]
    fn select(
        &mut self,
        parameters: &Parameters<C>,
        asset: Asset,
    ) -> Result<Selection<C>, SignError<C>> {
        let selection = self.assets.select(asset);
        if !asset.is_zero() && selection.is_empty() {
            return Err(SignError::InsufficientBalance(asset));
        }
        Selection::new(selection, move |k, v| {
            self.build_pre_sender(parameters, k, asset.id.with(v))
        })
    }

    /// Builds a [`TransferPost`] for the given `transfer`.
    #[inline]
    fn build_post<
        const SOURCES: usize,
        const SENDERS: usize,
        const RECEIVERS: usize,
        const SINKS: usize,
    >(
        parameters: FullParameters<C>,
        proving_context: &ProvingContext<C>,
        transfer: Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>,
        rng: &mut C::Rng,
    ) -> Result<TransferPost<C>, SignError<C>> {
        transfer
            .into_post(parameters, proving_context, rng)
            .map_err(SignError::ProofSystemError)
    }

    /// Mints an asset with zero value for the given `asset_id`, returning the appropriate
    /// Builds a [`TransferPost`] for `mint`.
    #[inline]
    fn mint_post(
        &mut self,
        parameters: &Parameters<C>,
        proving_context: &ProvingContext<C>,
        mint: Mint<C>,
    ) -> Result<TransferPost<C>, SignError<C>> {
        Self::build_post(
            FullParameters::new(parameters, self.utxo_accumulator.model()),
            proving_context,
            mint,
            &mut self.rng,
        )
    }

    /// Builds a [`TransferPost`] for `private_transfer`.
    #[inline]
    fn private_transfer_post(
        &mut self,
        parameters: &Parameters<C>,
        proving_context: &ProvingContext<C>,
        private_transfer: PrivateTransfer<C>,
    ) -> Result<TransferPost<C>, SignError<C>> {
        Self::build_post(
            FullParameters::new(parameters, self.utxo_accumulator.model()),
            proving_context,
            private_transfer,
            &mut self.rng,
        )
    }

    /// Builds a [`TransferPost`] for `reclaim`.
    #[inline]
    fn reclaim_post(
        &mut self,
        parameters: &Parameters<C>,
        proving_context: &ProvingContext<C>,
        reclaim: Reclaim<C>,
    ) -> Result<TransferPost<C>, SignError<C>> {
        Self::build_post(
            FullParameters::new(parameters, self.utxo_accumulator.model()),
            proving_context,
            reclaim,
            &mut self.rng,
        )
    }

    /// Computes the next [`Join`](Join) element for an asset rebalancing round.
    #[allow(clippy::type_complexity)] // NOTE: Clippy is too harsh here.
    #[inline]
    fn next_join(
        &mut self,
        parameters: &Parameters<C>,
        asset_id: AssetId,
        total: AssetValue,
    ) -> Result<([Receiver<C>; PrivateTransferShape::RECEIVERS], Join<C>), SignError<C>> {
        let keypair = self.accounts.get_default().default_keypair();
        Ok(Join::new(
            parameters,
            asset_id.with(total),
            &SpendingKey::new(keypair.spend, keypair.view),
            &mut self.rng,
        ))
    }

    /// Prepares the final pre-senders for the last part of the transaction.
    #[inline]
    fn prepare_final_pre_senders(
        &mut self,
        parameters: &Parameters<C>,
        proving_context: &MultiProvingContext<C>,
        asset_id: AssetId,
        mut new_zeroes: Vec<PreSender<C>>,
        pre_senders: &mut Vec<PreSender<C>>,
        posts: &mut Vec<TransferPost<C>>,
    ) -> Result<(), SignError<C>> {
        let mut needed_zeroes = PrivateTransferShape::SENDERS - pre_senders.len();
        if needed_zeroes == 0 {
            return Ok(());
        }
        let zeroes = self.assets.zeroes(needed_zeroes, asset_id);
        needed_zeroes -= zeroes.len();
        for zero in zeroes {
            let pre_sender = self.build_pre_sender(parameters, zero, Asset::zero(asset_id))?;
            pre_senders.push(pre_sender);
        }
        if needed_zeroes == 0 {
            return Ok(());
        }
        let needed_mints = needed_zeroes.saturating_sub(new_zeroes.len());
        for _ in 0..needed_zeroes {
            match new_zeroes.pop() {
                Some(zero) => pre_senders.push(zero),
                _ => break,
            }
        }
        if needed_mints == 0 {
            return Ok(());
        }
        for _ in 0..needed_mints {
            let (mint, pre_sender) = self.mint_zero(parameters, asset_id)?;
            posts.push(self.mint_post(parameters, &proving_context.mint, mint)?);
            pre_sender.insert_utxo(&mut self.utxo_accumulator);
            pre_senders.push(pre_sender);
        }
        Ok(())
    }

    /// Computes the batched transactions for rebalancing before a final transfer.
    #[inline]
    fn compute_batched_transactions(
        &mut self,
        parameters: &Parameters<C>,
        proving_context: &MultiProvingContext<C>,
        asset_id: AssetId,
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
                    s.try_upgrade(&self.utxo_accumulator)
                        .expect("Unable to upgrade expected UTXO.")
                });
                let (receivers, mut join) = self.next_join(
                    parameters,
                    asset_id,
                    senders.iter().map(Sender::asset_value).sum(),
                )?;
                posts.push(self.private_transfer_post(
                    parameters,
                    &proving_context.private_transfer,
                    PrivateTransfer::build(senders, receivers),
                )?);
                join.insert_utxos(&mut self.utxo_accumulator);
                joins.push(join.pre_sender);
                new_zeroes.append(&mut join.zeroes);
            }
            joins.append(&mut iter.remainder());
            pre_senders = joins;
        }
        self.prepare_final_pre_senders(
            parameters,
            proving_context,
            asset_id,
            new_zeroes,
            &mut pre_senders,
            posts,
        )?;
        Ok(into_array_unchecked(
            pre_senders
                .into_iter()
                .map(move |s| s.try_upgrade(&self.utxo_accumulator))
                .collect::<Option<Vec<_>>>()
                .expect("Unable to upgrade expected UTXOs."),
        ))
    }

    /// Prepares a given [`ReceivingKey`] for receiving `asset`.
    #[inline]
    fn prepare_receiver(
        &mut self,
        parameters: &Parameters<C>,
        asset: Asset,
        receiving_key: ReceivingKey<C>,
    ) -> Receiver<C> {
        receiving_key.into_receiver(parameters, self.rng.gen(), asset)
    }
}

impl<C> Clone for SignerState<C>
where
    C: Configuration,
    C::HierarchicalKeyDerivationScheme: Clone,
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
        proving_context: MultiProvingContext<C>,
        parameters: Parameters<C>,
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
        proving_context: MultiProvingContext<C>,
        parameters: Parameters<C>,
        utxo_accumulator: C::UtxoAccumulator,
        rng: C::Rng,
    ) -> Self {
        Self::new_inner(
            accounts,
            proving_context,
            parameters,
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
    ) -> Result<SyncResponse<C::Checkpoint>, SyncError<C::Checkpoint>> {
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
            let has_pruned = request.prune(checkpoint);
            let SyncData { receivers, senders } = request.data;
            let response = self.state.sync_with(
                &self.parameters.parameters,
                request.with_recovery,
                receivers.into_iter(),
                senders,
                !has_pruned,
            );
            self.state.utxo_accumulator.commit();
            Ok(response)
        }
    }

    /// Signs a withdraw transaction for `asset` sent to `receiver`.
    #[inline]
    fn sign_withdraw(
        &mut self,
        asset: Asset,
        receiver: Option<ReceivingKey<C>>,
    ) -> Result<SignResponse<C>, SignError<C>> {
        let selection = self.state.select(&self.parameters.parameters, asset)?;
        let change = self
            .state
            .build_receiver(&self.parameters.parameters, asset.id.with(selection.change))?;
        let mut posts = Vec::new();
        let senders = self.state.compute_batched_transactions(
            &self.parameters.parameters,
            &self.parameters.proving_context,
            asset.id,
            selection.pre_senders,
            &mut posts,
        )?;
        let final_post = match receiver {
            Some(receiver) => {
                let receiver =
                    self.state
                        .prepare_receiver(&self.parameters.parameters, asset, receiver);
                self.state.private_transfer_post(
                    &self.parameters.parameters,
                    &self.parameters.proving_context.private_transfer,
                    PrivateTransfer::build(senders, [change, receiver]),
                )?
            }
            _ => self.state.reclaim_post(
                &self.parameters.parameters,
                &self.parameters.proving_context.reclaim,
                Reclaim::build(senders, [change], asset),
            )?,
        };
        posts.push(final_post);
        Ok(SignResponse::new(posts))
    }

    /// Signs the `transaction`, generating transfer posts without releasing resources.
    #[inline]
    fn sign_internal(
        &mut self,
        transaction: Transaction<C>,
    ) -> Result<SignResponse<C>, SignError<C>> {
        match transaction {
            Transaction::Mint(asset) => {
                let receiver = self
                    .state
                    .build_receiver(&self.parameters.parameters, asset)?;
                Ok(SignResponse::new(vec![self.state.mint_post(
                    &self.parameters.parameters,
                    &self.parameters.proving_context.mint,
                    Mint::build(asset, receiver),
                )?]))
            }
            Transaction::PrivateTransfer(asset, receiver) => {
                self.sign_withdraw(asset, Some(receiver))
            }
            Transaction::Reclaim(asset) => self.sign_withdraw(asset, None),
        }
    }

    /// Signs the `transaction`, generating transfer posts.
    #[inline]
    pub fn sign(&mut self, transaction: Transaction<C>) -> Result<SignResponse<C>, SignError<C>> {
        let result = self.sign_internal(transaction);
        self.state.utxo_accumulator.rollback();
        result
    }

    /// Returns public receiving keys according to the `request`.
    #[inline]
    pub fn receiving_keys(&mut self, request: ReceivingKeyRequest) -> Vec<ReceivingKey<C>> {
        match request {
            ReceivingKeyRequest::Get { index } => self
                .state
                .accounts
                .get_default()
                .keypair(index)
                .into_iter()
                .map(|k| self.parameters.receiving_key(k))
                .collect(),
            ReceivingKeyRequest::GetAll => self
                .state
                .accounts
                .get_default()
                .keypairs()
                .map(|k| self.parameters.receiving_key(k))
                .collect(),
            ReceivingKeyRequest::New { count } => self
                .state
                .accounts
                .generate_keys(Default::default())
                .take(count)
                .map(|k| self.parameters.receiving_key(k))
                .collect(),
        }
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
        Result<SyncResponse<C::Checkpoint>, SyncError<C::Checkpoint>>,
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
    fn receiving_keys(
        &mut self,
        request: ReceivingKeyRequest,
    ) -> LocalBoxFutureResult<Vec<ReceivingKey<C>>, Self::Error> {
        Box::pin(async move { Ok(self.receiving_keys(request)) })
    }
}
