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
    asset::{AssetMap, AssetMetadata},
    key::{Account, AccountMap, LimitAccount},
    transfer::{
        self,
        batch::Join,
        canonical::{
            MultiProvingContext, PrivateTransfer, PrivateTransferShape, Selection, ToPrivate,
            ToPublic, Transaction,
        },
        requires_authorization, Address, Asset, FullParametersRef, Identifier, Metadata, Note,
        Nullifier, Parameters, PreSender, ProofSystemError, ProvingContext, Receiver, Sender,
        Shape, Transfer, TransferPost, Utxo, UtxoAccumulatorItem, UtxoAccumulatorModel,
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
    ) -> LocalBoxFutureResult<SyncResult<C, Self::Checkpoint>, Self::Error>;

    /// Signs a transaction and returns the ledger transfer posts if successful.
    fn sign(
        &mut self,
        request: SignRequest<C>,
    ) -> LocalBoxFutureResult<Result<SignResponse<C>, SignError<C>>, Self::Error>;

    /// Returns addresses according to the `request`.
    fn addresses(
        &mut self,
        request: AddressRequest,
    ) -> LocalBoxFutureResult<Vec<Address<C>>, Self::Error>;
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
/* TODO:
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
*/
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

/// Balance Update
/* TODO:
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
*/
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

/// Address Request
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AddressRequest {
    /// Get Specific Address
    ///
    /// Requests the address at the specific `index`. If the signer's response is an empty key
    /// vector, then the index was out of bounds.
    Get {
        /// Target Address Index
        index: u32,
    },

    /// Get All Addresses
    ///
    /// Requests all the addresses associated to the signer. The signer should always respond to
    /// this request with at least one address, the default address.
    GetAll,

    /// New Addresses
    ///
    /// Requests `count`-many new addresses. The signer should always respond with at most
    /// `count`-many addresses but may return fewer.
    New {
        /// Number of New Addresses to Generate
        count: usize,
    },
}

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
    fn prune(data: &mut SyncData<C>, origin: &Self, signer_checkpoint: &Self) -> bool;
}

/// Signer Configuration
pub trait Configuration: transfer::Configuration {
    /// Checkpoint Type
    type Checkpoint: Checkpoint<Self, UtxoAccumulator = Self::UtxoAccumulator>;

    /// Account Type
    type Account: Account<
        SpendingKey = Self::SpendingKey,
        Address = Address<Self>,
        Parameters = Self::Parameters,
    >;

    /// Account Map Type
    type AccountMap: AccountMap<Account = LimitAccount<Self::Account>>;

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
}

/// Signer State
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = r"
                C::AccountMap: Deserialize<'de>,
                C::UtxoAccumulator: Deserialize<'de>,
                C::AssetMap: Deserialize<'de>,
                C::Checkpoint: Deserialize<'de>
            ",
            serialize = r"
                C::AccountMap: Serialize,
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
    /// # Implementation Note
    ///
    /// For now, we only use the default account, and the rest of the storage data is related to
    /// this account. Eventually, we want to have a global `utxo_accumulator` for all accounts and
    /// a local `assets` map for each account.
    accounts: C::AccountMap,

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
        accounts: C::AccountMap,
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
    pub fn new(utxo_accumulator: C::UtxoAccumulator) -> Self {
        Self::build(
            C::AccountMap::new(),
            utxo_accumulator,
            Default::default(),
            FromEntropy::from_entropy(),
        )
    }

    /// Returns the default account for `self`.
    #[inline]
    fn default_account(&self) -> &LimitAccount<C::Account> {
        self.accounts.get_default()
    }

    /// Returns the default spending key for `self`.
    #[inline]
    fn default_spending_key(&self, parameters: &C::Parameters) -> C::SpendingKey {
        self.default_account().spending_key(parameters)
    }

    /// Returns the default address for the default account of `self`.
    #[inline]
    fn default_address(&mut self, parameters: &C::Parameters) -> Address<C> {
        self.accounts.get_mut_default().default_address(parameters)
    }

    ///
    #[inline]
    fn try_open<'h>(
        parameters: &C::Parameters,
        viewing_key: &(),
        note: Note<C>,
    ) -> Option<(Identifier<C>, Asset<C>)> {
        todo!()
    }

    /// Inserts the new `utxo`-`note` pair into the `utxo_accumulator` adding the spendable amount
    /// to `assets` if there is no void number to match it.
    #[inline]
    fn insert_next_item(
        utxo_accumulator: &mut C::UtxoAccumulator,
        assets: &mut C::AssetMap,
        parameters: &Parameters<C>,
        utxo: Utxo<C>,
        identifier: Identifier<C>,
        asset: Asset<C>,
        nullifiers: &mut Vec<Nullifier<C>>,
        deposit: &mut Vec<Asset<C>>,
    ) {
        /*
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
        */
        todo!()
    }

    /*
    /// Checks if `asset` matches with `nullifier`, removing it from the `utxo_accumulator` and
    /// inserting it into the `withdraw` set if this is the case.
    #[inline]
    fn is_asset_unspent(
        utxo_accumulator: &mut C::UtxoAccumulator,
        parameters: &Parameters<C>,
        secret_spend_key: &SecretKey<C>,
        ephemeral_secret_key: &SecretKey<C>,
        asset: Asset<C>,
        nullifiers: &mut Vec<Nullifier<C>>,
        withdraw: &mut Vec<Asset>,
    ) -> bool {
        let utxo = parameters.utxo(
            ephemeral_secret_key,
            &parameters.derive(secret_spend_key),
            &asset,
        );
        let nullifier = parameters.nullifiers(secret_spend_key, &utxo);
        if let Some(index) = nullifiers.iter().position(move |n| n == &nullifier) {
            nullifiers.remove(index);
            utxo_accumulator.remove_proof(&utxo);
            if !asset.is_zero() {
                withdraw.push(asset);
            }
            false
        } else {
            true
        }
    }
    */

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
        let viewing_key = ();
        for (utxo, note) in inserts {
            if let Some((identifier, asset)) = Self::try_open(parameters, &viewing_key, note) {
                Self::insert_next_item(
                    &mut self.utxo_accumulator,
                    &mut self.assets,
                    parameters,
                    utxo,
                    identifier,
                    asset,
                    &mut nullifiers,
                    &mut deposit,
                );
            } else {
                // FIXME: self.utxo_accumulator.insert_nonprovable(&utxo);
                todo!()
            }
        }
        self.assets.retain(|identifier, assets| {
            /*
            assets.retain(
                |asset| match self.accounts.get_default().spend_key(*index) {
                    Some(secret_spend_key) => {
                        /*
                        Self::is_asset_unspent(
                            &mut self.utxo_accumulator,
                            parameters,
                            &secret_spend_key,
                            ephemeral_secret_key,
                            *asset,
                            &mut void_numbers,
                            &mut withdraw,
                        )
                        */
                        todo!()
                    }
                    _ => true,
                },
            );
            */
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

    /// Builds the pre-sender associated to `key` and `asset`.
    #[inline]
    fn build_pre_sender(
        &mut self,
        parameters: &Parameters<C>,
        key: Identifier<C>,
        asset: Asset<C>,
    ) -> PreSender<C> {
        let default_spending_key = self.default_spending_key(parameters);
        /*
        PreSender::sample(
            parameters,
            default_spending_key.into(),
            key,
            asset,
            &mut self.rng,
        )
        */
        todo!()
    }

    ///
    #[inline]
    fn receiver(
        &mut self,
        parameters: &Parameters<C>,
        address: Address<C>,
        asset: Asset<C>,
        metadata: Metadata<C>,
    ) -> Receiver<C> {
        Receiver::<C>::sample(parameters, address, asset, metadata, &mut self.rng)
    }

    ///
    #[inline]
    fn default_receiver(&mut self, parameters: &Parameters<C>, asset: Asset<C>) -> Receiver<C> {
        let default_address = self.default_address(parameters);
        self.receiver(parameters, default_address, asset)
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
        spending_key: Option<&C::SpendingKey>,
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
        parameters: &SignerParameters<C>,
        proving_context: &ProvingContext<C>,
        transfer: Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>,
    ) -> Result<TransferPost<C>, SignError<C>> {
        let spending_key = self.default_spending_key();
        Self::build_post_inner(
            FullParametersRef::<C>::new(&parameters.parameters, self.utxo_accumulator.model()),
            &parameters.authorization_signature_scheme,
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
        /* TODO:
        let keypair = self.accounts.get_default().default_keypair();
        Ok(Join::new(
            parameters,
            asset_id.with(total),
            &SpendingKey::new(keypair.spend, keypair.view),
            &mut self.rng,
        ))
        */
        todo!()
    }

    /// Prepares the final pre-senders for the last part of the transaction.
    #[inline]
    fn prepare_final_pre_senders(
        &mut self,
        parameters: &Parameters<C>,
        proving_context: &MultiProvingContext<C>,
        asset_id: &C::AssetId,
        mut new_zeroes: Vec<PreSender<C>>,
        pre_senders: &mut Vec<PreSender<C>>,
        posts: &mut Vec<TransferPost<C>>,
    ) -> Result<(), SignError<C>> {
        /* FIXME: We need a new algorithm for this:
         *
         *
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
        */
        todo!()
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
                    senders.iter().map(|s| s.asset().value.clone()).sum(),
                )?;
                /*
                posts.push(self.build_post(
                    parameters,
                    &proving_context.private_transfer,
                    PrivateTransfer::build(senders, receivers),
                )?);
                */
                join.insert_utxos(parameters, &mut self.utxo_accumulator);
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
                .map(move |s| s.try_upgrade(parameters, &self.utxo_accumulator))
                .collect::<Option<Vec<_>>>()
                .expect("Unable to upgrade expected UTXOs."),
        ))
    }
}

impl<C> Clone for SignerState<C>
where
    C: Configuration,
    C::AccountMap: Clone,
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
        accounts: C::AccountMap,
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
        accounts: C::AccountMap,
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
            let has_pruned = request.prune(checkpoint);
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
        let final_post = match address {
            Some(address) => {
                let receiver = self
                    .state
                    .receiver(&self.parameters.parameters, address, asset);
                /*
                self.state.build_post(
                    &self.parameters.parameters,
                    &self.parameters.proving_context.private_transfer,
                    PrivateTransfer::build(senders, [change, receiver]),
                )?
                */
                todo!()
            }
            _ => {
                /*
                    self.state.build_post(
                    &self.parameters.parameters,
                    &self.parameters.proving_context.reclaim,
                    ToPublic::build(senders, [change], asset),
                )?
                    */
                todo!()
            }
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
            Transaction::ToPrivate(asset) => {
                let receiver = self
                    .state
                    .default_receiver(&self.parameters.parameters, asset.clone());
                Ok(SignResponse::new(vec![self.state.build_post(
                    &self.parameters,
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

    /// Returns addresses according to the `request`.
    #[inline]
    pub fn addresses(&mut self, request: AddressRequest) -> Vec<Address<C>> {
        let account = self.state.accounts.get_mut_default();
        match request {
            AddressRequest::Get { index } => vec![account.address(index.into())],
            AddressRequest::GetAll => account.iter_observed().collect(),
            AddressRequest::New { count } => account.iter_new().take(count).collect(),
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
    fn addresses(
        &mut self,
        request: AddressRequest,
    ) -> LocalBoxFutureResult<Vec<Address<C>>, Self::Error> {
        Box::pin(async move { Ok(self.addresses(request)) })
    }
}
