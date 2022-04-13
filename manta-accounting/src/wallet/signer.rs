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
// TODO:  Compress the `SyncResponse` data before sending (improves privacy and bandwidth).
// TODO:  Improve asynchronous interfaces internally in the signer, instead of just blocking
//        internally.

use crate::{
    asset::{Asset, AssetId, AssetMap, AssetMetadata, AssetValue},
    key::{self, HierarchicalKeyDerivationScheme, KeyIndex, SecretKeyPair, ViewKeySelection},
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
};
use alloc::{boxed::Box, vec, vec::Vec};
use core::{convert::Infallible, fmt::Debug, hash::Hash};
use manta_crypto::{
    accumulator::{Accumulator, ExactSizeAccumulator, OptimizedAccumulator},
    encryption::hybrid::DecryptedMessage,
    rand::{CryptoRng, FromEntropy, Rand, RngCore},
};
use manta_util::{
    array_map,
    cache::{CachedResource, CachedResourceError},
    future::LocalBoxFutureResult,
    into_array_unchecked,
    iter::IteratorExt,
    persistence::Rollback,
};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Signer Connection
pub trait Connection<C>
where
    C: transfer::Configuration,
{
    /// Error Type
    ///
    /// This is the error type for the connection itself, not for an error produced during one of
    /// the signer methods.
    type Error;

    /// Pushes updates from the ledger to the wallet, synchronizing it with the ledger state and
    /// returning an updated asset distribution.
    fn sync(
        &mut self,
        request: SyncRequest<C>,
    ) -> LocalBoxFutureResult<Result<SyncResponse, SyncError>, Self::Error>;

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

/// Signer Synchronization Request
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
pub struct SyncRequest<C>
where
    C: transfer::Configuration,
{
    /// Recovery Flag
    ///
    /// If `with_recovery` is set to `true`, the [`GAP_LIMIT`] is used during sync to perform a full
    /// recovery. See [`Configuration::HierarchicalKeyDerivationScheme`] for the scheme where the
    /// [`GAP_LIMIT`] is configured.
    ///
    /// [`GAP_LIMIT`]: HierarchicalKeyDerivationScheme::GAP_LIMIT
    pub with_recovery: bool,

    /// Starting Index
    ///
    /// This index is the starting point for insertions and indicates how far into the
    /// [`UtxoAccumulator`] the insertions received are starting from. The signer may be ahead of
    /// this index and so can skip those UTXOs which are in between the `starting_index` and its own
    /// internal index.
    ///
    /// [`UtxoAccumulator`]: Configuration::UtxoAccumulator
    pub starting_index: usize,

    /// Balance Insertions
    pub inserts: Vec<(Utxo<C>, EncryptedNote<C>)>,

    /// Balance Removals
    pub removes: Vec<VoidNumber<C>>,
}

/// Signer Synchronization Response
///
/// This `enum` is created by the [`sync`](Connection::sync) method on [`Connection`].
/// See its documentation for more.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum SyncResponse {
    /// Partial Update
    ///
    /// This is the typical response from the [`Signer`]. In rare cases, we may need to perform a
    /// [`Full`](Self::Full) update.
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
pub enum SyncError {
    /// Inconsistent Synchronization
    InconsistentSynchronization {
        /// Desired starting index to fix synchronization
        starting_index: usize,
    },
}

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
    /// Proving Context Cache Error
    ProvingContextCacheError,

    /// Insufficient Balance
    InsufficientBalance(Asset),

    /// Proof System Error
    ProofSystemError(ProofSystemError<C>),
}

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

/// Signer Configuration
pub trait Configuration: transfer::Configuration {
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

    /// Proving Context Cache
    type ProvingContextCache: CachedResource<MultiProvingContext<Self>>;

    /// Random Number Generator Type
    type Rng: CryptoRng + FromEntropy + RngCore;
}

/// Account Table Type
pub type AccountTable<C> = key::AccountTable<<C as Configuration>::HierarchicalKeyDerivationScheme>;

/// Asset Map Key Type
pub type AssetMapKey<C> = (KeyIndex, SecretKey<C>);

/// Proving Context Cache Error Type
pub type ProvingContextCacheError<C> =
    CachedResourceError<MultiProvingContext<C>, <C as Configuration>::ProvingContextCache>;

/// Signer Parameters
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "Parameters<C>: Clone, C::ProvingContextCache: Clone"),
    Debug(bound = "Parameters<C>: Debug, C::ProvingContextCache: Debug"),
    Eq(bound = "Parameters<C>: Eq, C::ProvingContextCache: Eq"),
    Hash(bound = "Parameters<C>: Hash, C::ProvingContextCache: Hash"),
    PartialEq(bound = "Parameters<C>: PartialEq, C::ProvingContextCache: PartialEq")
)]
pub struct SignerParameters<C>
where
    C: Configuration,
{
    /// Parameters
    pub parameters: Parameters<C>,

    /// Proving Context
    pub proving_context: C::ProvingContextCache,
}

impl<C> SignerParameters<C>
where
    C: Configuration,
{
    /// Builds a new [`SignerParameters`] from `parameters` and `proving_context`.
    #[inline]
    pub fn new(parameters: Parameters<C>, proving_context: C::ProvingContextCache) -> Self {
        Self {
            parameters,
            proving_context,
        }
    }

    /// Returns the public parameters by reading from the proving context cache.
    #[inline]
    pub fn get(
        &mut self,
    ) -> Result<(&Parameters<C>, &MultiProvingContext<C>), ProvingContextCacheError<C>> {
        let reading_key = self.proving_context.aquire()?;
        Ok((&self.parameters, self.proving_context.read(reading_key)))
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
                C::AssetMap: Deserialize<'de>
            ",
            serialize = r"
                AccountTable<C>: Serialize,
                C::UtxoAccumulator: Serialize,
                C::AssetMap: Serialize
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

    /// Random Number Generator
    #[cfg_attr(feature = "serde", serde(skip, default = "FromEntropy::from_entropy"))]
    rng: C::Rng,
}

impl<C> SignerState<C>
where
    C: Configuration,
{
    /// Builds a new [`SignerState`] from `keys`, `utxo_accumulator`, and `assets`.
    #[inline]
    fn build(
        accounts: AccountTable<C>,
        utxo_accumulator: C::UtxoAccumulator,
        assets: C::AssetMap,
    ) -> Self {
        Self {
            accounts,
            utxo_accumulator,
            assets,
            rng: FromEntropy::from_entropy(),
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
        )
    }

    /// Inserts the new `utxo`-`encrypted_note` pair if a known key can decrypt the note and
    /// validate the utxo.
    #[inline]
    fn insert_next_item(
        &mut self,
        parameters: &Parameters<C>,
        with_recovery: bool,
        utxo: Utxo<C>,
        encrypted_note: EncryptedNote<C>,
        void_numbers: &mut Vec<VoidNumber<C>>,
        deposit: &mut Vec<Asset>,
    ) -> Result<(), SyncError> {
        let mut finder = DecryptedMessage::find(encrypted_note);
        if let Some(ViewKeySelection {
            index,
            keypair,
            item,
        }) = self
            .accounts
            .get_mut_default()
            .find_index_with_maybe_gap(with_recovery, |k| {
                finder.decrypt(&parameters.note_encryption_scheme, k)
            })
        {
            let Note {
                ephemeral_secret_key,
                asset,
            } = item.plaintext;
            if let Some(void_number) =
                parameters.check_full_asset(&keypair.spend, &ephemeral_secret_key, &asset, &utxo)
            {
                if let Some(index) = void_numbers.iter().position(move |v| v == &void_number) {
                    void_numbers.remove(index);
                } else {
                    self.utxo_accumulator.insert(&utxo);
                    self.assets.insert((index, ephemeral_secret_key), asset);
                    if !asset.is_zero() {
                        deposit.push(asset);
                    }
                    return Ok(());
                }
            }
        }
        self.utxo_accumulator.insert_nonprovable(&utxo);
        Ok(())
    }

    /// Checks if `asset` matches with `void_number`, removing it from the `utxo_accumulator` and
    /// inserting it into the `withdraw` set if this is the case.
    #[inline]
    fn is_asset_unspent(
        parameters: &Parameters<C>,
        secret_spend_key: &SecretKey<C>,
        ephemeral_secret_key: &SecretKey<C>,
        asset: Asset,
        void_numbers: &mut Vec<VoidNumber<C>>,
        utxo_accumulator: &mut C::UtxoAccumulator,
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
    ) -> Result<SyncResponse, SyncError>
    where
        I: Iterator<Item = (Utxo<C>, EncryptedNote<C>)>,
    {
        let mut deposit = Vec::new();
        let mut withdraw = Vec::new();
        for (utxo, encrypted_note) in inserts {
            self.insert_next_item(
                parameters,
                with_recovery,
                utxo,
                encrypted_note,
                &mut void_numbers,
                &mut deposit,
            )?;
        }
        self.assets.retain(|(index, ephemeral_secret_key), assets| {
            assets.retain(
                |asset| match self.accounts.get_default().spend_key(*index) {
                    Some(secret_spend_key) => Self::is_asset_unspent(
                        parameters,
                        &secret_spend_key,
                        ephemeral_secret_key,
                        *asset,
                        &mut void_numbers,
                        &mut self.utxo_accumulator,
                        &mut withdraw,
                    ),
                    _ => true,
                },
            );
            !assets.is_empty()
        });
        // TODO: Whenever we are doing a full update, don't even build the `deposit` and `withdraw`
        //       vectors, since we won't be needing them.
        if is_partial {
            Ok(SyncResponse::Partial { deposit, withdraw })
        } else {
            Ok(SyncResponse::Full {
                assets: self.assets.assets().into(),
            })
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
        proving_context: C::ProvingContextCache,
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
            SignerState {
                accounts,
                utxo_accumulator,
                assets,
                rng,
            },
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
        proving_context: C::ProvingContextCache,
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
    pub fn sync(&mut self, request: SyncRequest<C>) -> Result<SyncResponse, SyncError> {
        // TODO: Do a capacity check on the current UTXO accumulator?
        //
        // if self.utxo_accumulator.capacity() < starting_index {
        //    panic!("full capacity")
        // }
        //
        let utxo_accumulator_len = self.state.utxo_accumulator.len();
        match utxo_accumulator_len.checked_sub(request.starting_index) {
            Some(diff) => {
                let result = self.state.sync_with(
                    &self.parameters.parameters,
                    request.with_recovery,
                    request.inserts.into_iter().skip(diff),
                    request.removes,
                    diff == 0,
                );
                self.state.utxo_accumulator.commit();
                result
            }
            _ => Err(SyncError::InconsistentSynchronization {
                starting_index: utxo_accumulator_len,
            }),
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
        let (parameters, proving_context) = self
            .parameters
            .get()
            .map_err(|_| SignError::ProvingContextCacheError)?;
        let mut posts = Vec::new();
        let senders = self.state.compute_batched_transactions(
            parameters,
            proving_context,
            asset.id,
            selection.pre_senders,
            &mut posts,
        )?;
        let final_post = match receiver {
            Some(receiver) => {
                let receiver = self.state.prepare_receiver(parameters, asset, receiver);
                self.state.private_transfer_post(
                    parameters,
                    &proving_context.private_transfer,
                    PrivateTransfer::build(senders, [change, receiver]),
                )?
            }
            _ => self.state.reclaim_post(
                parameters,
                &proving_context.reclaim,
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
                let (parameters, proving_context) = self
                    .parameters
                    .get()
                    .map_err(|_| SignError::ProvingContextCacheError)?;
                Ok(SignResponse::new(vec![self.state.mint_post(
                    parameters,
                    &proving_context.mint,
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
        // TODO: Should we do a time-based release mechanism to amortize the cost of reading
        //       from the proving context cache?
        let result = self.sign_internal(transaction);
        self.state.utxo_accumulator.rollback();
        self.parameters.proving_context.release();
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
    type Error = Infallible;

    #[inline]
    fn sync(
        &mut self,
        request: SyncRequest<C>,
    ) -> LocalBoxFutureResult<Result<SyncResponse, SyncError>, Self::Error> {
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
