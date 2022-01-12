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

//! Wallet Signer

// FIXME: Add wallet recovery i.e. remove the assumption that a new signer represents a completely
//        new derived secret key generator.
// TODO:  Should have a mode on the signer where we return a generic error which reveals no detail
//        about what went wrong during signing. The kind of error returned from a signing could
//        reveal information about the internal state (privacy leak, not a secrecy leak).
// TODO:  Setup multi-account wallets using `crate::key::AccountTable`.
// TODO:  Move `sync` to a stream-based algorithm instead of iterator-based.
// TODO:  Save/Load `SignerState` to/from disk.
// TODO:  Add self-destruct feature for clearing all secret and private data.
// TODO:  Compress the `SyncResponse` data before sending (improves privacy and bandwidth).
// TODO:  Should we split the errors into two groups, one for `sync` and one for `sign`?

use crate::{
    asset::{Asset, AssetId, AssetMap, AssetValue},
    key::{self, HierarchicalKeyDerivationScheme, ViewKeySelection},
    transfer::{
        self,
        batch::Join,
        canonical::{
            Mint, MultiProvingContext, PrivateTransfer, PrivateTransferShape, Reclaim, Selection,
            Shape, Transaction,
        },
        EncryptedNote, FullParameters, Parameters, PreSender, ProofSystemError, ProvingContext,
        PublicKey, Receiver, ReceivingKey, SecretKey, Sender, SpendingKey, Transfer, TransferPost,
        Utxo, VoidNumber,
    },
};
use alloc::{boxed::Box, vec, vec::Vec};
use core::{convert::Infallible, fmt::Debug};
use manta_crypto::{
    accumulator::{
        Accumulator, ConstantCapacityAccumulator, ExactSizeAccumulator, OptimizedAccumulator,
    },
    encryption::DecryptedMessage,
    rand::{CryptoRng, Rand, RngCore},
};
use manta_util::{
    cache::{CachedResource, CachedResourceError},
    fallible_array_map,
    future::LocalBoxFuture,
    into_array_unchecked,
    iter::IteratorExt,
    Rollback,
};

/// Signer Connection
pub trait Connection<C>
where
    C: transfer::Configuration,
{
    /// Key Index Type
    type KeyIndex;

    /// Error Type
    type Error;

    /// Pushes updates from the ledger to the wallet, synchronizing it with the ledger state and
    /// returning an updated asset distribution.
    fn sync<'s, I, R>(
        &'s mut self,
        starting_index: usize,
        inserts: I,
        removes: R,
    ) -> LocalBoxFuture<'s, SyncResult<C, Self>>
    where
        I: 's + IntoIterator<Item = (Utxo<C>, EncryptedNote<C>)>,
        R: 's + IntoIterator<Item = VoidNumber<C>>;

    /// Signs a `transaction` and returns the ledger transfer posts if successful.
    fn sign(&mut self, transaction: Transaction<C>) -> LocalBoxFuture<SignResult<C, Self>>;

    /// Returns a [`ReceivingKey`] for `self` to receive assets with `index`.
    fn receiving_key(
        &mut self,
        index: Self::KeyIndex,
    ) -> LocalBoxFuture<ReceivingKeyResult<C, Self>>;
}

/// Synchronization Result
///
/// See the [`sync`](Connection::sync) method on [`Connection`] for more.
pub type SyncResult<C, S> = Result<SyncResponse, <S as Connection<C>>::Error>;

/// Signing Result
///
/// See the [`sign`](Connection::sign) method on [`Connection`] for more.
pub type SignResult<C, S> = Result<SignResponse<C>, <S as Connection<C>>::Error>;

/// Receving Key Result
///
/// See the [`receiving_key`](Connection::receiving_key) method on [`Connection`] for more.
pub type ReceivingKeyResult<C, S> = Result<ReceivingKey<C>, <S as Connection<C>>::Error>;

/// Signer Synchronization Response
///
/// This `struct` is created by the [`sync`](Connection::sync) method on [`Connection`].
/// See its documentation for more.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct SyncResponse {
    /// Assets Deposited
    pub deposit: Vec<Asset>,

    /// Assets Withdrawn
    pub withdraw: Vec<Asset>,
}

impl SyncResponse {
    /// Builds a new [`SyncResponse`] from `deposit` and `withdraw`.
    #[inline]
    pub fn new(deposit: Vec<Asset>, withdraw: Vec<Asset>) -> Self {
        Self { deposit, withdraw }
    }
}

/// Signer Signing Response
///
/// This `struct` is created by the [`sign`](Connection::sign) method on [`Connection`].
/// See its documentation for more.
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

/// Signer Configuration
pub trait Configuration: transfer::Configuration {
    /// Hierarchical Key Derivation Scheme
    type HierarchicalKeyDerivationScheme: HierarchicalKeyDerivationScheme<
        SecretKey = SecretKey<Self>,
    >;

    /// [`Utxo`] Accumulator Type
    type UtxoSet: Accumulator<Item = Self::Utxo, Model = Self::UtxoSetModel>
        + ConstantCapacityAccumulator
        + ExactSizeAccumulator
        + OptimizedAccumulator
        + Rollback;

    /// Asset Map Type
    type AssetMap: AssetMap<Key = AssetMapKey<Self>>;

    /// Proving Context Cache
    type ProvingContextCache: CachedResource<MultiProvingContext<Self>>;

    /// Random Number Generator Type
    type Rng: CryptoRng + RngCore;
}

/// Index Type
pub type Index<C> = key::Index<<C as Configuration>::HierarchicalKeyDerivationScheme>;

/// Hierarchical Key Derivation Scheme Index
type HierarchicalKeyDerivationSchemeIndex<C> =
    <<C as Configuration>::HierarchicalKeyDerivationScheme as HierarchicalKeyDerivationScheme>::Index;

/// Account Table Type
pub type AccountTable<C> = key::AccountTable<<C as Configuration>::HierarchicalKeyDerivationScheme>;

/// Spend Index Type
pub type SpendIndex<C> = HierarchicalKeyDerivationSchemeIndex<C>;

/// View Index Type
pub type ViewIndex<C> = HierarchicalKeyDerivationSchemeIndex<C>;

/// Asset Map Key Type
pub type AssetMapKey<C> = (SpendIndex<C>, PublicKey<C>);

/// Proving Context Cache Error Type
pub type ProvingContextCacheError<C> =
    CachedResourceError<MultiProvingContext<C>, <C as Configuration>::ProvingContextCache>;

/// Signer Error
#[derive(derivative::Derivative)]
#[derivative(Debug(bound = r#"
    key::Error<C::HierarchicalKeyDerivationScheme>: Debug,
    ProvingContextCacheError<C>: Debug,
    ProofSystemError<C>: Debug,
    CE: Debug
"#))]
pub enum Error<C, CE = Infallible>
where
    C: Configuration,
{
    /// Hierarchical Key Derivation Scheme Error
    HierarchicalKeyDerivationSchemeError(key::Error<C::HierarchicalKeyDerivationScheme>),

    /// Proving Context Cache Error
    ProvingContextCacheError(ProvingContextCacheError<C>),

    /// Missing [`Utxo`] Membership Proof
    MissingUtxoMembershipProof,

    /// Insufficient Balance
    InsufficientBalance(Asset),

    /// Inconsistent Synchronization
    InconsistentSynchronization,

    /// Proof System Error
    ProofSystemError(ProofSystemError<C>),

    /// Signer Connection Error
    ConnectionError(CE),
}

impl<C, CE> From<key::Error<C::HierarchicalKeyDerivationScheme>> for Error<C, CE>
where
    C: Configuration,
{
    #[inline]
    fn from(err: key::Error<C::HierarchicalKeyDerivationScheme>) -> Self {
        Self::HierarchicalKeyDerivationSchemeError(err)
    }
}

/// Signer Parameters
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
    /// Returns the parameters by reading from the proving context cache.
    #[inline]
    pub async fn get(
        &mut self,
    ) -> Result<(&Parameters<C>, &MultiProvingContext<C>), ProvingContextCacheError<C>> {
        let reading_key = self.proving_context.aquire().await?;
        Ok((&self.parameters, self.proving_context.read(reading_key)))
    }
}

/// Signer State
struct SignerState<C>
where
    C: Configuration,
{
    /// Account Table
    ///
    /// # Note
    ///
    /// For now, we only use the default account, and the rest of the storage data is related to
    /// this account. Eventually, we want to have a global `utxo_set` for all accounts and a local
    /// `assets` map for each account.
    accounts: AccountTable<C>,

    /// UTXO Set
    utxo_set: C::UtxoSet,

    /// Asset Distribution
    assets: C::AssetMap,

    /// Random Number Generator
    rng: C::Rng,
}

impl<C> SignerState<C>
where
    C: Configuration,
{
    /// Inserts the new `utxo`-`encrypted_note` pair if a known key can decrypt the note and
    /// validate the utxo.
    #[inline]
    fn insert_next_item(
        &mut self,
        parameters: &Parameters<C>,
        utxo: Utxo<C>,
        encrypted_note: EncryptedNote<C>,
        void_numbers: &mut Vec<VoidNumber<C>>,
        deposit: &mut Vec<Asset>,
        withdraw: &mut Vec<Asset>,
    ) -> Result<(), Error<C>> {
        let mut finder = DecryptedMessage::find(encrypted_note);
        if let Some(ViewKeySelection {
            index,
            keypair,
            item:
                DecryptedMessage {
                    plaintext: asset,
                    ephemeral_public_key,
                },
        }) = self
            .accounts
            .get_default()
            .find_index(|k| finder.decrypt(&parameters.key_agreement, k))
            .map_err(key::Error::KeyDerivationError)?
        {
            if let Some(void_number) = C::check_full_asset(
                parameters,
                &keypair.spend,
                &ephemeral_public_key,
                &asset,
                &utxo,
            ) {
                if let Some(void_number_index) =
                    void_numbers.iter().position(move |v| v == &void_number)
                {
                    void_numbers.remove(void_number_index);
                    self.utxo_set.remove_proof(&utxo);
                    self.assets
                        .remove((index.spend, ephemeral_public_key), asset);
                    withdraw.push(asset);
                } else {
                    self.utxo_set.insert(&utxo);
                    self.assets
                        .insert((index.spend, ephemeral_public_key), asset);
                    deposit.push(asset);
                    return Ok(());
                }
            }
        }
        self.utxo_set.insert_nonprovable(&utxo);
        Ok(())
    }

    /// Updates the internal ledger state, returning the new asset distribution.
    #[inline]
    fn sync_with<I>(
        &mut self,
        parameters: &Parameters<C>,
        inserts: I,
        mut void_numbers: Vec<VoidNumber<C>>,
    ) -> SyncResult<C, Signer<C>>
    where
        I: Iterator<Item = (Utxo<C>, EncryptedNote<C>)>,
    {
        // TODO: Do this loop in parallel.
        let mut deposit = Vec::new();
        let mut withdraw = Vec::new();
        for (utxo, encrypted_note) in inserts {
            self.insert_next_item(
                parameters,
                utxo,
                encrypted_note,
                &mut void_numbers,
                &mut deposit,
                &mut withdraw,
            )?;
        }

        for void_number in void_numbers {
            // FIXME: Use default account method like everywhere else.
            self.assets
                .remove_if(|(index, ephemeral_public_key), assets| {
                    assets.iter().any(
                        |asset| match self.accounts.get_default().spend_key(*index) {
                            Ok(secret_key) => {
                                let utxo = C::utxo(
                                    &parameters.key_agreement,
                                    &parameters.utxo_commitment,
                                    &secret_key,
                                    ephemeral_public_key,
                                    asset,
                                );
                                let known_void_number = C::void_number(
                                    &parameters.void_number_hash,
                                    &utxo,
                                    &secret_key,
                                );
                                if void_number == known_void_number {
                                    self.utxo_set.remove_proof(&utxo);
                                    withdraw.push(*asset);
                                    true
                                } else {
                                    false
                                }
                            }
                            _ => false,
                        },
                    )
                });
        }

        self.utxo_set.commit();
        Ok(SyncResponse::new(deposit, withdraw))
    }

    /// Builds the pre-sender associated to `key` and `asset`.
    #[inline]
    fn build_pre_sender(
        &self,
        parameters: &Parameters<C>,
        key: AssetMapKey<C>,
        asset: Asset,
    ) -> Result<PreSender<C>, Error<C>> {
        let (spend_index, ephemeral_key) = key;
        Ok(PreSender::new(
            parameters,
            self.accounts.get_default().spend_key(spend_index)?,
            ephemeral_key,
            asset,
        ))
    }

    /// Builds the receiver for `asset`.
    #[inline]
    fn build_receiver(
        &mut self,
        parameters: &Parameters<C>,
        asset: Asset,
    ) -> Result<Receiver<C>, Error<C>> {
        let keypair = self
            .accounts
            .get_default()
            .default_keypair()
            .map_err(key::Error::KeyDerivationError)?;
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
    ) -> Result<(Mint<C>, PreSender<C>), Error<C>> {
        let asset = Asset::zero(asset_id);
        let keypair = self
            .accounts
            .get_default()
            .default_keypair()
            .map_err(key::Error::KeyDerivationError)?;
        let (receiver, pre_sender) = SpendingKey::new(keypair.spend, keypair.view).internal_pair(
            parameters,
            self.rng.gen(),
            asset,
        );
        Ok((Mint::build(asset, receiver), pre_sender))
    }

    /// Selects the pre-senders which collectively own at least `asset`, returning any change.
    #[inline]
    fn select(
        &mut self,
        parameters: &Parameters<C>,
        asset: Asset,
    ) -> Result<Selection<C>, Error<C>> {
        let selection = self.assets.select(asset);
        if selection.is_empty() {
            return Err(Error::InsufficientBalance(asset));
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
    ) -> Result<TransferPost<C>, Error<C>> {
        transfer
            .into_post(parameters, proving_context, rng)
            .map_err(Error::ProofSystemError)
    }

    /// Mints an asset with zero value for the given `asset_id`, returning the appropriate
    /// Builds a [`TransferPost`] for `mint`.
    #[inline]
    fn mint_post(
        &mut self,
        parameters: &Parameters<C>,
        proving_context: &ProvingContext<C>,
        mint: Mint<C>,
    ) -> Result<TransferPost<C>, Error<C>> {
        Self::build_post(
            FullParameters::new(parameters, self.utxo_set.model()),
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
    ) -> Result<TransferPost<C>, Error<C>> {
        Self::build_post(
            FullParameters::new(parameters, self.utxo_set.model()),
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
    ) -> Result<TransferPost<C>, Error<C>> {
        Self::build_post(
            FullParameters::new(parameters, self.utxo_set.model()),
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
    ) -> Result<([Receiver<C>; PrivateTransferShape::RECEIVERS], Join<C>), Error<C>> {
        let keypair = self
            .accounts
            .get_default()
            .default_keypair()
            .map_err(key::Error::KeyDerivationError)?;
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
    ) -> Result<(), Error<C>> {
        let mut needed_zeroes = PrivateTransferShape::SENDERS - pre_senders.len();
        if needed_zeroes == 0 {
            return Ok(());
        }
        let zeroes = self.assets.zeroes(needed_zeroes, asset_id);
        needed_zeroes -= zeroes.len();
        for zero in zeroes {
            let pre_sender = self.build_pre_sender(parameters, zero, Asset::zero(asset_id))?;
            pre_sender.insert_utxo(&mut self.utxo_set);
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
            pre_sender.insert_utxo(&mut self.utxo_set);
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
    ) -> Result<[Sender<C>; PrivateTransferShape::SENDERS], Error<C>> {
        assert!(
            !pre_senders.is_empty(),
            "The set of initial senders cannot be empty."
        );
        let mut new_zeroes = Vec::new();
        while pre_senders.len() > PrivateTransferShape::SENDERS {
            let mut joins = Vec::new();
            let mut iter = pre_senders
                .into_iter()
                .chunk_by::<{ PrivateTransferShape::SENDERS }>();
            for chunk in &mut iter {
                let senders = fallible_array_map(chunk, |s| {
                    s.try_upgrade(&self.utxo_set)
                        .ok_or(Error::MissingUtxoMembershipProof)
                })?;
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
                join.insert_utxos(&mut self.utxo_set);
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
                .map(move |s| s.try_upgrade(&self.utxo_set))
                .collect::<Option<Vec<_>>>()
                .ok_or(Error::MissingUtxoMembershipProof)?,
        ))
    }

    /// Prepares a given [`ReceivingKey`] for receiving `asset`.
    #[inline]
    fn prepare_receiver(
        &mut self,
        parameters: &Parameters<C>,
        asset: Asset,
        receiver: ReceivingKey<C>,
    ) -> Receiver<C> {
        receiver.into_receiver(parameters, self.rng.gen(), asset)
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
    /// Builds a new [`Signer`].
    #[inline]
    fn new_inner(
        accounts: AccountTable<C>,
        proving_context: C::ProvingContextCache,
        parameters: Parameters<C>,
        utxo_set: C::UtxoSet,
        assets: C::AssetMap,
        rng: C::Rng,
    ) -> Self {
        Self {
            parameters: SignerParameters {
                parameters,
                proving_context,
            },
            state: SignerState {
                accounts,
                utxo_set,
                assets,
                rng,
            },
        }
    }

    /// Builds a new [`Signer`] from a fresh set of `accounts`.
    ///
    /// # Warning
    ///
    /// This method assumes that `accounts` has never been used before, and does not attempt
    /// to perform wallet recovery on this table.
    //
    //  FIXME: Check that this warning even makes sense.
    #[inline]
    pub fn new(
        accounts: AccountTable<C>,
        proving_context: C::ProvingContextCache,
        parameters: Parameters<C>,
        utxo_set: C::UtxoSet,
        rng: C::Rng,
    ) -> Self {
        Self::new_inner(
            accounts,
            proving_context,
            parameters,
            utxo_set,
            Default::default(),
            rng,
        )
    }

    /// Updates the internal ledger state, returning the new asset distribution.
    #[inline]
    pub fn sync<I, R>(
        &mut self,
        starting_index: usize,
        inserts: I,
        removes: R,
    ) -> SyncResult<C, Self>
    where
        I: IntoIterator<Item = (Utxo<C>, EncryptedNote<C>)>,
        R: IntoIterator<Item = VoidNumber<C>>,
    {
        // FIXME: Do a capacity check on the current UTXO set?
        //
        // if self.utxo_set.capacity() < starting_index {
        //    panic!("something is very wrong here")
        // }
        //
        // TODO: Use a smarter object than `Vec` for `removes.into_iter().collect()` like a
        //       `HashSet` or some other set-like container with fast membership and remove ops.
        //
        match self.state.utxo_set.len().checked_sub(starting_index) {
            Some(diff) => self.state.sync_with(
                &self.parameters.parameters,
                inserts.into_iter().skip(diff),
                removes.into_iter().collect(),
            ),
            _ => Err(Error::InconsistentSynchronization),
        }
    }

    /// Signs a withdraw transaction for `asset` sent to `receiver`.
    #[inline]
    async fn sign_withdraw(
        &mut self,
        asset: Asset,
        receiver: Option<ReceivingKey<C>>,
    ) -> SignResult<C, Self> {
        let selection = self.state.select(&self.parameters.parameters, asset)?;
        let change = self
            .state
            .build_receiver(&self.parameters.parameters, asset.id.with(selection.change))?;
        let (parameters, proving_context) = self
            .parameters
            .get()
            .await
            .map_err(Error::ProvingContextCacheError)?;
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
        self.state.utxo_set.rollback();
        Ok(SignResponse::new(posts))
    }

    /// Signs the `transaction`, generating transfer posts without releasing resources.
    #[inline]
    async fn sign_internal(&mut self, transaction: Transaction<C>) -> SignResult<C, Self> {
        match transaction {
            Transaction::Mint(asset) => {
                let receiver = self
                    .state
                    .build_receiver(&self.parameters.parameters, asset)?;
                let (parameters, proving_context) = self
                    .parameters
                    .get()
                    .await
                    .map_err(Error::ProvingContextCacheError)?;
                Ok(SignResponse::new(vec![self.state.mint_post(
                    parameters,
                    &proving_context.mint,
                    Mint::build(asset, receiver),
                )?]))
            }
            Transaction::PrivateTransfer(asset, receiver) => {
                self.sign_withdraw(asset, Some(receiver)).await
            }
            Transaction::Reclaim(asset) => self.sign_withdraw(asset, None).await,
        }
    }

    /// Signs the `transaction`, generating transfer posts.
    #[inline]
    pub async fn sign(&mut self, transaction: Transaction<C>) -> SignResult<C, Self> {
        // TODO: Should we do a time-based release mechanism to amortize the cost of reading/writing
        //       to disk?
        let result = self.sign_internal(transaction).await;
        self.parameters.proving_context.release().await;
        result
    }

    /// Returns a [`ReceivingKey`] for `self` to receive assets with `index`.
    #[inline]
    fn compute_receiving_key(&self, index: Index<C>) -> ReceivingKeyResult<C, Self> {
        let keypair = self.state.accounts.get_default().keypair(index)?;
        Ok(SpendingKey::new(keypair.spend, keypair.view)
            .derive(&self.parameters.parameters.key_agreement))
    }
}

impl<C> Connection<C> for Signer<C>
where
    C: Configuration,
{
    type KeyIndex = Index<C>;
    type Error = Error<C>;

    #[inline]
    fn sync<'s, I, R>(
        &'s mut self,
        starting_index: usize,
        inserts: I,
        removes: R,
    ) -> LocalBoxFuture<'s, SyncResult<C, Self>>
    where
        I: 's + IntoIterator<Item = (Utxo<C>, EncryptedNote<C>)>,
        R: 's + IntoIterator<Item = VoidNumber<C>>,
    {
        Box::pin(async move { self.sync(starting_index, inserts, removes) })
    }

    #[inline]
    fn sign(&mut self, transaction: Transaction<C>) -> LocalBoxFuture<SignResult<C, Self>> {
        Box::pin(self.sign(transaction))
    }

    #[inline]
    fn receiving_key(&mut self, index: Index<C>) -> LocalBoxFuture<ReceivingKeyResult<C, Self>> {
        Box::pin(async move { self.compute_receiving_key(index) })
    }
}
