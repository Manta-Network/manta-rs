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

// TODO: Use universal transfers instead of just the canonical ones.

use crate::{
    asset::{Asset, AssetBalance, AssetId, AssetMap},
    fs::{Load, LoadWith, Save, SaveWith},
    identity::{self, Identity, PreSender, Utxo},
    keys::{
        Account, DerivedSecretKeyGenerator, ExternalIndex, Index, InternalIndex, InternalKeyOwned,
        KeyOwned,
    },
    transfer::{
        self,
        canonical::{Mint, PrivateTransfer, Reclaim, Transaction},
        EncryptedAsset, IntegratedEncryptionSchemeError, InternalReceiver, ProofSystemError,
        ProvingContext, Receiver, SecretTransfer, Sender, ShieldedIdentity, Transfer, TransferPost,
    },
};
use alloc::{vec, vec::Vec};
use core::{
    convert::Infallible,
    fmt::Debug,
    future::{self, Future, Ready},
    hash::Hash,
    mem,
    ops::Range,
};
use manta_crypto::{
    rand::{CryptoRng, RngCore},
    set::VerifiedSet,
};
use manta_util::{fallible_array_map, into_array_unchecked, iter::IteratorExt};

/// Rollback Trait
pub trait Rollback {
    /// Commits `self` to the current state.
    ///
    /// # Implementation Note
    ///
    /// Commiting to the current state must be idempotent. Calling [`rollback`](Self::rollback)
    /// after [`commit`](Self::commit) must not change the state after the call to
    /// [`commit`](Self::commit).
    fn commit(&mut self);

    /// Rolls back `self` to the previous state.
    ///
    /// # Implementation Note
    ///
    /// Rolling back to the previous state must be idempotent. Calling [`commit`](Self::commit)
    /// after [`rollback`](Self::rollback) must not change the state after the call to
    /// [`rollback`](Self::rollback).
    fn rollback(&mut self);
}

/// Signer Connection
pub trait Connection<D, C>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
{
    /// Sync Future Type
    ///
    /// Future for the [`sync`](Self::sync) method.
    type SyncFuture: Future<Output = SyncResult<D, C, Self>>;

    /// Sign Future Type
    ///
    /// Future for the [`sign`](Self::sign) method.
    type SignFuture: Future<Output = SignResult<D, C, Self>>;

    /// Sign Commit Future Type
    ///
    /// Future for the [`commit`](Self::commit) method.
    type CommitFuture: Future<Output = Result<(), Self::Error>>;

    /// Sign Rollback Future Type
    ///
    /// Future for the [`rollback`](Self::rollback) method.
    type RollbackFuture: Future<Output = Result<(), Self::Error>>;

    /// External Receiver Future Type
    ///
    /// Future for the [`external_receiver`](Self::external_receiver) method.
    type ExternalReceiverFuture: Future<Output = ExternalReceiverResult<D, C, Self>>;

    /// Error Type
    type Error;

    /// Pushes updates from the ledger to the wallet, synchronizing it with the ledger state and
    /// returning an updated asset distribution. Depending on the `sync_state`, the signer will
    /// either commit to the current state before synchronizing or rollback to the previous state.
    fn sync<I>(
        &mut self,
        sync_state: SyncState,
        starting_index: usize,
        updates: I,
    ) -> Self::SyncFuture
    where
        I: IntoIterator<Item = (Utxo<C>, EncryptedAsset<C>)>;

    /// Signs a `transaction` and returns the ledger transfer posts if successful.
    ///
    /// # Safety
    ///
    /// To preserve consistency, calls to [`sign`](Self::sign) should be followed by a call to
    /// either [`commit`](Self::commit), [`rollback`](Self::rollback), or [`sync`](Self::sync) with
    /// the appropriate [`SyncState`]. Repeated calls to [`sign`](Self::sign) should automatically
    /// commit the current state before signing.
    ///
    /// See the [`Rollback`] trait for expectations on the behavior of [`commit`](Self::commit)
    /// and [`rollback`](Self::rollback).
    fn sign(&mut self, transaction: Transaction<C>) -> Self::SignFuture;

    /// Commits to the state after the last call to [`sign`](Self::sign).
    ///
    /// See the [`Rollback`] trait for expectations on the behavior of [`commit`](Self::commit).
    fn commit(&mut self) -> Self::CommitFuture;

    /// Rolls back to the state before the last call to [`sign`](Self::sign).
    ///
    /// See the [`Rollback`] trait for expectations on the behavior of [`rollback`](Self::rollback).
    fn rollback(&mut self) -> Self::RollbackFuture;

    /// Generates a new [`ShieldedIdentity`] for `self` to receive assets.
    ///
    /// # Note
    ///
    /// This method does not interact with the other methods on [`Connection`] so it can be called
    /// at any point in between calls to [`sync`](Self::sync), [`sign`](Self::sign), and other
    /// rollback related methods.
    fn external_receiver(&mut self) -> Self::ExternalReceiverFuture;
}

/// Synchronization State
///
/// This `enum` is used by the [`sync`](Connection::sync) method on [`Connection`]. See its
/// documentation for more.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SyncState {
    /// Should commit the current state before synchronizing
    Commit,

    /// Should rollback to the previous state before synchronizing
    Rollback,
}

/// Synchronization Result
///
/// See the [`sync`](Connection::sync) method on [`Connection`] for more information.
pub type SyncResult<D, C, S> = Result<SyncResponse, Error<D, C, <S as Connection<D, C>>::Error>>;

/// Signing Result
///
/// See the [`sign`](Connection::sign) method on [`Connection`] for more information.
pub type SignResult<D, C, S> = Result<SignResponse<C>, Error<D, C, <S as Connection<D, C>>::Error>>;

/// External Receiver Generation Result
///
/// See the [`external_receiver`](Connection::external_receiver) method on [`Connection`] for more
/// information.
pub type ExternalReceiverResult<D, C, S> =
    Result<ShieldedIdentity<C>, Error<D, C, <S as Connection<D, C>>::Error>>;

/// Signer Synchronization Response
///
/// This `struct` is created by the [`sync`](Connection::sync) method on [`Connection`].
/// See its documentation for more.
pub struct SyncResponse {
    /// Updates to the Asset Distribution
    pub assets: Vec<Asset>,
}

impl SyncResponse {
    /// Builds a new [`SyncResponse`] from `assets`.
    #[inline]
    pub fn new(assets: Vec<Asset>) -> Self {
        Self { assets }
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

/// Signer Error
pub enum Error<D, C, CE = Infallible>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
{
    /// Secret Key Generation Error
    SecretKeyError(D::Error),

    /// Encryption Error
    EncryptionError(IntegratedEncryptionSchemeError<C>),

    /// Missing [`Utxo`] Membership Proof
    MissingUtxoMembershipProof,

    /// Insufficient Balance
    InsufficientBalance(Asset),

    /// Proof System Error
    ProofSystemError(ProofSystemError<C>),

    /// Inconsistent Synchronization State
    InconsistentSynchronization,

    /// Signer Connection Error
    ConnectionError(CE),
}

impl<D, C, CE> From<InternalReceiverError<D, C>> for Error<D, C, CE>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
{
    #[inline]
    fn from(err: InternalReceiverError<D, C>) -> Self {
        match err {
            InternalReceiverError::SecretKeyError(err) => Self::SecretKeyError(err),
            InternalReceiverError::EncryptionError(err) => Self::EncryptionError(err),
        }
    }
}

/// Signer
pub struct Signer<D>
where
    D: DerivedSecretKeyGenerator,
{
    /// Secret Key Source
    secret_key_source: D,

    /// Signer Account
    account: Account<D>,
}

impl<D> Signer<D>
where
    D: DerivedSecretKeyGenerator,
{
    /// Builds a new [`Signer`] for `account` from a `secret_key_source`.
    #[inline]
    pub fn new(secret_key_source: D, account: D::Account) -> Self {
        Self::with_account(secret_key_source, Account::new(account))
    }

    /// Builds a new [`Signer`] for `account` from a `secret_key_source`.
    #[inline]
    pub fn with_account(secret_key_source: D, account: Account<D>) -> Self {
        Self {
            secret_key_source,
            account,
        }
    }

    /// Builds a new [`Signer`] for `account` from a `secret_key_source` with starting ranges
    /// `external_indices` and `internal_indices`.
    #[inline]
    pub fn with_ranges(
        secret_key_source: D,
        account: D::Account,
        external_indices: Range<D::Index>,
        internal_indices: Range<D::Index>,
    ) -> Self {
        Self::with_account(
            secret_key_source,
            Account::with_ranges(account, external_indices, internal_indices),
        )
    }

    /// Returns the next [`Signer`] after `self`, incrementing the account number.
    #[inline]
    pub fn next(self) -> Self {
        Self::with_account(self.secret_key_source, self.account.next())
    }

    /// Returns the identity for a key of the given `index`.
    #[inline]
    pub fn get<C>(&self, index: &Index<D>) -> Result<Identity<C>, D::Error>
    where
        C: identity::Configuration<SecretKey = D::SecretKey>,
    {
        index
            .key(&self.secret_key_source, self.account.as_ref())
            .map(Identity::new)
    }

    /// Returns the identity for an external key of the given `index`.
    #[inline]
    pub fn get_external<C>(&self, index: &ExternalIndex<D>) -> Result<Identity<C>, D::Error>
    where
        C: identity::Configuration<SecretKey = D::SecretKey>,
    {
        index
            .key(&self.secret_key_source, self.account.as_ref())
            .map(Identity::new)
    }

    /// Returns the identity for an internal key of the given `index`.
    #[inline]
    pub fn get_internal<C>(&self, index: &InternalIndex<D>) -> Result<Identity<C>, D::Error>
    where
        C: identity::Configuration<SecretKey = D::SecretKey>,
    {
        index
            .key(&self.secret_key_source, self.account.as_ref())
            .map(Identity::new)
    }

    /// Returns a [`PreSender`] for the key at the given `index`.
    #[inline]
    pub fn get_pre_sender<C>(
        &self,
        index: Index<D>,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
    ) -> Result<PreSender<C>, D::Error>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
    {
        Ok(self.get(&index)?.into_pre_sender(commitment_scheme, asset))
    }

    /// Generates the next external identity for this signer.
    #[inline]
    fn next_external_identity<C>(&mut self) -> Result<Identity<C>, D::Error>
    where
        C: identity::Configuration<SecretKey = D::SecretKey>,
    {
        Ok(self
            .account
            .next_external_key(&self.secret_key_source)?
            .map(Identity::new)
            .unwrap())
    }

    /// Generates the next internal identity for this signer.
    #[inline]
    fn next_internal_identity<C>(&mut self) -> Result<InternalKeyOwned<D, Identity<C>>, D::Error>
    where
        C: identity::Configuration<SecretKey = D::SecretKey>,
    {
        Ok(self
            .account
            .next_internal_key(&self.secret_key_source)?
            .map(Identity::new))
    }

    /// Generates a new [`ShieldedIdentity`] to receive assets to this account via an external
    /// transaction.
    #[inline]
    pub fn next_shielded<C>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
    ) -> Result<ShieldedIdentity<C>, D::Error>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
    {
        Ok(self
            .next_external_identity()?
            .into_shielded(commitment_scheme))
    }

    /// Builds the next zero accumulator receivers and pre-senders.
    #[inline]
    fn next_zeroes<C, R, const RECEIVERS: usize>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
        asset_id: AssetId,
        rng: &mut R,
    ) -> Result<
        (Vec<Receiver<C>>, Vec<InternalKeyOwned<D, PreSender<C>>>),
        InternalReceiverError<D, C>,
    >
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        R: CryptoRng + RngCore + ?Sized,
    {
        let mut receivers = Vec::with_capacity(RECEIVERS);
        let mut pre_senders = Vec::with_capacity(RECEIVERS - 1);
        for _ in 0..RECEIVERS - 1 {
            let (identity, index) = self
                .next_internal_identity()
                .map_err(InternalReceiverError::SecretKeyError)?
                .into();
            let internal_receiver = identity
                .into_internal_receiver(commitment_scheme, Asset::zero(asset_id), rng)
                .map_err(InternalReceiverError::EncryptionError)?;
            receivers.push(internal_receiver.receiver);
            pre_senders.push(KeyOwned::new(internal_receiver.pre_sender, index));
        }
        Ok((receivers, pre_senders))
    }

    /// Builds the next accumulator receiver and pre-sender.
    #[inline]
    fn next_accumulator<C, R>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        rng: &mut R,
    ) -> Result<InternalReceiver<C>, InternalReceiverError<D, C>>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        R: CryptoRng + RngCore + ?Sized,
    {
        self.next_internal_identity()
            .map_err(InternalReceiverError::SecretKeyError)?
            .unwrap()
            .into_internal_receiver(commitment_scheme, asset, rng)
            .map_err(InternalReceiverError::EncryptionError)
    }

    /// Builds the next accumulated receiver.
    #[inline]
    pub fn next_accumulated_receiver<C, R, const RECEIVERS: usize>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
        asset_id: AssetId,
        sender_sum: AssetBalance,
        rng: &mut R,
    ) -> Result<
        (
            [Receiver<C>; RECEIVERS],
            PreSender<C>,
            Vec<InternalKeyOwned<D, PreSender<C>>>,
        ),
        InternalReceiverError<D, C>,
    >
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        R: CryptoRng + RngCore + ?Sized,
    {
        let (mut receivers, zero_pre_senders) =
            self.next_zeroes::<_, _, RECEIVERS>(commitment_scheme, asset_id, rng)?;
        let internal_receiver =
            self.next_accumulator(commitment_scheme, asset_id.with(sender_sum), rng)?;
        receivers.push(internal_receiver.receiver);
        Ok((
            into_array_unchecked(receivers),
            internal_receiver.pre_sender,
            zero_pre_senders,
        ))
    }

    /// Builds the change receiver for the end of a transaction.
    #[inline]
    pub fn next_change<C, R>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        rng: &mut R,
    ) -> Result<InternalKeyOwned<D, Receiver<C>>, InternalReceiverError<D, C>>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        R: CryptoRng + RngCore + ?Sized,
    {
        // TODO: Simplify this so that `into_shielded` and `into_receiver` can be replaced by a
        //       one-step `into_receiver` call on `Identity`.
        self.next_internal_identity()
            .map_err(InternalReceiverError::SecretKeyError)?
            .map_ok(move |identity| {
                identity.into_shielded(commitment_scheme).into_receiver(
                    commitment_scheme,
                    asset,
                    rng,
                )
            })
            .map_err(InternalReceiverError::EncryptionError)
    }

    /// Builds a [`Mint`] transaction to mint `asset` and returns the index for that asset.
    #[inline]
    pub fn mint<C, R>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        rng: &mut R,
    ) -> Result<(Mint<C>, InternalIndex<D>), InternalReceiverError<D, C>>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        R: CryptoRng + RngCore + ?Sized,
    {
        let (identity, index) = self
            .next_internal_identity()
            .map_err(InternalReceiverError::SecretKeyError)?
            .into();
        Ok((
            Mint::from_identity(identity, commitment_scheme, asset, rng)
                .map_err(InternalReceiverError::EncryptionError)?,
            index,
        ))
    }

    /// Builds a [`Mint`] transaction to mint a zero asset with the given `asset_id`, returning a
    /// [`PreSender`] for that asset.
    #[inline]
    pub fn mint_zero<C, R>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
        asset_id: AssetId,
        rng: &mut R,
    ) -> Result<(Mint<C>, PreSender<C>), InternalReceiverError<D, C>>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        R: CryptoRng + RngCore + ?Sized,
    {
        Mint::zero(
            self.next_internal_identity()
                .map_err(InternalReceiverError::SecretKeyError)?
                .unwrap(),
            commitment_scheme,
            asset_id,
            rng,
        )
        .map_err(InternalReceiverError::EncryptionError)
    }

    /// Looks for an index that can decrypt the given `encrypted_asset`.
    #[inline]
    pub fn find_external_asset<C>(
        &mut self,
        encrypted_asset: &EncryptedAsset<C>,
    ) -> Option<(Index<D>, Asset)>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
    {
        // FIXME: Simplify this implementation.
        let open_spend = self
            .account
            .external_keys(&self.secret_key_source)
            .find_map(move |ek| {
                ek.map(move |ek| {
                    ek.map(move |k| Identity::<C>::new(k).try_open(encrypted_asset))
                        .ok()
                })
                .ok()
                .flatten()
            })?;
        self.account
            .conditional_increment_external_range(&open_spend.index.index);
        Some((open_spend.index.reduce(), open_spend.value.into_asset()))
    }
}

impl<D> Load for Signer<D>
where
    D: DerivedSecretKeyGenerator + LoadWith<Account<D>>,
{
    type Path = D::Path;

    type LoadingKey = D::LoadingKey;

    type Error = <D as Load>::Error;

    #[inline]
    fn load<P>(path: P, loading_key: &Self::LoadingKey) -> Result<Self, Self::Error>
    where
        P: AsRef<Self::Path>,
    {
        let (secret_key_source, account) = D::load_with(path, loading_key)?;
        Ok(Self::with_account(secret_key_source, account))
    }
}

impl<D> Save for Signer<D>
where
    D: DerivedSecretKeyGenerator + SaveWith<Account<D>>,
{
    type Path = D::Path;

    type SavingKey = D::SavingKey;

    type Error = <D as Save>::Error;

    #[inline]
    fn save<P>(self, path: P, saving_key: &Self::SavingKey) -> Result<(), Self::Error>
    where
        P: AsRef<Self::Path>,
    {
        self.secret_key_source
            .save_with(self.account, path, saving_key)
    }
}

/// Pending Asset Map
#[derive(derivative::Derivative)]
#[derivative(Default(bound = ""))]
struct PendingAssetMap<D>
where
    D: DerivedSecretKeyGenerator,
{
    /// Pending Insert Data
    insert: Option<(InternalIndex<D>, Asset)>,

    /// Pending Insert Zeroes Data
    insert_zeroes: Option<(AssetId, Vec<Index<D>>)>,

    /// Pending Remove Data
    remove: Vec<Index<D>>,
}

impl<D> PendingAssetMap<D>
where
    D: DerivedSecretKeyGenerator,
{
    /// Commits the pending asset map data to `assets`.
    #[inline]
    fn commit<M>(&mut self, assets: &mut M)
    where
        M: AssetMap<Key = Index<D>> + ?Sized,
    {
        if let Some((key, asset)) = self.insert.take() {
            assets.insert(key.reduce(), asset);
        }
        if let Some((asset_id, zeroes)) = self.insert_zeroes.take() {
            assets.insert_zeroes(asset_id, zeroes);
        }
        assets.remove_all(mem::take(&mut self.remove))
    }

    /// Clears the pending asset map.
    #[inline]
    fn rollback(&mut self) {
        *self = Default::default()
    }
}

/// Full Signer
pub struct FullSigner<D, C, M, R>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
    C::UtxoSet: Rollback,
    M: AssetMap<Key = Index<D>>,
    R: CryptoRng + RngCore,
{
    /// Signer
    signer: Signer<D>,

    /// Commitment Scheme
    commitment_scheme: C::CommitmentScheme,

    /// Proving Context
    proving_context: ProvingContext<C>,

    /// UTXO Set
    utxo_set: C::UtxoSet,

    /// Asset Distribution
    assets: M,

    /// Pending Asset Distribution
    pending_assets: PendingAssetMap<D>,

    /// Random Number Generator
    rng: R,
}

impl<D, C, M, R> FullSigner<D, C, M, R>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
    C::UtxoSet: Rollback,
    M: AssetMap<Key = Index<D>>,
    R: CryptoRng + RngCore,
{
    /// Builds a new [`FullSigner`].
    #[inline]
    fn new_inner(
        signer: Signer<D>,
        commitment_scheme: C::CommitmentScheme,
        proving_context: ProvingContext<C>,
        utxo_set: C::UtxoSet,
        assets: M,
        pending_assets: PendingAssetMap<D>,
        rng: R,
    ) -> Self {
        Self {
            signer,
            commitment_scheme,
            proving_context,
            utxo_set,
            assets,
            pending_assets,
            rng,
        }
    }

    /// Builds a new [`FullSigner`] from `secret_key_source`, `account`, `commitment_scheme`,
    /// `proving_context`, and `rng`, using a default [`Utxo`] set and asset distribution.
    #[inline]
    pub fn new(
        secret_key_source: D,
        account: D::Account,
        commitment_scheme: C::CommitmentScheme,
        proving_context: ProvingContext<C>,
        rng: R,
    ) -> Self
    where
        C::UtxoSet: Default,
    {
        Self::new_inner(
            Signer::new(secret_key_source, account),
            commitment_scheme,
            proving_context,
            Default::default(),
            Default::default(),
            Default::default(),
            rng,
        )
    }

    /// Updates the internal ledger state, returning the new asset distribution.
    #[inline]
    fn sync_inner<I>(&mut self, updates: I) -> SyncResult<D, C, Self>
    where
        I: Iterator<Item = (Utxo<C>, EncryptedAsset<C>)>,
    {
        let mut assets = Vec::new();
        for (utxo, encrypted_asset) in updates {
            // TODO: Add optimization path where we have "strong" and "weak" insertions into the
            //       `utxo_set`. If the `utxo` is accompanied by an `encrypted_asset` then we
            //       "strong insert", if not we "weak insert".
            //
            if let Some((key, asset)) = self.signer.find_external_asset::<C>(&encrypted_asset) {
                assets.push(asset);
                self.assets.insert(key, asset);
            }

            // FIXME: Should this ever error? We should check the capacity at `updates`, then
            //        insert should always work here.
            let _ = self.utxo_set.insert(&utxo);
        }
        Ok(SyncResponse::new(assets))
    }

    /// Updates the internal ledger state, returning the new asset distribution.
    #[inline]
    pub fn sync<I>(
        &mut self,
        sync_state: SyncState,
        starting_index: usize,
        updates: I,
    ) -> SyncResult<D, C, Self>
    where
        I: IntoIterator<Item = (Utxo<C>, EncryptedAsset<C>)>,
    {
        self.start_sync(sync_state);
        match self.utxo_set.len().checked_sub(starting_index) {
            Some(diff) => self.sync_inner(updates.into_iter().skip(diff)),
            _ => Err(Error::InconsistentSynchronization),
        }
    }

    /// Returns a [`PreSender`] for the key at the given `index`.
    #[inline]
    fn get_pre_sender(&self, index: Index<D>, asset: Asset) -> Result<PreSender<C>, Error<D, C>> {
        self.signer
            .get_pre_sender(index, &self.commitment_scheme, asset)
            .map_err(Error::SecretKeyError)
    }

    /// Selects the pre-senders which collectively own at least `asset`, returning any change.
    #[inline]
    fn select(&mut self, asset: Asset) -> Result<(AssetBalance, Vec<PreSender<C>>), Error<D, C>> {
        let selection = self.assets.select(asset);
        if selection.is_empty() {
            return Err(Error::InsufficientBalance(asset));
        }

        self.pending_assets.remove = selection.keys().cloned().collect();

        let pre_senders = selection
            .balances
            .into_iter()
            .map(move |(k, v)| self.get_pre_sender(k, asset.id.with(v)))
            .collect::<Result<_, _>>()?;

        Ok((selection.change, pre_senders))
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
        transfer: impl Into<Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>>,
    ) -> Result<TransferPost<C>, Error<D, C>> {
        transfer
            .into()
            .into_post(
                &self.commitment_scheme,
                &self.utxo_set.verifier(),
                &self.proving_context,
                &mut self.rng,
            )
            .map_err(Error::ProofSystemError)
    }

    /// Accumulate transfers using the `SENDERS -> RECEIVERS` shape.
    #[inline]
    fn accumulate_transfers<const SENDERS: usize, const RECEIVERS: usize>(
        &mut self,
        asset_id: AssetId,
        mut pre_senders: Vec<PreSender<C>>,
    ) -> Result<
        (
            Vec<InternalKeyOwned<D, PreSender<C>>>,
            Vec<PreSender<C>>,
            Vec<TransferPost<C>>,
        ),
        Error<D, C>,
    > {
        assert!(
            (SENDERS > 1) && (RECEIVERS > 1),
            "The transfer shape must include at least two senders and two receivers."
        );
        assert!(
            !pre_senders.is_empty(),
            "The set of initial senders cannot be empty."
        );

        let mut new_zeroes = Vec::new();
        let mut posts = Vec::new();

        while pre_senders.len() > SENDERS {
            let mut accumulators = Vec::new();
            let mut iter = pre_senders.into_iter().chunk_by::<SENDERS>();
            for chunk in &mut iter {
                let senders = fallible_array_map(chunk, |ps| {
                    ps.try_upgrade(&self.utxo_set)
                        .ok_or(Error::MissingUtxoMembershipProof)
                })?;

                let (receivers, accumulator, mut zeroes) =
                    self.signer.next_accumulated_receiver::<_, _, RECEIVERS>(
                        &self.commitment_scheme,
                        asset_id,
                        senders.iter().map(Sender::asset_value).sum(),
                        &mut self.rng,
                    )?;

                posts.push(self.build_post(SecretTransfer::new(senders, receivers))?);

                new_zeroes.append(&mut zeroes);
                accumulators.push(accumulator);
            }

            for pre_sender in accumulators.iter() {
                pre_sender.insert_utxo(&mut self.utxo_set);
            }

            accumulators.append(&mut iter.remainder());
            pre_senders = accumulators;
        }

        Ok((new_zeroes, pre_senders, posts))
    }

    /// Prepare final pre-senders for the transaction.
    #[inline]
    fn prepare_final_pre_senders<const SENDERS: usize>(
        &mut self,
        asset_id: AssetId,
        mut new_zeroes: Vec<InternalKeyOwned<D, PreSender<C>>>,
        pre_senders: &mut Vec<PreSender<C>>,
        posts: &mut Vec<TransferPost<C>>,
    ) -> Result<(), Error<D, C>> {
        let mut needed_zeroes = SENDERS - pre_senders.len();
        if needed_zeroes == 0 {
            return Ok(());
        }

        let zeroes = self.assets.zeroes(needed_zeroes, asset_id);
        needed_zeroes -= zeroes.len();

        for zero in zeroes {
            pre_senders.push(self.get_pre_sender(zero, Asset::zero(asset_id))?);
        }

        if needed_zeroes == 0 {
            return Ok(());
        }

        let needed_mints = needed_zeroes.saturating_sub(new_zeroes.len());

        for _ in 0..needed_zeroes {
            match new_zeroes.pop() {
                Some(zero) => pre_senders.push(zero.unwrap()),
                _ => break,
            }
        }

        self.pending_assets.insert_zeroes = Some((
            asset_id,
            new_zeroes
                .into_iter()
                .map(move |z| z.index.reduce())
                .collect(),
        ));

        if needed_mints == 0 {
            return Ok(());
        }

        for _ in 0..needed_mints {
            let (mint, pre_sender) =
                self.signer
                    .mint_zero(&self.commitment_scheme, asset_id, &mut self.rng)?;
            pre_senders.push(pre_sender);
            posts.push(self.build_post(mint)?);
        }

        Ok(())
    }

    /// Returns the next change receiver for `asset`.
    #[inline]
    fn next_change(
        &mut self,
        asset_id: AssetId,
        change: AssetBalance,
    ) -> Result<Receiver<C>, Error<D, C>> {
        let asset = asset_id.with(change);
        let (receiver, index) = self
            .signer
            .next_change(&self.commitment_scheme, asset, &mut self.rng)?
            .into();
        self.pending_assets.insert = Some((index, asset));
        Ok(receiver)
    }

    /// Prepares a given [`ShieldedIdentity`] for receiving `asset`.
    #[inline]
    pub fn prepare_receiver(
        &mut self,
        asset: Asset,
        receiver: ShieldedIdentity<C>,
    ) -> Result<Receiver<C>, Error<D, C>> {
        receiver
            .into_receiver(&self.commitment_scheme, asset, &mut self.rng)
            .map_err(Error::EncryptionError)
    }

    /// Signs a withdraw transaction without resetting on error.
    #[inline]
    fn sign_withdraw_inner(
        &mut self,
        asset: Asset,
        receiver: Option<ShieldedIdentity<C>>,
    ) -> SignResult<D, C, Self> {
        let (change, pre_senders) = self.select(asset)?;

        let (new_zeroes, mut pre_senders, mut posts) =
            self.accumulate_transfers::<2, 2>(asset.id, pre_senders)?;

        self.prepare_final_pre_senders::<2>(asset.id, new_zeroes, &mut pre_senders, &mut posts)?;

        let sender_side = into_array_unchecked(
            pre_senders
                .into_iter()
                .map(|ps| ps.try_upgrade(&self.utxo_set))
                .collect::<Option<Vec<_>>>()
                .ok_or(Error::MissingUtxoMembershipProof)?,
        );

        let change_receiver = self.next_change(asset.id, change)?;

        let final_post = match receiver {
            Some(receiver) => {
                let receiver = self.prepare_receiver(asset, receiver)?;
                self.build_post(PrivateTransfer::build(
                    sender_side,
                    [change_receiver, receiver],
                ))?
            }
            _ => self.build_post(Reclaim::build(sender_side, change_receiver, asset))?,
        };

        posts.push(final_post);

        Ok(SignResponse::new(posts))
    }

    /// Signs a withdraw transaction, resetting the internal state on an error.
    #[inline]
    fn sign_withdraw(
        &mut self,
        asset: Asset,
        receiver: Option<ShieldedIdentity<C>>,
    ) -> SignResult<D, C, Self> {
        let result = self.sign_withdraw_inner(asset, receiver);
        if result.is_err() {
            self.rollback();
        }
        result
    }

    /// Signs the `transaction`, generating transfer posts.
    #[inline]
    pub fn sign(&mut self, transaction: Transaction<C>) -> SignResult<D, C, Self> {
        self.commit();
        match transaction {
            Transaction::Mint(asset) => {
                let (mint, owner) =
                    self.signer
                        .mint(&self.commitment_scheme, asset, &mut self.rng)?;
                let mint_post = self.build_post(mint)?;
                self.pending_assets.insert = Some((owner, asset));
                Ok(SignResponse::new(vec![mint_post]))
            }
            Transaction::PrivateTransfer(asset, receiver) => {
                self.sign_withdraw(asset, Some(receiver))
            }
            Transaction::Reclaim(asset) => self.sign_withdraw(asset, None),
        }
    }

    /// Commits to the state after the last call to [`sign`](Self::sign).
    #[inline]
    pub fn commit(&mut self) {
        self.signer.account.internal_range_shift_to_end();
        self.utxo_set.commit();
        self.pending_assets.commit(&mut self.assets);
    }

    /// Rolls back to the state before the last call to [`sign`](Self::sign).
    #[inline]
    pub fn rollback(&mut self) {
        self.signer.account.internal_range_shift_to_start();
        self.utxo_set.rollback();
        self.pending_assets.rollback();
    }

    /// Commits or rolls back the state depending on the value of `sync_state`.
    #[inline]
    pub fn start_sync(&mut self, sync_state: SyncState) {
        match sync_state {
            SyncState::Commit => self.commit(),
            SyncState::Rollback => self.rollback(),
        }
    }

    /// Generates a new [`ShieldedIdentity`] for `self` to receive assets.
    #[inline]
    pub fn external_receiver(&mut self) -> ExternalReceiverResult<D, C, Self> {
        self.signer
            .next_shielded(&self.commitment_scheme)
            .map_err(Error::SecretKeyError)
    }
}

impl<D, C, M, R> Connection<D, C> for FullSigner<D, C, M, R>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
    C::UtxoSet: Rollback,
    M: AssetMap<Key = Index<D>>,
    R: CryptoRng + RngCore,
{
    type SyncFuture = Ready<SyncResult<D, C, Self>>;

    type SignFuture = Ready<SignResult<D, C, Self>>;

    type CommitFuture = Ready<Result<(), Self::Error>>;

    type RollbackFuture = Ready<Result<(), Self::Error>>;

    type ExternalReceiverFuture = Ready<ExternalReceiverResult<D, C, Self>>;

    type Error = Infallible;

    #[inline]
    fn sync<I>(
        &mut self,
        sync_state: SyncState,
        starting_index: usize,
        updates: I,
    ) -> Self::SyncFuture
    where
        I: IntoIterator<Item = (Utxo<C>, EncryptedAsset<C>)>,
    {
        future::ready(self.sync(sync_state, starting_index, updates))
    }

    #[inline]
    fn sign(&mut self, transaction: Transaction<C>) -> Self::SignFuture {
        future::ready(self.sign(transaction))
    }

    #[inline]
    fn commit(&mut self) -> Self::CommitFuture {
        future::ready({
            self.commit();
            Ok(())
        })
    }

    #[inline]
    fn rollback(&mut self) -> Self::RollbackFuture {
        future::ready({
            self.rollback();
            Ok(())
        })
    }

    #[inline]
    fn external_receiver(&mut self) -> Self::ExternalReceiverFuture {
        future::ready(self.external_receiver())
    }
}

/// Internal Receiver Error
///
/// This `enum` is the error state for any construction of an internal receiver from a derived
/// secret key generator.
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "D::Error: Clone, IntegratedEncryptionSchemeError<C>: Clone"),
    Copy(bound = "D::Error: Copy, IntegratedEncryptionSchemeError<C>: Copy"),
    Debug(bound = "D::Error: Debug, IntegratedEncryptionSchemeError<C>: Debug"),
    Eq(bound = "D::Error: Eq, IntegratedEncryptionSchemeError<C>: Eq"),
    Hash(bound = "D::Error: Hash, IntegratedEncryptionSchemeError<C>: Hash"),
    PartialEq(bound = "D::Error: PartialEq, IntegratedEncryptionSchemeError<C>: PartialEq")
)]
pub enum InternalReceiverError<D, C>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
{
    /// Secret Key Generator Error
    SecretKeyError(D::Error),

    /// Encryption Error
    EncryptionError(IntegratedEncryptionSchemeError<C>),
}
