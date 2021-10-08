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
    asset::{self, Asset, AssetBalance, AssetId, AssetMap, AssetMapSelection},
    fs::{Load, LoadWith, Save, SaveWith},
    identity::{self, AssetParameters, Identity, PreSender, Utxo},
    keys::{
        Account, DerivedSecretKeyGenerator, External, ExternalIndex, Index, Internal,
        InternalIndex, InternalKeyOwned, KeyKind, KeyOwned,
    },
    transfer::{
        self,
        canonical::{Mint, PrivateTransfer, Reclaim},
        EncryptedAsset, IntegratedEncryptionSchemeError, ProofSystemError, ProvingContext,
        Receiver, Sender, ShieldedIdentity, Transfer, TransferPost,
    },
};
use alloc::{vec, vec::Vec};
use core::{
    convert::Infallible,
    fmt::Debug,
    future::{self, Future, Ready},
    hash::Hash,
    ops::Range,
};
use manta_crypto::{Set, VerifiedSet};
use rand::{
    distributions::{Distribution, Standard},
    CryptoRng, RngCore,
};

///
pub type Selection<D> = asset::Selection<Index<D>, Vec<(Index<D>, AssetBalance)>, Vec<Index<D>>>;

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
    fn sync<I>(&mut self, updates: I, sync_state: SyncState) -> Self::SyncFuture
    where
        I: IntoIterator<Item = (Utxo<C>, EncryptedAsset<C>)>;

    /// Signs a transfer `request` and returns the ledger transfer posts if successful.
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
    fn sign(&mut self, request: SignRequest<C>) -> Self::SignFuture;

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

/// Signer Signing Request
///
/// This `struct` is used by the [`sign`](Connection::sign) method on [`Connection`].
/// See its documentation for more.
pub enum SignRequest<C>
where
    C: transfer::Configuration,
{
    /// Mint Transaction
    Mint(Asset),

    /// Private Transfer Transaction
    PrivateTransfer(Asset, ShieldedIdentity<C>),

    /// Reclaim Transaction
    Reclaim(Asset),
}

impl<C> SignRequest<C>
where
    C: transfer::Configuration,
{
    /// Returns the underlying asset of the transaction.
    #[inline]
    pub fn asset(&self) -> Asset {
        match self {
            Self::Mint(asset) => *asset,
            Self::PrivateTransfer(asset, _) => *asset,
            Self::Reclaim(asset) => *asset,
        }
    }

    /// Returns `true` if the transaction is a deposit relative to the poster.
    #[inline]
    pub fn is_deposit(&self) -> bool {
        matches!(self, Self::Mint(_))
    }

    /// Returns `true` if the transaction is a withdraw relative to the poster.
    #[inline]
    pub fn is_withdraw(&self) -> bool {
        !self.is_deposit()
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
    /// Resulting Balance to Deposit
    pub deposit: AssetBalance,

    /// Transfer Posts
    pub posts: Vec<TransferPost<C>>,
}

impl<C> SignResponse<C>
where
    C: transfer::Configuration,
{
    /// Builds a new [`SignResponse`] from `deposit` and `posts`.
    #[inline]
    pub fn new(deposit: AssetBalance, posts: Vec<TransferPost<C>>) -> Self {
        Self { deposit, posts }
    }
}

/// Signer Error
pub enum Error<D, C, CE>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
{
    /// Secret Key Generation Error
    SecretKeyError(D::Error),

    /// Encryption Error
    EncryptionError(IntegratedEncryptionSchemeError<C>),

    /// Proof System Error
    ProofSystemError(ProofSystemError<C>),

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

    /// Returns a [`Sender`] for the key at the given `index`.
    #[inline]
    pub fn get_sender<C>(
        &self,
        index: Index<D>,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        utxo_set: &C::UtxoSet,
    ) -> Result<Sender<C>, SenderError<D, C>>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        Standard: Distribution<AssetParameters<C>>,
    {
        self.get(&index)
            .map_err(SenderError::SecretKeyError)?
            .into_sender(commitment_scheme, asset, utxo_set)
            .map_err(SenderError::ContainmentError)
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
        Standard: Distribution<AssetParameters<C>>,
    {
        Ok(self
            .next_external_identity()?
            .into_shielded(commitment_scheme))
    }

    /// Builds the next inner change receiver and pre-sender.
    #[inline]
    pub fn next_inner_change<C, R>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        rng: &mut R,
    ) -> Result<(Receiver<C>, PreSender<C>), InternalReceiverError<D, C>>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        R: CryptoRng + RngCore + ?Sized,
        Standard: Distribution<AssetParameters<C>>,
    {
        // TODO: Simplify this so that `into_internal_receiver` automatically produces a
        //       `PreSender` instead of an `OpenSpend`.
        let internal_receiver = self
            .next_internal_identity()
            .map_err(InternalReceiverError::SecretKeyError)?
            .unwrap()
            .into_internal_receiver(commitment_scheme, asset, rng)
            .map_err(InternalReceiverError::EncryptionError)?;
        Ok((
            internal_receiver.receiver,
            internal_receiver
                .open_spend
                .into_pre_sender(commitment_scheme),
        ))
    }

    /// Builds the final change receiver for the end of a transaction.
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
        Standard: Distribution<AssetParameters<C>>,
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
        Standard: Distribution<AssetParameters<C>>,
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

    /// Builds [`PrivateTransfer`] transactions to send `asset` to an `external_receiver`.
    #[inline]
    pub fn private_transfer<C, R>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        senders: Vec<(Index<D>, AssetBalance)>,
        external_receiver: ShieldedIdentity<C>,
        rng: &mut R,
    ) -> Option<Vec<PrivateTransfer<C>>>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        R: CryptoRng + RngCore + ?Sized,
        Standard: Distribution<AssetParameters<C>>,
    {
        /* FIXME:
        let mut sender_total = AssetBalance(0);
        let mut pre_senders = senders
            .into_iter()
            .map(|(index, value)| {
                sender_total += value;
                self.get_pre_sender(index, commitment_scheme, asset.id.with(value))
            })
            .collect::<Result<Vec<_>, _>>()
            .ok()?;

        let mint = if pre_senders.len() % 2 == 1 {
            let (mint, open_spend) = self.mint_zero(commitment_scheme, asset.id, rng).ok()?;
            pre_senders.push(open_spend.map(move |os| os.into_pre_sender(commitment_scheme)));
            Some(mint)
        } else {
            None
        };

        let mut transfers = Vec::new();
        let mut accumulator = self
            .next_internal_identity()?
            .into_pre_sender(commitment_scheme, Asset::zero(asset.id));
        for pre_sender in pre_senders {
            let (next_receiver, next_open_spend) =
                self.next_change_receiver(commitment_scheme)?.value.into();
            transfers.push(PrivateTransfer::build(
                [accumulator.into_sender(), pre_sender.value],
                [
                    next_receiver,
                    self.next_empty_receiver(commitment_scheme, asset.id, rng)?,
                ],
            ));
            accumulator = next_open_spend.into_pre_sender(commitment_scheme);
        }

        let external_receiver = external_receiver.into_receiver(commitment_scheme, asset, rng);

        transfers.push(PrivateTransfer::build(
            [accumulator.into_sender(), self.next_empty_sender()],
            [external_receiver, change],
        ));
        */

        todo!()
    }

    /// Looks for an index that can decrypt the given `encrypted_asset`.
    #[inline]
    pub fn find_external_asset<C>(
        &mut self,
        encrypted_asset: &EncryptedAsset<C>,
    ) -> Option<(Index<D>, Asset)>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        Standard: Distribution<AssetParameters<C>>,
    {
        let open_spend = self
            .account
            .external_keys(&self.secret_key_source)
            .find_map(move |ek| {
                ek.map(move |ek| {
                    ek.map(move |k| Identity::new(k).try_open(encrypted_asset))
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
struct PendingAssetMap<M>
where
    M: AssetMap + ?Sized,
{
    /// Pending Deposit Data
    deposit: Option<(M::Key, Asset)>,

    /// Pending Withdraw Data
    withdraw: Option<(AssetId, AssetMapSelection<M>)>,
}

impl<M> PendingAssetMap<M>
where
    M: AssetMap + ?Sized,
{
    /// Commits the pending asset map data to `assets`.
    #[inline]
    fn commit(&mut self, assets: &mut M) {
        self.withdraw = None;
        if let Some((key, asset)) = self.deposit.take() {
            assets.insert(key, asset);
        }
    }

    /// Rolls back the pending asset map data updating `assets`.
    #[inline]
    fn rollback(&mut self, assets: &mut M) {
        self.deposit = None;
        if let Some((asset_id, selection)) = self.withdraw.take() {
            assets.insert_all_same(asset_id, selection.balances);
            assets.insert_all_zeroes(asset_id, selection.zeroes);
        }
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
    pending_assets: PendingAssetMap<M>,

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
        pending_assets: PendingAssetMap<M>,
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

    /// Updates the internal ledger state, returing the new asset distribution.
    #[inline]
    fn sync<I>(&mut self, updates: I, sync_state: SyncState) -> SyncResult<D, C, Self>
    where
        I: IntoIterator<Item = (Utxo<C>, EncryptedAsset<C>)>,
        Standard: Distribution<AssetParameters<C>>,
    {
        self.start_sync(sync_state);

        let mut assets = Vec::new();
        for (utxo, encrypted_asset) in updates {
            // TODO: Add optimization path where we have "strong" and "weak" insertions into the
            //       `utxo_set`. If the `utxo` is accompanied by an `encrypted_asset` then we
            //       "strong insert", if not we "weak insert".
            //
            if let Some((key, asset)) = self.signer.find_external_asset(&encrypted_asset) {
                assets.push(asset);
                self.assets.insert(key, asset);
            }

            // FIXME: Should this ever error? We should check the capacity at `updates`, then
            //        insert should always work here.
            let _ = self.utxo_set.try_insert(utxo);
        }
        Ok(SyncResponse { assets })
    }

    /// Selects `asset` from the asset distribution, returning it back if there was an insufficient
    /// balance.
    #[inline]
    fn select(&mut self, asset: Asset) -> Result<AssetMapSelection<M>, Asset> {
        /*
        self.assets
            .select(asset, &self.selection_strategy)
            .ok_or(asset)
        */
        todo!()
    }

    /// Prepares a `request` for signing.
    #[inline]
    fn prepare(&mut self, request: SignRequest<C>) {
        /* TODO:
        match transaction {
            Transaction::Mint(asset) => Ok((asset.id, SignRequest::Mint(asset))),
            Transaction::PrivateTransfer(asset, receiver) => {
                let Selection {
                    change,
                    balances,
                    zeroes,
                } = self.select(asset)?;
                Ok((
                    asset.id,
                    SignRequest::PrivateTransfer {
                        total: asset,
                        change,
                        balances: balances.collect(),
                        zeroes: zeroes.collect(),
                        receiver,
                    },
                ))
            }
            Transaction::Reclaim(asset) => {
                let Selection {
                    change,
                    balances,
                    zeroes,
                } = self.select(asset)?;
                Ok((
                    asset.id,
                    SignRequest::Reclaim {
                        total: asset,
                        change,
                        balances: balances.collect(),
                        zeroes: zeroes.collect(),
                    },
                ))
            }
        }
        */
        todo!()
    }

    /// Returns a [`Sender`] for the key at the given `index`.
    #[inline]
    fn get_sender(&self, index: Index<D>, asset: Asset) -> Result<Sender<C>, SenderError<D, C>>
    where
        Standard: Distribution<AssetParameters<C>>,
    {
        self.signer
            .get_sender(index, &self.commitment_scheme, asset, &self.utxo_set)
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
        transfer: Transfer<C, SOURCES, SENDERS, RECEIVERS, SINKS>,
    ) -> Result<TransferPost<C>, Error<D, C, Infallible>> {
        transfer
            .into_post(
                &self.commitment_scheme,
                &self.utxo_set,
                &self.proving_context,
                &mut self.rng,
            )
            .map_err(Error::ProofSystemError)
    }

    /// Signs the `request`, generating transfer posts.
    #[inline]
    fn sign(&mut self, request: SignRequest<C>) -> SignResult<D, C, Self>
    where
        Standard: Distribution<AssetParameters<C>>,
    {
        self.commit();
        match request {
            SignRequest::Mint(asset) => {
                let (mint, owner) =
                    self.signer
                        .mint(&self.commitment_scheme, asset, &mut self.rng)?;
                let mint_post = self.build_post(mint)?;
                self.pending_assets.deposit = Some((owner.reduce(), asset));
                Ok(SignResponse::new(asset.value, vec![mint_post]))
            }
            SignRequest::PrivateTransfer(..) => {
                // FIXME: implement
                todo!()
            }
            SignRequest::Reclaim(..) => {
                // FIXME: implement
                todo!()
            }
        }
    }

    /// Commits to the state after the last call to [`sign`](Self::sign).
    #[inline]
    fn commit(&mut self) {
        self.signer.account.internal_range_shift_to_end();
        self.utxo_set.commit();
        self.pending_assets.commit(&mut self.assets);
    }

    /// Rolls back to the state before the last call to [`sign`](Self::sign).
    #[inline]
    fn rollback(&mut self) {
        self.signer.account.internal_range_shift_to_start();
        self.utxo_set.rollback();
        self.pending_assets.rollback(&mut self.assets);
    }

    /// Commits or rolls back the state depending on the value of `sync_state`.
    #[inline]
    fn start_sync(&mut self, sync_state: SyncState) {
        match sync_state {
            SyncState::Commit => self.commit(),
            SyncState::Rollback => self.rollback(),
        }
    }
}

impl<D, C, M, R> Connection<D, C> for FullSigner<D, C, M, R>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
    C::UtxoSet: Rollback,
    M: AssetMap<Key = Index<D>>,
    R: CryptoRng + RngCore,
    Standard: Distribution<AssetParameters<C>>,
{
    type SyncFuture = Ready<SyncResult<D, C, Self>>;

    type SignFuture = Ready<SignResult<D, C, Self>>;

    type CommitFuture = Ready<Result<(), Self::Error>>;

    type RollbackFuture = Ready<Result<(), Self::Error>>;

    type ExternalReceiverFuture = Ready<ExternalReceiverResult<D, C, Self>>;

    type Error = Infallible;

    #[inline]
    fn sync<I>(&mut self, updates: I, sync_state: SyncState) -> Self::SyncFuture
    where
        I: IntoIterator<Item = (Utxo<C>, EncryptedAsset<C>)>,
    {
        future::ready(self.sync(updates, sync_state))
    }

    #[inline]
    fn sign(&mut self, request: SignRequest<C>) -> Self::SignFuture {
        future::ready(self.sign(request))
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
        future::ready(
            self.signer
                .next_shielded(&self.commitment_scheme)
                .map_err(Error::SecretKeyError),
        )
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

/// Internal Receiver Result Type
pub type InternalReceiverResult<D, C, T> = Result<T, InternalReceiverError<D, C>>;

/// Sender Error
pub enum SenderError<D, C>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration,
{
    /// Secret Key Generator Error
    SecretKeyError(D::Error),

    /// Containment Error
    ContainmentError(<C::UtxoSet as VerifiedSet>::ContainmentError),
}
