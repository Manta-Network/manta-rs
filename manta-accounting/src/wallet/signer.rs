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
    asset::{Asset, AssetBalance, AssetId},
    fs::{Load, LoadWith, Save, SaveWith},
    identity::{self, AssetParameters, Identity, Utxo},
    keys::{
        Account, DerivedSecretKeyGenerator, External, ExternalIndex, ExternalKeyOwned, Index,
        Internal, InternalIndex, InternalKeyOwned, KeyKind, KeyOwned,
    },
    transfer::{
        self,
        canonical::{Mint, PrivateTransfer, Reclaim},
        EncryptedAsset, IntegratedEncryptionSchemeError, ProofSystemError, ProvingContext,
        TransferPost,
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
use rand::{
    distributions::{Distribution, Standard},
    CryptoRng, RngCore,
};

/// Key-Owned Pre-Sender Type
pub type PreSender<D, C> = InternalKeyOwned<D, identity::PreSender<C>>;

/// Key-Owned Shielded Identity Type
pub type ShieldedIdentity<D, C> = ExternalKeyOwned<D, transfer::ShieldedIdentity<C>>;

/// Key-Owned Internal Receiver Type
pub type InternalReceiver<D, C> = InternalKeyOwned<
    D,
    identity::InternalReceiver<C, <C as transfer::Configuration>::IntegratedEncryptionScheme>,
>;

/// Key-Owned Open Spend Type
pub type OpenSpend<D, C, K = KeyKind> = KeyOwned<D, identity::OpenSpend<C>, K>;

/// External Key-Owned Open Spend Type
pub type ExternalOpenSpend<D, C> = OpenSpend<D, C, External>;

/// Internal Key-Owned Open Spend Type
pub type InternalOpenSpend<D, C> = OpenSpend<D, C, Internal>;

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
    fn sign(&mut self, request: SignRequest<D, C>) -> Self::SignFuture;

    /// Commits to the state after the last call to [`sign`](Self::sign).
    fn commit(&mut self) -> Self::CommitFuture;

    /// Rolls back to the state before the last call to [`sign`](Self::sign).
    fn rollback(&mut self) -> Self::RollbackFuture;

    /// Generates a new [`ShieldedIdentity`] for `self` to receive assets.
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
pub type SyncResult<D, C, S> = Result<SyncResponse<D>, Error<D, C, <S as Connection<D, C>>::Error>>;

/// Signing Result
///
/// See the [`sign`](Connection::sign) method on [`Connection`] for more information.
pub type SignResult<D, C, S> =
    Result<SignResponse<D, C>, Error<D, C, <S as Connection<D, C>>::Error>>;

/// External Receiver Generation Result
///
/// See the [`external_receiver`](Connection::external_receiver) method on [`Connection`] for more
/// information.
pub type ExternalReceiverResult<D, C, S> =
    Result<transfer::ShieldedIdentity<C>, Error<D, C, <S as Connection<D, C>>::Error>>;

/// Signer Synchronization Response
///
/// This `struct` is created by the [`sync`](Connection::sync) method on [`Connection`].
/// See its documentation for more.
pub struct SyncResponse<D>
where
    D: DerivedSecretKeyGenerator,
{
    /// Updates to the Asset Distribution
    pub assets: Vec<(ExternalIndex<D>, Asset)>,
}

/// Signer Signing Request
///
/// This `struct` is used by the [`sign`](Connection::sign) method on [`Connection`].
/// See its documentation for more.
pub enum SignRequest<D, C>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
{
    /// Mint Transaction
    Mint(Asset),

    /// Private Transfer Transaction
    PrivateTransfer {
        /// Total Asset to Transfer
        total: Asset,

        /// Change Remaining from Asset Selection
        change: AssetBalance,

        /// Asset Selection
        balances: Vec<(Index<D>, AssetBalance)>,

        /// Receiver Shielded Identity
        receiver: transfer::ShieldedIdentity<C>,
    },

    /// Reclaim Transaction
    Reclaim {
        /// Total Asset to Transfer
        total: Asset,

        /// Change Remaining from Asset Selection
        change: AssetBalance,

        /// Asset Selection
        balances: Vec<(Index<D>, AssetBalance)>,
    },
}

/// Signer Signing Response
///
/// This `struct` is created by the [`sign`](Connection::sign) method on [`Connection`].
/// See its documentation for more.
pub struct SignResponse<D, C>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
{
    /// Asset Distribution Deposit Balance Updates
    pub balances: Vec<(InternalIndex<D>, AssetBalance)>,

    /// Transfer Posts
    pub posts: Vec<TransferPost<C>>,
}

impl<D, C> SignResponse<D, C>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
{
    /// Builds a new [`SignResponse`] from `balances` and `posts`.
    #[inline]
    pub fn new(
        balances: Vec<(InternalIndex<D>, AssetBalance)>,
        posts: Vec<TransferPost<C>>,
    ) -> Self {
        Self { balances, posts }
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

    /// Returns a [`PreSender`] for the key at the given `index`.
    #[inline]
    pub fn get_pre_sender<C>(
        &self,
        index: InternalIndex<D>,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
    ) -> Result<PreSender<D, C>, D::Error>
    where
        C: identity::Configuration<SecretKey = D::SecretKey>,
        Standard: Distribution<AssetParameters<C>>,
    {
        Ok(KeyOwned::new(
            self.get_internal(&index)?
                .into_pre_sender(commitment_scheme, asset),
            index,
        ))
    }

    /// Generates the next identity of the given `kind` for this signer.
    #[inline]
    pub fn next_identity<C>(&mut self, kind: KeyKind) -> Result<KeyOwned<D, Identity<C>>, D::Error>
    where
        C: identity::Configuration<SecretKey = D::SecretKey>,
    {
        Ok(self
            .account
            .next_key(&self.secret_key_source, kind)?
            .map(Identity::new))
    }

    /// Generates the next external identity for this signer.
    #[inline]
    pub fn next_external_identity<C>(
        &mut self,
    ) -> Result<ExternalKeyOwned<D, Identity<C>>, D::Error>
    where
        C: identity::Configuration<SecretKey = D::SecretKey>,
    {
        Ok(self
            .account
            .next_external_key(&self.secret_key_source)?
            .map(Identity::new))
    }

    /// Generates the next internal identity for this signer.
    #[inline]
    pub fn next_internal_identity<C>(
        &mut self,
    ) -> Result<InternalKeyOwned<D, Identity<C>>, D::Error>
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
    ) -> Result<ShieldedIdentity<D, C>, D::Error>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        Standard: Distribution<AssetParameters<C>>,
    {
        Ok(self
            .next_external_identity()?
            .map(move |identity| identity.into_shielded(commitment_scheme)))
    }

    /// Generates a new [`InternalReceiver`] to receive `asset` to this account via an
    /// internal transaction.
    #[inline]
    pub fn next_change_receiver<C, R>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        rng: &mut R,
    ) -> Result<InternalReceiver<D, C>, InternalReceiverError<D, C>>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        R: CryptoRng + RngCore + ?Sized,
        Standard: Distribution<AssetParameters<C>>,
    {
        self.next_internal_identity()
            .map_err(InternalReceiverError::SecretKeyError)?
            .map_ok(move |identity| identity.into_internal_receiver(commitment_scheme, asset, rng))
            .map_err(InternalReceiverError::EncryptionError)
    }

    /// Builds a vector of `n` internal receivers to capture the given `asset`.
    ///
    /// # Panics
    ///
    /// This method panics if `n == 0`.
    #[inline]
    pub fn next_change_receivers<C, R>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        n: usize,
        rng: &mut R,
    ) -> InternalReceiverResult<D, C, Vec<InternalReceiver<D, C>>>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        R: CryptoRng + RngCore + ?Sized,
        Standard: Distribution<AssetParameters<C>>,
    {
        asset
            .value
            .make_change(n)
            .unwrap()
            .map(move |value| {
                self.next_change_receiver(commitment_scheme, asset.id.with(value), rng)
            })
            .collect()
    }

    /// Generates a new [`InternalReceiver`] to receive an asset, with the given `asset_id` and
    /// no value, to this account via an internal transaction.
    #[inline]
    pub fn next_empty_receiver<C, R>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
        asset_id: AssetId,
        rng: &mut R,
    ) -> Result<InternalReceiver<D, C>, InternalReceiverError<D, C>>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        R: CryptoRng + RngCore + ?Sized,
        Standard: Distribution<AssetParameters<C>>,
    {
        self.next_change_receiver(commitment_scheme, Asset::zero(asset_id), rng)
    }

    /// Generates a new [`PreSender`] to send `asset` from this account via an internal
    /// transaction.
    #[inline]
    pub fn next_pre_sender<C>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
    ) -> Result<PreSender<D, C>, D::Error>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        Standard: Distribution<AssetParameters<C>>,
    {
        Ok(self
            .next_internal_identity()?
            .map(move |identity| identity.into_pre_sender(commitment_scheme, asset)))
    }

    /// Generates a new [`PreSender`] to send an asset with the given `asset_id` and no value,
    /// from this account via an internal transaction.
    #[inline]
    pub fn next_empty_pre_sender<C>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
        asset_id: AssetId,
    ) -> Result<PreSender<D, C>, D::Error>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        Standard: Distribution<AssetParameters<C>>,
    {
        self.next_pre_sender(commitment_scheme, Asset::zero(asset_id))
    }

    /// Builds a [`Mint`] transaction to mint `asset` and returns the [`OpenSpend`] for that asset.
    #[inline]
    pub fn mint<C, R>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        rng: &mut R,
    ) -> InternalReceiverResult<D, C, (Mint<C>, InternalOpenSpend<D, C>)>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        R: CryptoRng + RngCore + ?Sized,
        Standard: Distribution<AssetParameters<C>>,
    {
        Ok(self
            .next_internal_identity()
            .map_err(InternalReceiverError::SecretKeyError)?
            .map_ok(move |identity| Mint::from_identity(identity, commitment_scheme, asset, rng))
            .map_err(InternalReceiverError::EncryptionError)?
            .right())
    }

    /// Builds a [`Mint`] transaction to mint an asset with the given `asset_id` and no value,
    /// returning the [`OpenSpend`] for that asset.
    #[inline]
    pub fn mint_zero<C, R>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
        asset_id: AssetId,
        rng: &mut R,
    ) -> InternalReceiverResult<D, C, (Mint<C>, InternalOpenSpend<D, C>)>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        R: CryptoRng + RngCore + ?Sized,
        Standard: Distribution<AssetParameters<C>>,
    {
        self.mint(commitment_scheme, Asset::zero(asset_id), rng)
    }

    /// Builds [`PrivateTransfer`] transactions to send `asset` to an `external_receiver`.
    #[inline]
    pub fn private_transfer<C, R>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        senders: Vec<(Index<D>, AssetBalance)>,
        external_receiver: transfer::ShieldedIdentity<C>,
        rng: &mut R,
    ) -> Option<Vec<PrivateTransfer<C>>>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        R: CryptoRng + RngCore + ?Sized,
        Standard: Distribution<AssetParameters<C>>,
    {
        /* TODO:
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

    /// Builds a [`Reclaim`] transaction.
    #[inline]
    pub fn reclaim<C, R>(
        &self,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        rng: &mut R,
    ) -> Option<Reclaim<C>>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        R: CryptoRng + RngCore + ?Sized,
    {
        let _ = (commitment_scheme, asset, rng);
        todo!()
    }

    /// Looks for an [`OpenSpend`] for this `encrypted_asset`.
    #[inline]
    pub fn find_external_open_spend<C>(
        &mut self,
        encrypted_asset: &EncryptedAsset<C>,
    ) -> Option<ExternalOpenSpend<D, C>>
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
        Some(open_spend)
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

/// Full Signer
pub struct FullSigner<D, C, R>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
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

    /// Random Number Generator
    rng: R,
}

impl<D, C, R> FullSigner<D, C, R>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
    R: CryptoRng + RngCore,
{
    /// Builds a new [`FullSigner`].
    #[inline]
    fn new_inner(
        signer: Signer<D>,
        commitment_scheme: C::CommitmentScheme,
        proving_context: ProvingContext<C>,
        utxo_set: C::UtxoSet,
        rng: R,
    ) -> Self {
        Self {
            signer,
            commitment_scheme,
            proving_context,
            utxo_set,
            rng,
        }
    }

    /// Builds a new [`FullSigner`] from `secret_key_source`, `account`, `commitment_scheme`,
    /// `proving_context`, and `rng`, using a default [`Utxo`] set.
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
        use manta_crypto::Set; // FIXME: move up to top of file

        match sync_state {
            SyncState::Commit => self.commit(),
            SyncState::Rollback => self.rollback(),
        }

        let mut assets = Vec::new();
        for (utxo, encrypted_asset) in updates {
            // TODO: Add optimization path where we have "strong" and "weak" insertions into the
            //       `utxo_set`. If the `utxo` is accompanied by an `encrypted_asset` then we
            //       "strong insert", if not we "weak insert".
            //
            if let Some(open_spend) = self.signer.find_external_open_spend(&encrypted_asset) {
                assets.push((open_spend.index, open_spend.value.into_asset()));
            }
            let _ = self.utxo_set.try_insert(utxo); // FIXME: Should this ever error?
        }
        Ok(SyncResponse { assets })
    }

    /// Signs the `request`, generating transfer posts.
    #[inline]
    fn sign(&mut self, request: SignRequest<D, C>) -> SignResult<D, C, Self>
    where
        Standard: Distribution<AssetParameters<C>>,
    {
        // FIXME: Repeated calls to sign should automatically commit.
        match request {
            SignRequest::Mint(asset) => {
                let (mint, open_spend) =
                    self.signer
                        .mint(&self.commitment_scheme, asset, &mut self.rng)?;
                let mint_post = mint
                    .into_post(
                        &self.commitment_scheme,
                        &self.utxo_set,
                        &self.proving_context,
                        &mut self.rng,
                    )
                    .map_err(Error::ProofSystemError)?;
                Ok(SignResponse::new(
                    vec![(open_spend.index, asset.value)],
                    vec![mint_post],
                ))
            }
            SignRequest::PrivateTransfer { .. } => {
                // FIXME: implement
                todo!()
            }
            SignRequest::Reclaim { .. } => {
                // FIXME: implement
                todo!()
            }
        }
    }

    /// Commits to the state after the last call to [`sign`](Self::sign).
    #[inline]
    fn commit(&mut self) {
        // FIXME: Implement commit for UTXO set.
        self.signer.account.internal_range_shift_to_end();
        todo!()
    }

    /// Rolls back to the state before the last call to [`sign`](Self::sign).
    #[inline]
    fn rollback(&mut self) {
        // FIXME: Implement rollback for UTXO set.
        self.signer.account.internal_range_shift_to_start();
        todo!()
    }
}

impl<D, C, R> Connection<D, C> for FullSigner<D, C, R>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
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
    fn sign(&mut self, request: SignRequest<D, C>) -> Self::SignFuture {
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
                .map(KeyOwned::unwrap)
                .map_err(Error::SecretKeyError),
        )
    }
}

/// Internal Receiver Error
///
/// This `enum` is the error state for any construction of an [`InternalReceiver`] from a derived
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
