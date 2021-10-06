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

use crate::{
    asset::{Asset, AssetBalance, AssetId, AssetMap},
    fs::{Load, LoadWith, Save, SaveWith},
    identity::{self, AssetParameters, Identity, Utxo},
    keys::{
        Account, DerivedSecretKeyGenerator, ExternalKeys, Index, InternalKeys, KeyKind, KeyOwned,
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
};
use rand::{
    distributions::{Distribution, Standard},
    CryptoRng, RngCore,
};

/// Key-Owned Pre-Sender Type
pub type PreSender<D, C> = KeyOwned<D, identity::PreSender<C>>;

/// Key-Owned Shielded Identity Type
pub type ShieldedIdentity<D, C> = KeyOwned<D, transfer::ShieldedIdentity<C>>;

/// Key-Owned Internal Receiver Type
pub type InternalReceiver<D, C> = KeyOwned<
    D,
    identity::InternalReceiver<C, <C as transfer::Configuration>::IntegratedEncryptionScheme>,
>;

/// Key-Owned Open Spend Type
pub type OpenSpend<D, C> = KeyOwned<D, identity::OpenSpend<C>>;

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

    /// New Receiver Future Type
    ///
    /// Future for the [`new_receiver`](Self::new_receiver) method.
    type NewReceiverFuture: Future<Output = NewReceiverResult<D, C, Self>>;

    /// Error Type
    type Error;

    /// Pushes updates from the ledger to the wallet, synchronizing it with the ledger state and
    /// returning an updated asset distribution.
    fn sync(&mut self, updates: Vec<(Utxo<C>, EncryptedAsset<C>)>) -> Self::SyncFuture;

    /// Signs a transfer `request` and returns the ledger transfer posts if successful.
    fn sign(&mut self, request: SignRequest<D, C>) -> Self::SignFuture;

    /// Generates a new [`ShieldedIdentity`] for `self` to receive assets.
    fn new_receiver(&mut self) -> Self::NewReceiverFuture;
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

/// New Receiver Generation Result
///
/// See the [`new_receiver`](Connection::new_receiver) method on [`Connection`] for more
/// information.
pub type NewReceiverResult<D, C, S> =
    Result<transfer::ShieldedIdentity<C>, Error<D, C, <S as Connection<D, C>>::Error>>;

/// Signer Synchronization Response
///
/// This `struct` is created by the [`sync`](Connection::sync) methon on [`Connection`].
/// See its documentation for more.
pub struct SyncResponse<D>
where
    D: DerivedSecretKeyGenerator,
{
    ///
    pub deposits: Vec<(Index<D>, Asset)>,
}

/* TODO:
pub struct SignRequest<D, C>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
{
    ///
    pub asset: Asset,

    ///
    pub sources: Vec<AssetBalance>,

    ///
    pub senders: Vec<(AssetBalance, Index<D>)>,

    ///
    pub receivers: Vec<(AssetBalance, transfer::ShieldedIdentity<C>)>,

    ///
    pub sinks: Vec<AssetBalance>,
}
*/

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
    PrivateTransfer(Asset, Vec<Index<D>>, transfer::ShieldedIdentity<C>),

    /// Reclaim Transaction
    Reclaim(Asset, Vec<Index<D>>),
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
    /// Asset Distribution Deposit Asset Id
    pub asset_id: AssetId,

    /// Asset Distribution Deposit Balance Updates
    pub balances: Vec<(Index<D>, AssetBalance)>,

    /// Transfer Posts
    pub transfers: Vec<TransferPost<C>>,
}

impl<D, C> SignResponse<D, C>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
{
    /// Builds a new [`SignResponse`] from `asset_id`, `balances` and `transfers`.
    #[inline]
    pub fn new(
        asset_id: AssetId,
        balances: Vec<(Index<D>, AssetBalance)>,
        transfers: Vec<TransferPost<C>>,
    ) -> Self {
        Self {
            asset_id,
            balances,
            transfers,
        }
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

    /// Builds a new [`Signer`] for `account` from a `secret_key_source` with starting indices
    /// `external_index` and `internal_index`.
    #[inline]
    pub fn with_indices(
        secret_key_source: D,
        account: D::Account,
        external_index: D::Index,
        internal_index: D::Index,
    ) -> Self {
        Self::with_account(
            secret_key_source,
            Account::with_indices(account, external_index, internal_index),
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

    /// Returns a [`PreSender`] for the key at the given `index`.
    #[inline]
    pub fn get_pre_sender<C>(
        &self,
        index: Index<D>,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
    ) -> Result<PreSender<D, C>, D::Error>
    where
        C: identity::Configuration<SecretKey = D::SecretKey>,
        Standard: Distribution<AssetParameters<C>>,
    {
        Ok(KeyOwned::new(
            self.get(&index)?.into_pre_sender(commitment_scheme, asset),
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
    pub fn next_external_identity<C>(&mut self) -> Result<KeyOwned<D, Identity<C>>, D::Error>
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
    pub fn next_internal_identity<C>(&mut self) -> Result<KeyOwned<D, Identity<C>>, D::Error>
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
    ) -> InternalReceiverResult<D, C, (Mint<C>, OpenSpend<D, C>)>
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
    ) -> InternalReceiverResult<D, C, (Mint<C>, OpenSpend<D, C>)>
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
        // TODO: Reclaim::build(senders, receiver, reclaim);
        todo!()
    }

    /* TODO:
    /// Returns an [`ExternalKeys`] generator starting from the given `index`.
    #[inline]
    fn external_keys_from_index(&self, index: D::Index) -> ExternalKeys<D> {
        self.account
            .external_keys_from_index(&self.secret_key_source, index)
    }

    /// Returns an [`InternalKeys`] generator starting from the given `index`.
    #[inline]
    fn internal_keys_from_index(&self, index: D::Index) -> InternalKeys<D> {
        self.account
            .internal_keys_from_index(&self.secret_key_source, index)
    }

    /// Looks for an [`OpenSpend`] for this `encrypted_asset` by checking every secret key
    /// in the iterator.
    #[inline]
    fn find_open_spend_from_iter<C, I>(
        &self,
        encrypted_asset: &EncryptedAsset<C>,
        iter: I,
    ) -> Option<OpenSpend<D, C>>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        I: IntoIterator<Item = SecretKey<D>>,
        Standard: Distribution<AssetParameters<C>>,
    {
        iter.into_iter().find_map(move |k| {
            k.map(move |k| Identity::new(k).try_open(encrypted_asset))
                .ok()
        })
    }

    /// Looks for an [`OpenSpend`] for this `encrypted_asset`, only trying `gap_limit`-many
    /// external keys starting from `index`.
    #[inline]
    pub fn find_external_open_spend<C>(
        &self,
        encrypted_asset: &EncryptedAsset<C>,
        index: D::Index,
        gap_limit: usize,
    ) -> Option<OpenSpend<D, C>>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        Standard: Distribution<AssetParameters<C>>,
    {
        self.find_open_spend_from_iter(
            encrypted_asset,
            self.external_keys_from_index(index).take(gap_limit),
        )
    }

    /// Looks for an [`OpenSpend`] for this `encrypted_asset`, only trying `gap_limit`-many
    /// internal keys starting from `index`.
    #[inline]
    pub fn find_internal_open_spend<C>(
        &self,
        encrypted_asset: &EncryptedAsset<C>,
        index: D::Index,
        gap_limit: usize,
    ) -> Option<OpenSpend<D, C>>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        Standard: Distribution<AssetParameters<C>>,
    {
        self.find_open_spend_from_iter(
            encrypted_asset,
            self.internal_keys_from_index(index).take(gap_limit),
        )
    }

    /// Looks for an [`OpenSpend`] for this `encrypted_asset`, only trying `gap_limit`-many
    /// external and internal keys starting from `external_index` and `internal_index`.
    #[inline]
    pub fn find_open_spend<C>(
        &self,
        encrypted_asset: &EncryptedAsset<C>,
        external_index: D::Index,
        internal_index: D::Index,
        gap_limit: usize,
    ) -> Option<OpenSpend<D, C>>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        Standard: Distribution<AssetParameters<C>>,
    {
        // TODO: Find a way to either interleave these or parallelize these.
        if let Some(spend) =
            self.find_external_open_spend(encrypted_asset, external_index, gap_limit)
        {
            return Some(spend);
        }
        if let Some(spend) =
            self.find_internal_open_spend(encrypted_asset, internal_index, gap_limit)
        {
            return Some(spend);
        }
        None
    }
    */
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
pub struct FullSigner<D, C, M, R>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
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

    /// Random Number Generator
    rng: R,
}

impl<D, C, M, R> FullSigner<D, C, M, R>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
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
        rng: R,
    ) -> Self {
        Self {
            signer,
            commitment_scheme,
            proving_context,
            utxo_set,
            assets,
            rng,
        }
    }

    /// Builds a new [`FullSigner`] from `secret_key_source`, `account`, `commitment_scheme`,
    /// `proving_context`, and `rng`, using a default [`Utxo`] set and empty asset distribution.
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
        M: Default,
    {
        Self::new_inner(
            Signer::new(secret_key_source, account),
            commitment_scheme,
            proving_context,
            Default::default(),
            Default::default(),
            rng,
        )
    }

    /// Updates the internal ledger state, returing the new asset distribution.
    #[inline]
    fn sync(&mut self, updates: Vec<(Utxo<C>, EncryptedAsset<C>)>) -> SyncResult<D, C, Self>
    where
        Standard: Distribution<AssetParameters<C>>,
    {
        /* TODO:
        use manta_crypto::Set;

        let mut asset_distribution = Vec::new();

        for (utxo, encrypted_asset) in updates {
            if let Some(open_spend) = self.signer.find_open_spend(encrypted_asset) {
                asset_distribution.push((open_spend.index, open_spend.value.into_asset()));
            }
            let _ = self.utxo_set.try_insert(utxo);
        }
        */

        // TODO:
        // 1. Update the utxo_set
        // 2. Update the asset distribution
        // 3. Return asset distribution changes
        todo!()
    }

    /// Signs the `request`, generating transfer posts.
    #[inline]
    fn sign(&mut self, request: SignRequest<D, C>) -> SignResult<D, C, Self>
    where
        Standard: Distribution<AssetParameters<C>>,
    {
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
                    asset.id,
                    vec![(open_spend.index, asset.value)],
                    vec![mint_post],
                ))
            }
            SignRequest::PrivateTransfer(asset, senders, receiver) => {
                //
                todo!()
            }
            SignRequest::Reclaim(asset, senders) => {
                //
                todo!()
            }
        }
    }
}

impl<D, C, M, R> Connection<D, C> for FullSigner<D, C, M, R>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
    M: AssetMap<Key = Index<D>>,
    R: CryptoRng + RngCore,
    Standard: Distribution<AssetParameters<C>>,
{
    type SyncFuture = Ready<SyncResult<D, C, Self>>;

    type SignFuture = Ready<SignResult<D, C, Self>>;

    type NewReceiverFuture = Ready<NewReceiverResult<D, C, Self>>;

    type Error = Infallible;

    #[inline]
    fn sync(&mut self, updates: Vec<(Utxo<C>, EncryptedAsset<C>)>) -> Self::SyncFuture {
        future::ready(self.sync(updates))
    }

    #[inline]
    fn sign(&mut self, request: SignRequest<D, C>) -> Self::SignFuture {
        future::ready(self.sign(request))
    }

    #[inline]
    fn new_receiver(&mut self) -> Self::NewReceiverFuture {
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
