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

//! Wallet Abstractions

// TODO: How to manage accounts? Wallet should have a fixed account or not?
// TODO: Is recovery different than just building a fresh `Wallet` instance?
// TODO: Add encrypt-to-disk and decrypt-from-disk methods to save the wallet state.
// TODO: Add query builder for encrypted asset search (internal/external, gap_limit, start_index)

use crate::{
    asset::{Asset, AssetBalance, AssetId},
    fs::{Load, Save},
    identity::{
        AssetParameters, Identity, IdentityConfiguration, OpenSpend, Receiver, ShieldedIdentity,
        Spend,
    },
    keys::{self, DerivedSecretKeyGenerator, ExternalKeys, InternalKeys},
    ledger::Ledger,
    transfer::{SecretTransfer, TransferConfiguration},
};
use core::{convert::Infallible, fmt::Debug, hash::Hash};
use manta_crypto::ies::{EncryptedMessage, IntegratedEncryptionScheme};
use rand::{
    distributions::{Distribution, Standard},
    CryptoRng, RngCore,
};

/// Asset Map
pub trait AssetMap {
    /// Returns the current balance associated with this `id`.
    fn balance(&self, id: AssetId) -> AssetBalance;

    /// Returns `true` if `self` contains at least `asset.value` of the asset of kind `asset.id`.
    #[inline]
    fn contains(&self, asset: Asset) -> bool {
        self.balance(asset.id) >= asset.value
    }

    /// Sets the asset balance for `id` to `value`.
    fn set_balance(&mut self, id: AssetId, value: AssetBalance);

    /// Sets the asset balance for `asset.id` to `asset.value`.
    #[inline]
    fn set_asset(&mut self, asset: Asset) {
        self.set_balance(asset.id, asset.value)
    }

    /// Mutates the asset balance for `id` to the result of `f` if it succeeds.
    #[inline]
    #[must_use = "this only modifies the stored value if the function call succeeded"]
    fn mutate<F, E>(&mut self, id: AssetId, f: F) -> Result<AssetBalance, E>
    where
        F: FnOnce(AssetBalance) -> Result<AssetBalance, E>,
    {
        // TODO: use `try_trait_v2` when it comes out
        f(self.balance(id)).map(move |v| {
            self.set_balance(id, v);
            v
        })
    }

    /// Performs a deposit of value `asset.value` into the balance of `asset.id`,
    /// returning the new balance for this `asset.id` if it did not overflow.
    ///
    /// To skip the overflow check, use [`deposit_unchecked`](Self::deposit_unchecked) instead.
    #[inline]
    #[must_use = "this only modifies the stored value if the addition did not overflow"]
    fn deposit(&mut self, asset: Asset) -> Option<AssetBalance> {
        self.mutate(asset.id, move |v| v.checked_add(asset.value).ok_or(()))
            .ok()
    }

    /// Performs a deposit of value `asset.value` into the balance of `asset.id`,
    /// without checking for overflow, returning the new balance for this `asset.id`.
    ///
    /// # Panics
    ///
    /// This function panics on overflow. To explicitly check for overflow, use
    /// [`deposit`](Self::deposit) instead.
    #[inline]
    fn deposit_unchecked(&mut self, asset: Asset) -> AssetBalance {
        self.mutate::<_, Infallible>(asset.id, move |v| Ok(v + asset.value))
            .unwrap()
    }

    /// Performs a withdrawl of value `asset.value` from the balance of `asset.id`,
    /// returning the new balance for this `asset.id` if it did not overflow.
    ///
    /// To skip the overflow check, use [`withdraw_unchecked`](Self::withdraw_unchecked) instead.
    #[inline]
    #[must_use = "this only modifies the stored value if the subtraction did not overflow"]
    fn withdraw(&mut self, asset: Asset) -> Option<AssetBalance> {
        self.mutate(asset.id, move |v| v.checked_sub(asset.value).ok_or(()))
            .ok()
    }

    /// Performs a withdrawl of value `asset.value` from the balance of `asset.id`,
    /// without checking for overflow, returning the new balance for this `asset.id`.
    ///
    /// # Panics
    ///
    /// This function panics on overflow. To explicitly check for overflow, use
    /// [`withdraw`](Self::withdraw) instead.
    #[inline]
    fn withdraw_unchecked(&mut self, asset: Asset) -> AssetBalance {
        self.mutate::<_, Infallible>(asset.id, move |v| Ok(v - asset.value))
            .unwrap()
    }
}

/// Wallet
pub struct Wallet<D, M>
where
    D: DerivedSecretKeyGenerator,
    M: AssetMap,
{
    /// Secret Key Source
    secret_key_source: D,

    /// Wallet Account
    account: D::Account,

    /// External Transaction Running Index
    external_index: D::Index,

    /// Internal Transaction Running Index
    internal_index: D::Index,

    /// Public Asset Map
    public_assets: M,

    /// Secret Asset Map
    secret_assets: M,
}

impl<D, M> Wallet<D, M>
where
    D: DerivedSecretKeyGenerator,
    M: AssetMap,
{
    /// Builds a new [`Wallet`] for `account` from a `secret_key_source`.
    #[inline]
    pub fn new(secret_key_source: D, account: D::Account) -> Self
    where
        M: Default,
    {
        Self::with_balances(
            secret_key_source,
            account,
            Default::default(),
            Default::default(),
        )
    }

    /// Builds a new [`Wallet`] for `account` from a `secret_key_source` and pre-built
    /// `public_assets` map and `secret_assets` map.
    #[inline]
    pub fn with_balances(
        secret_key_source: D,
        account: D::Account,
        public_assets: M,
        secret_assets: M,
    ) -> Self {
        Self {
            secret_key_source,
            account,
            external_index: Default::default(),
            internal_index: Default::default(),
            public_assets,
            secret_assets,
        }
    }

    /// Generates the next external key for this wallet.
    #[inline]
    fn next_external_key(&mut self) -> Result<D::SecretKey, D::Error> {
        keys::next_external(
            &self.secret_key_source,
            &self.account,
            &mut self.external_index,
        )
    }

    /// Generates the next internal key for this wallet.
    #[inline]
    fn next_internal_key(&mut self) -> Result<D::SecretKey, D::Error> {
        keys::next_internal(
            &self.secret_key_source,
            &self.account,
            &mut self.internal_index,
        )
    }

    /// Generates the next external identity for this wallet.
    #[inline]
    fn next_external_identity<C>(&mut self) -> Result<Identity<C>, D::Error>
    where
        C: IdentityConfiguration<SecretKey = D::SecretKey>,
    {
        self.next_external_key().map(Identity::new)
    }

    /// Generates the next internal identity for this wallet.
    #[inline]
    fn next_internal_identity<C>(&mut self) -> Result<Identity<C>, D::Error>
    where
        C: IdentityConfiguration<SecretKey = D::SecretKey>,
    {
        self.next_internal_key().map(Identity::new)
    }

    /// Returns an [`ExternalKeys`] generator starting from the given `index`.
    #[inline]
    fn external_keys_from_index(&self, index: D::Index) -> ExternalKeys<D> {
        self.secret_key_source
            .external_keys_from_index(&self.account, index)
    }

    /// Returns an [`InternalKeys`] generator starting from the given `index`.
    #[inline]
    fn internal_keys_from_index(&self, index: D::Index) -> InternalKeys<D> {
        self.secret_key_source
            .internal_keys_from_index(&self.account, index)
    }

    /// Looks for an [`OpenSpend`] for this `encrypted_asset` by checking every secret key
    /// in the iterator.
    #[inline]
    fn find_open_spend_from_iter<C, I, Iter>(
        &self,
        encrypted_asset: EncryptedMessage<I>,
        iter: Iter,
    ) -> Option<OpenSpend<C>>
    where
        C: IdentityConfiguration<SecretKey = D::SecretKey>,
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        Iter: IntoIterator<Item = D::SecretKey>,
        Standard: Distribution<AssetParameters<C>>,
    {
        iter.into_iter()
            .find_map(move |k| Identity::new(k).try_open(&encrypted_asset).ok())
    }

    /// Looks for an [`OpenSpend`] for this `encrypted_asset`, only trying `gap_limit`-many
    /// external and internal keys starting from `index`.
    #[inline]
    pub fn find_open_spend<C, I>(
        &self,
        encrypted_asset: EncryptedMessage<I>,
        index: D::Index,
        gap_limit: usize,
    ) -> Option<OpenSpend<C>>
    where
        C: IdentityConfiguration<SecretKey = D::SecretKey>,
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        Standard: Distribution<AssetParameters<C>>,
    {
        // TODO: Return which kind of spend it was, internal or external.

        let interleaved_keys = self
            .external_keys_from_index(index.clone())
            .zip(self.internal_keys_from_index(index))
            .flat_map(move |(e, i)| [e, i])
            .take(2 * gap_limit);

        self.find_open_spend_from_iter(encrypted_asset, interleaved_keys)
    }

    /// Looks for an [`OpenSpend`] for this `encrypted_asset`, only trying `gap_limit`-many
    /// external keys starting from `index`.
    #[inline]
    pub fn find_external_open_spend<C, I>(
        &self,
        encrypted_asset: EncryptedMessage<I>,
        index: D::Index,
        gap_limit: usize,
    ) -> Option<OpenSpend<C>>
    where
        C: IdentityConfiguration<SecretKey = D::SecretKey>,
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
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
    pub fn find_internal_open_spend<C, I>(
        &self,
        encrypted_asset: EncryptedMessage<I>,
        index: D::Index,
        gap_limit: usize,
    ) -> Option<OpenSpend<C>>
    where
        C: IdentityConfiguration<SecretKey = D::SecretKey>,
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        Standard: Distribution<AssetParameters<C>>,
    {
        self.find_open_spend_from_iter(
            encrypted_asset,
            self.internal_keys_from_index(index).take(gap_limit),
        )
    }

    /// Updates `self` with new information from the ledger.
    pub fn pull_updates<L>(&mut self, ledger: &L)
    where
        L: Ledger,
    {
        // TODO: pull updates from the ledger
        //         1. Download the new encrypted notes and try to decrypt them using the latest
        //            keys that haven't been used.
        //         2. Download the new vns and utxos and check that we can still spend all the
        //            tokens we think we can spend.
        //         3. compute the new deposits and withdrawls
        let _ = ledger;
        todo!()
    }

    /// Generates a new [`ShieldedIdentity`] to receive assets to this wallet via an external
    /// transaction.
    #[inline]
    pub fn generate_external_receiver<C, I>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
    ) -> Result<ShieldedIdentity<C, I>, D::Error>
    where
        C: IdentityConfiguration<SecretKey = D::SecretKey>,
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        Standard: Distribution<AssetParameters<C>>,
    {
        self.next_external_identity()
            .map(move |identity| identity.into_shielded(commitment_scheme))
    }

    /// Generates a new [`Receiver`]-[`Spend`] pair to receive `asset` to this wallet via an
    /// internal transaction.
    #[allow(clippy::type_complexity)] // NOTE: This is not very complex.
    #[inline]
    pub fn generate_internal_receiver<C, I, R>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        rng: &mut R,
    ) -> Result<(Receiver<C, I>, Spend<C, I>), InternalReceiverError<D, I>>
    where
        C: IdentityConfiguration<SecretKey = D::SecretKey>,
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        R: CryptoRng + RngCore + ?Sized,
        Standard: Distribution<AssetParameters<C>>,
    {
        let (shielded_identity, spend) = self
            .next_internal_identity()
            .map_err(InternalReceiverError::SecretKeyGenerationError)?
            .into_receiver(commitment_scheme);
        Ok((
            shielded_identity
                .into_receiver(commitment_scheme, asset, rng)
                .map_err(InternalReceiverError::EncryptionError)?,
            spend,
        ))
    }

    /// Builds a [`SecretTransfer`] transaction to send `asset` to an `external_receiver`.
    pub fn secret_send<T, R>(
        &self,
        commitment_scheme: &T::CommitmentScheme,
        asset: Asset,
        external_receiver: ShieldedIdentity<T, T::IntegratedEncryptionScheme>,
        rng: &mut R,
    ) -> Option<SecretTransfer<T, 2, 2>>
    where
        T: TransferConfiguration,
        R: CryptoRng + RngCore + ?Sized,
    {
        // TODO: spec:
        // 1. check that we have enough `asset` in the secret_assets map
        // 2. find out which keys have control over `asset`
        // 3. build two senders and build a receiver and a change receiver for the extra change

        /*
        let sender = Sender::generate(self.secret_key_source, commitment_scheme);
        */
        let _ = external_receiver.into_receiver(commitment_scheme, asset, rng);
        todo!()
    }
}

impl<D, M> Load for Wallet<D, M>
where
    D: DerivedSecretKeyGenerator + Load,
    M: AssetMap + Default,
{
    type Path = D::Path;

    type LoadingKey = D::LoadingKey;

    type Error = <D as Load>::Error;

    #[inline]
    fn load<P>(path: P, loading_key: &Self::LoadingKey) -> Result<Self, Self::Error>
    where
        P: AsRef<Self::Path>,
    {
        Ok(Self::new(D::load(path, loading_key)?, Default::default()))
    }
}

impl<D, M> Save for Wallet<D, M>
where
    D: DerivedSecretKeyGenerator + Save,
    M: AssetMap + Default,
{
    type Path = D::Path;

    type SavingKey = D::SavingKey;

    type Error = <D as Save>::Error;

    #[inline]
    fn save<P>(self, path: P, saving_key: &Self::SavingKey) -> Result<(), Self::Error>
    where
        P: AsRef<Self::Path>,
    {
        self.secret_key_source.save(path, saving_key)
    }
}

/// Internal Receiver Error
///
/// This `enum` is the error state for the [`generate_internal_receiver`] method on [`Wallet`].
/// See its documentation for more.
///
/// [`generate_internal_receiver`]: Wallet::generate_internal_receiver
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "D::Error: Clone, I::Error: Clone"),
    Copy(bound = "D::Error: Copy, I::Error: Copy"),
    Debug(bound = "D::Error: Debug, I::Error: Debug"),
    Eq(bound = "D::Error: Eq, I::Error: Eq"),
    Hash(bound = "D::Error: Hash, I::Error: Hash"),
    PartialEq(bound = "D::Error: PartialEq, I::Error: PartialEq")
)]
pub enum InternalReceiverError<D, I>
where
    D: DerivedSecretKeyGenerator,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
{
    /// Secret Key Generation Error
    SecretKeyGenerationError(D::Error),

    /// Encryption Error
    EncryptionError(I::Error),
}
