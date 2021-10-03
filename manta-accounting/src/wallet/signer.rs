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
    asset::{Asset, AssetId},
    fs::{Load, LoadWith, Save, SaveWith},
    identity::{self, AssetParameters, Identity},
    keys::{Account, DerivedSecretKeyGenerator, Index, KeyKind, KeyOwned},
    transfer::{
        self,
        canonical::{Mint, PrivateTransfer, Reclaim},
        IntegratedEncryptionSchemeError, ProofSystemError, ProvingContext, TransferPost,
    },
};
use alloc::vec::Vec;
use core::{
    fmt::Debug,
    future::{self, Future, Ready},
    hash::Hash,
};
use manta_crypto::ies::IntegratedEncryptionScheme;
use rand::{
    distributions::{Distribution, Standard},
    CryptoRng, RngCore,
};

/// Key-Owned Pre-Sender Type
pub type PreSender<D, C> = KeyOwned<D, identity::PreSender<C>>;

/// Key-Owned Shielded Identity Type
pub type ShieldedIdentity<D, C, I> = KeyOwned<D, identity::ShieldedIdentity<C, I>>;

/// Key-Owned Internal Receiver Type
pub type InternalReceiver<D, C, I> = KeyOwned<D, identity::InternalReceiver<C, I>>;

/// Key-Owned Open Spend Type
pub type OpenSpend<D, C> = KeyOwned<D, identity::OpenSpend<C>>;

/// Secret Key Generation Error
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "D::Error: Clone, E: Clone"),
    Copy(bound = "D::Error: Copy, E: Copy"),
    Debug(bound = "D::Error: Debug, E: Debug"),
    Eq(bound = "D::Error: Eq, E: Eq"),
    Hash(bound = "D::Error: Hash, E: Hash"),
    PartialEq(bound = "D::Error: PartialEq, E: PartialEq")
)]
pub enum SecretKeyGenerationError<D, E>
where
    D: DerivedSecretKeyGenerator,
{
    /// Secret Key Generator Error
    SecretKeyError(D::Error),

    /// Other Error
    Error(E),
}

/// Signer Connection
pub trait Connection<D, C>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
{
    /// Sign Future Type
    ///
    /// Future for the [`sign`](Self::sign) method.
    type SignFuture: Future<Output = Result<Response<D, C>, Error<D, C>>>;

    /// Signs a transfer request and returns the ledger transfer posts if successful.
    fn sign(&mut self, request: Request<D, C>) -> Self::SignFuture;
}

/// Signer Connection Request
///
/// This `struct` is used by the [`sign`](Connection::sign) method on [`Connection`].
/// See its documentation for more.
pub enum Request<D, C>
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

/// Signer Connection Response
///
/// This `struct` is created by the [`sign`](Connection::sign) method on [`Connection`].
/// See its documentation for more.
pub struct Response<D, C>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
{
    /// Final Owner Index
    pub owner: Index<D>,

    /// Transfer Posts
    pub transfers: Vec<TransferPost<C>>,
}

impl<D, C> Response<D, C>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
{
    /// Builds a new [`Response`] from `owner` and `transfers`.
    #[inline]
    pub fn new(owner: Index<D>, transfers: Vec<TransferPost<C>>) -> Self {
        Self { owner, transfers }
    }
}

/// Signer Connection Error
pub enum Error<D, C>
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
    pub fn next_shielded_identity<C, I>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
    ) -> Result<ShieldedIdentity<D, C, I>, D::Error>
    where
        C: identity::Configuration<SecretKey = D::SecretKey>,
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        Standard: Distribution<AssetParameters<C>>,
    {
        Ok(self
            .next_external_identity()?
            .map(move |identity| identity.into_shielded(commitment_scheme)))
    }

    /// Generates a new [`InternalReceiver`] to receive `asset` to this account via an
    /// internal transaction.
    #[inline]
    pub fn next_internal_receiver<C, I, R>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        rng: &mut R,
    ) -> Result<InternalReceiver<D, C, I>, SecretKeyGenerationError<D, I::Error>>
    where
        C: identity::Configuration<SecretKey = D::SecretKey>,
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        R: CryptoRng + RngCore + ?Sized,
        Standard: Distribution<AssetParameters<C>>,
    {
        self.next_internal_identity()
            .map_err(SecretKeyGenerationError::SecretKeyError)?
            .map_ok(move |identity| identity.into_internal_receiver(commitment_scheme, asset, rng))
            .map_err(SecretKeyGenerationError::Error)
    }

    /// Generates a new [`InternalReceiver`] to receive an asset, with the given `asset_id` and
    /// no value, to this account via an internal transaction.
    #[inline]
    pub fn next_empty_internal_receiver<C, I, R>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
        asset_id: AssetId,
        rng: &mut R,
    ) -> Result<InternalReceiver<D, C, I>, SecretKeyGenerationError<D, I::Error>>
    where
        C: identity::Configuration<SecretKey = D::SecretKey>,
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        R: CryptoRng + RngCore + ?Sized,
        Standard: Distribution<AssetParameters<C>>,
    {
        self.next_internal_receiver(commitment_scheme, Asset::zero(asset_id), rng)
    }

    /// Builds a [`Mint`] transaction to mint `asset` and returns the [`OpenSpend`] for that asset.
    #[inline]
    pub fn mint<C, R>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        rng: &mut R,
    ) -> Result<(Mint<C>, OpenSpend<D, C>), MintError<D, C>>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        R: CryptoRng + RngCore + ?Sized,
        Standard: Distribution<AssetParameters<C>>,
    {
        Ok(self
            .next_internal_identity()
            .map_err(MintError::SecretKeyError)?
            .map_ok(move |identity| Mint::from_identity(identity, commitment_scheme, asset, rng))
            .map_err(MintError::EncryptionError)?
            .right())
    }

    /// Builds [`PrivateTransfer`] transactions to send `asset` to an `external_receiver`.
    #[inline]
    pub fn private_transfer<C, R>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        senders: Vec<Index<D>>,
        external_receiver: transfer::ShieldedIdentity<C>,
        rng: &mut R,
    ) -> Option<Vec<PrivateTransfer<C>>>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        R: CryptoRng + RngCore + ?Sized,
        Standard: Distribution<AssetParameters<C>>,
    {
        /* TODO:
        let selection = self.balance_state.asset_map.select(asset).ok()?;

        let change_receiver = selection
            .change_receiver::<_, _, C::IntegratedEncryptionScheme, _>(
                &mut self.signer,
                asset.id,
                commitment_scheme,
                rng,
            )
            .ok()?;

        let mut pre_senders = selection
            .assets
            .into_iter()
            .map(|(index, value)| {
                self.signer
                    .get_pre_sender(index, commitment_scheme, Asset::new(asset.id, value))
            })
            .collect::<Result<Vec<_>, _>>()
            .ok()?;

        let mint = if pre_senders.len() % 2 == 1 {
            let (mint, open_spend) = self
                .signer
                .mint(commitment_scheme, Asset::zero(asset.id), rng)
                .ok()?;
            pre_senders.push(open_spend.map(move |os| os.into_pre_sender(commitment_scheme)));
            Some(mint)
        } else {
            None
        };
        */

        let external_receiver = external_receiver.into_receiver(commitment_scheme, asset, rng);

        /* TODO:
        for i in 0..(pre_senders.len() / 2) {
            PrivateTransfer::build(
                [pre_senders[2 * i], pre_senders[2 * i + 1]],
                [?, ?]
            )
        }
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

    /* TODO: Revisit how this is designed (this is part of recovery/ledger-sync):

    /// Returns an [`ExternalKeys`] generator starting from the given `index`.
    #[inline]
    fn external_keys_from_index(&self, index: D::Index) -> ExternalKeys<D> {
        self.secret_key_source
            .external_keys_from_index(self.account.as_ref(), index)
    }

    /// Returns an [`InternalKeys`] generator starting from the given `index`.
    #[inline]
    fn internal_keys_from_index(&self, index: D::Index) -> InternalKeys<D> {
        self.secret_key_source
            .internal_keys_from_index(self.account.as_ref(), index)
    }

    /// Looks for an [`OpenSpend`] for this `encrypted_asset` by checking every secret key
    /// in the iterator.
    #[inline]
    fn find_open_spend_from_iter<C, I, Iter>(
        &self,
        encrypted_asset: &EncryptedMessage<I>,
        iter: Iter,
    ) -> Option<OpenSpend<C>>
    where
        C: identity::Configuration<SecretKey = D::SecretKey>,
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        Iter: IntoIterator<Item = D::SecretKey>,
        Standard: Distribution<AssetParameters<C>>,
    {
        iter.into_iter()
            .find_map(move |k| Identity::new(k).try_open(encrypted_asset).ok())
    }

    /// Looks for an [`OpenSpend`] for this `encrypted_asset`, only trying `gap_limit`-many
    /// external keys starting from `index`.
    #[inline]
    pub fn find_external_open_spend<C, I>(
        &self,
        encrypted_asset: &EncryptedMessage<I>,
        index: D::Index,
        gap_limit: usize,
    ) -> Option<OpenSpend<C>>
    where
        C: identity::Configuration<SecretKey = D::SecretKey>,
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
        encrypted_asset: &EncryptedMessage<I>,
        index: D::Index,
        gap_limit: usize,
    ) -> Option<OpenSpend<C>>
    where
        C: identity::Configuration<SecretKey = D::SecretKey>,
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
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
    pub fn find_open_spend<C, I>(
        &self,
        encrypted_asset: &EncryptedMessage<I>,
        external_index: D::Index,
        internal_index: D::Index,
        gap_limit: usize,
    ) -> Option<(OpenSpend<C>, KeyKind)>
    where
        C: identity::Configuration<SecretKey = D::SecretKey>,
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        Standard: Distribution<AssetParameters<C>>,
    {
        // TODO: Find a way to either interleave these or parallelize these.
        if let Some(spend) =
            self.find_external_open_spend(encrypted_asset, external_index, gap_limit)
        {
            return Some((spend, KeyKind::External));
        }
        if let Some(spend) =
            self.find_internal_open_spend(encrypted_asset, internal_index, gap_limit)
        {
            return Some((spend, KeyKind::Internal));
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
pub struct FullSigner<D, C, R>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
    R: CryptoRng + RngCore + ?Sized,
{
    /// Signer
    signer: Signer<D>,

    /// Commitment Scheme
    commitment_scheme: C::CommitmentScheme,

    /// Proving Context
    proving_context: ProvingContext<C>,

    /// Random Number Generator
    rng: R,
}

impl<D, C, R> Connection<D, C> for FullSigner<D, C, R>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
    R: CryptoRng + RngCore + ?Sized,
    Standard: Distribution<AssetParameters<C>>,
{
    type SignFuture = Ready<Result<Response<D, C>, Error<D, C>>>;

    #[inline]
    fn sign(&mut self, request: Request<D, C>) -> Self::SignFuture {
        future::ready(match request {
            Request::Mint(asset) => self
                .signer
                .mint::<C, _>(&self.commitment_scheme, asset, &mut self.rng)
                .map_err(|e| match e {
                    MintError::SecretKeyError(err) => Error::SecretKeyError(err),
                    MintError::EncryptionError(err) => Error::EncryptionError(err),
                })
                .and_then(|(mint, open_spend)| {
                    /* TODO:
                    mint.into_post(
                        &self.commitment_scheme,
                        &self.proving_context,
                        &mut self.rng,
                    )
                    .map_err(Error::ProofSystemError)
                    .map(|p| Response::new(open_spend.index, vec![p]))
                    */
                    todo!()
                }),
            Request::PrivateTransfer(asset, senders, receiver) => {
                //
                todo!()
            }
            Request::Reclaim(asset, senders) => {
                //
                todo!()
            }
        })
    }
}

/// Mint Error
///
/// This `enum` is the error state for the [`mint`](Signer::mint) method on [`Signer`].
/// See its documentation for more.
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "D::Error: Clone, IntegratedEncryptionSchemeError<C>: Clone"),
    Copy(bound = "D::Error: Copy, IntegratedEncryptionSchemeError<C>: Copy"),
    Debug(bound = "D::Error: Debug, IntegratedEncryptionSchemeError<C>: Debug"),
    Eq(bound = "D::Error: Eq, IntegratedEncryptionSchemeError<C>: Eq"),
    Hash(bound = "D::Error: Hash, IntegratedEncryptionSchemeError<C>: Hash"),
    PartialEq(bound = "D::Error: PartialEq, IntegratedEncryptionSchemeError<C>: PartialEq")
)]
pub enum MintError<D, C>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration,
{
    /// Secret Key Generator Error
    SecretKeyError(D::Error),

    /// Encryption Error
    EncryptionError(IntegratedEncryptionSchemeError<C>),
}
