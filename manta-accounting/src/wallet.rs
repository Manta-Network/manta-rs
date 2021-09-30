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
// TODO: Add query builder for encrypted asset search (internal/external, gap_limit, start_index)
// TODO: Merge `AssetMap` and `LocalLedger` into one container and have it query `LedgerSource`
//       instead of `Wallet`. Then `Wallet` just has access to local ledger (also async).
//       Have then a "light wallet" which is just `Wallet` and a "heavy wallet" where the
//       local ledger and asset map are built-in to it.

use crate::{
    asset::{Asset, AssetBalance, AssetId},
    fs::{Load, LoadWith, Save, SaveWith},
    identity::{
        self, AssetParameters, Identity, InternalReceiver, InternalReceiverError, OpenSpend,
        PreSender, ShieldedIdentity, Utxo, VoidNumber,
    },
    keys::{Account, DerivedSecretKeyGenerator, InternalKeys, KeyKind},
    transfer::{
        self,
        canonical::{Mint, PrivateTransfer, Reclaim},
        EncryptedAsset, IntegratedEncryptionSchemeError, ReceiverPost, SenderPost, TransferPost,
    },
};
use alloc::{vec, vec::Vec};
use core::{convert::Infallible, fmt::Debug, future::Future, hash::Hash, marker::PhantomData};
use manta_crypto::ies::IntegratedEncryptionScheme;
use rand::{
    distributions::{Distribution, Standard},
    CryptoRng, RngCore,
};

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

    /// Returns the identity for a key of the given `kind` and `index`.
    #[inline]
    pub fn get<C>(&self, kind: KeyKind, index: D::Index) -> Result<Identity<C>, D::Error>
    where
        C: identity::Configuration<SecretKey = D::SecretKey>,
    {
        self.secret_key_source
            .generate_key(kind, self.account.as_ref(), &index)
            .map(Identity::new)
    }

    /// Generates the next identity of the given `kind` for this signer.
    #[inline]
    pub fn next<C>(&mut self, kind: KeyKind) -> Result<Identity<C>, D::Error>
    where
        C: identity::Configuration<SecretKey = D::SecretKey>,
    {
        self.account
            .next_key(&self.secret_key_source, kind)
            .map(Identity::new)
    }

    /// Generates the next external identity for this signer.
    #[inline]
    pub fn next_external<C>(&mut self) -> Result<Identity<C>, D::Error>
    where
        C: identity::Configuration<SecretKey = D::SecretKey>,
    {
        self.account
            .next_external_key(&self.secret_key_source)
            .map(Identity::new)
    }

    /// Generates the next internal identity for this signer.
    #[inline]
    pub fn next_internal<C>(&mut self) -> Result<Identity<C>, D::Error>
    where
        C: identity::Configuration<SecretKey = D::SecretKey>,
    {
        self.account
            .next_internal_key(&self.secret_key_source)
            .map(Identity::new)
    }

    /// Generates a new [`ShieldedIdentity`] to receive assets to this account via an external
    /// transaction.
    #[inline]
    pub fn next_shielded_identity<C, I>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
    ) -> Result<ShieldedIdentity<C, I>, D::Error>
    where
        C: identity::Configuration<SecretKey = D::SecretKey>,
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        Standard: Distribution<AssetParameters<C>>,
    {
        self.next_external()
            .map(move |identity| identity.into_shielded(commitment_scheme))
    }

    /// Generates a new [`InternalReceiver`] to receive `asset` to this account via an
    /// internal transaction.
    #[inline]
    pub fn next_internal_receiver<C, I, R>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        rng: &mut R,
    ) -> Result<InternalReceiver<C, I>, InternalReceiverError<InternalKeys<D>, I>>
    where
        C: identity::Configuration<SecretKey = D::SecretKey>,
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        R: CryptoRng + RngCore + ?Sized,
        Standard: Distribution<AssetParameters<C>>,
    {
        self.next_internal()
            .map_err(InternalReceiverError::SecretKeyError)?
            .into_internal_receiver(commitment_scheme, asset, rng)
            .map_err(InternalReceiverError::EncryptionError)
    }

    /// Generates a new [`InternalReceiver`] to receive an asset, with the given `asset_id` and
    /// no value, to this account via an internal transaction.
    #[inline]
    pub fn next_empty_internal_receiver<C, I, R>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
        asset_id: AssetId,
        rng: &mut R,
    ) -> Result<InternalReceiver<C, I>, InternalReceiverError<InternalKeys<D>, I>>
    where
        C: identity::Configuration<SecretKey = D::SecretKey>,
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        R: CryptoRng + RngCore + ?Sized,
        Standard: Distribution<AssetParameters<C>>,
    {
        self.next_internal_receiver(commitment_scheme, Asset::zero(asset_id), rng)
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

/// Ledger Source
pub trait LedgerSource<C>
where
    C: transfer::Configuration,
{
    /// Sync Future Type
    ///
    /// Future for the [`sync`](Self::sync) method.
    type SyncFuture: Future<Output = Result<SyncResponse<C, Self>, Self::Error>>;

    /// Send Future Type
    ///
    /// Future for the [`send`](Self::send) method.
    type SendFuture: Future<Output = Result<SendResponse<C, Self>, Self::Error>>;

    /// Ledger State Checkpoint Type
    type Checkpoint: Default + Ord;

    /// Error Type
    type Error;

    /// Pulls data from the ledger starting from `checkpoint`, returning the current
    /// [`Checkpoint`](Self::Checkpoint).
    fn sync(&self, checkpoint: &Self::Checkpoint) -> Self::SyncFuture;

    /// Pulls all of the data from the entire history of the ledger, returning the current
    /// [`Checkpoint`](Self::Checkpoint).
    #[inline]
    fn sync_all(&self) -> Self::SyncFuture {
        self.sync(&Default::default())
    }

    /// Sends `transfers` to the ledger, returning the current [`Checkpoint`](Self::Checkpoint)
    /// and the status of the transfers.
    fn send(&self, transfers: Vec<TransferPost<C>>) -> Self::SendFuture;

    /// Sends `transfer` to the ledger, returning the current [`Checkpoint`](Self::Checkpoint)
    /// and the status of the transfer.
    #[inline]
    fn send_one(&self, transfer: TransferPost<C>) -> Self::SendFuture {
        self.send(vec![transfer])
    }
}

/// Ledger Source Sync Response
///
/// This `struct` is created by the [`sync`](LedgerSource::sync) method on [`LedgerSource`].
/// See its documentation for more.
pub struct SyncResponse<C, LS>
where
    C: transfer::Configuration,
    LS: LedgerSource<C> + ?Sized,
{
    /// Current Ledger Checkpoint
    pub checkpoint: LS::Checkpoint,

    /// New Void Numbers
    pub void_numbers: Vec<VoidNumber<C>>,

    /// New UTXOS
    pub utxos: Vec<Utxo<C>>,

    /// New Encrypted Assets
    pub encrypted_assets: Vec<EncryptedAsset<C>>,
}

/// Ledger Source Send Response
///
/// This `struct` is created by the [`send`](LedgerSource::send) method on [`LedgerSource`].
/// See its documentation for more.
pub struct SendResponse<C, LS>
where
    C: transfer::Configuration,
    LS: LedgerSource<C> + ?Sized,
{
    /// Current Ledger Checkpoint
    pub checkpoint: LS::Checkpoint,

    /// Ledger Responses
    // FIXME: Design responses.
    pub responses: Vec<bool>,
}

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

    /// Mutates the asset balance for `id` to the result of `f` if it succeeds, returning the
    /// new balance.
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

/// Asset Key
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = "D::Index: Copy"),
    Debug(bound = "D::Index: Debug"),
    Eq(bound = "D::Index: Eq"),
    Hash(bound = "D::Index: Hash"),
    PartialEq(bound = "D::Index: PartialEq")
)]
pub struct AssetKey<D>
where
    D: DerivedSecretKeyGenerator,
{
    /// Key Kind
    pub kind: KeyKind,

    /// Key Index
    pub index: D::Index,

    /// Value stored at this key
    pub value: AssetBalance,
}

impl<D> AssetKey<D>
where
    D: DerivedSecretKeyGenerator,
{
    /// Builds a [`PreSender`] for `self`, using `signer` to generate the secret key.
    #[inline]
    pub fn into_pre_sender<C>(
        self,
        signer: &Signer<D>,
        commitment_scheme: &C::CommitmentScheme,
        asset_id: AssetId,
    ) -> Result<PreSender<C>, D::Error>
    where
        C: identity::Configuration<SecretKey = D::SecretKey>,
        Standard: Distribution<AssetParameters<C>>,
    {
        Ok(signer
            .get(self.kind, self.index)?
            .into_pre_sender(commitment_scheme, Asset::new(asset_id, self.value)))
    }
}

/// Asset Selection
pub struct AssetSelection<D, S>
where
    D: DerivedSecretKeyGenerator,
    S: AssetSelector<D> + ?Sized,
{
    /// Change Amount
    pub change: AssetBalance,

    /// Asset Keys
    pub keys: S::Keys,
}

impl<D, S> AssetSelection<D, S>
where
    D: DerivedSecretKeyGenerator,
    S: AssetSelector<D> + ?Sized,
{
    /* TODO:
    ///
    #[inline]
    pub fn make_change(&self, signer: &Signer<D>, n: usize) -> Option<Vec<()>> {
        let amounts = self.change.make_change(n)?;
        todo!()
    }
    */
}

/// Asset Selector
pub trait AssetSelector<D>
where
    D: DerivedSecretKeyGenerator,
{
    /// Keys Type
    type Keys: Iterator<Item = AssetKey<D>>;

    /// Error Type
    type Error;

    /// Selects assets which total up to at least `asset` in value.
    fn select(&self, asset: Asset) -> Result<AssetSelection<D, Self>, Self::Error>;
}

/// Ledger Ownership Marker
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Ownership {
    /// Key Ownership
    Key(KeyKind),

    /// Unknown Self-Ownership
    Unknown,

    /// Ownership by Others
    Other,
}

impl Default for Ownership {
    #[inline]
    fn default() -> Self {
        Self::Unknown
    }
}

/// Ledger Data
pub enum LedgerData<C>
where
    C: transfer::Configuration,
{
    /// Sender Data
    Sender(VoidNumber<C>),

    /// Receiver Data
    Receiver(Utxo<C>, EncryptedAsset<C>),
}

/// Ledger Post Entry
pub enum PostEntry<'t, C>
where
    C: transfer::Configuration,
{
    /// Sender Entry
    Sender(&'t SenderPost<C>),

    /// Receiver Entry
    Receiver(&'t ReceiverPost<C>),
}

/// Local Ledger
pub trait LocalLedger<C>
where
    C: transfer::Configuration,
{
    /// Ledger State Checkpoint Type
    type Checkpoint: Default + Ord;

    /// Data Preservation Key
    type Key;

    /// Data Access Error
    type Error;

    /// Returns the checkpoint of the local ledger.
    fn checkpoint(&self) -> &Self::Checkpoint;

    /// Sets the checkpoint of the local ledger to `checkpoint`.
    fn set_checkpoint(&mut self, checkpoint: Self::Checkpoint);

    /// Saves `data` into the local ledger.
    fn push(&mut self, data: LedgerData<C>) -> Result<(), Self::Error>;

    /// Prepares a `post` in the local ledger, returning a key to decide if the post should
    /// be preserved by the ledger or not.
    fn prepare(&mut self, post: PostEntry<C>, ownership: Ownership) -> Self::Key;

    /// Preserves the data associated to the `key`.
    fn keep(&mut self, key: Self::Key);

    /// Drops the data associated to the `key`.
    fn drop(&mut self, key: Self::Key);
}

/// Wallet Balance State
pub struct BalanceState<C, L, M>
where
    C: transfer::Configuration,
    L: LocalLedger<C>,
    M: AssetMap,
{
    /// Secret Asset Map
    secret_assets: M,

    /// Public Asset Map
    // TODO: Find a way to connect this.
    _public_assets: M,

    /// Local Ledger
    ledger: L,

    /// Type Parameter Marker
    __: PhantomData<C>,
}

impl<C, L, M> BalanceState<C, L, M>
where
    C: transfer::Configuration,
    L: LocalLedger<C>,
    M: AssetMap,
{
    /// Returns the [`Checkpoint`](LocalLedger::Checkpoint) associated with the local ledger.
    #[inline]
    pub fn checkpoint(&self) -> &L::Checkpoint {
        self.ledger.checkpoint()
    }

    /// Synchronizes `self` with the `ledger`.
    #[inline]
    pub async fn sync<LS>(&mut self, ledger: &LS) -> Result<(), LS::Error>
    where
        LS: LedgerSource<C, Checkpoint = L::Checkpoint> + ?Sized,
    {
        let SyncResponse {
            checkpoint,
            void_numbers,
            utxos,
            encrypted_assets,
        } = ledger.sync(self.checkpoint()).await?;

        for void_number in void_numbers {
            // TODO: Only keep the ones we care about. How do we alert the local ledger? We have to
            //       communicate with it when we try to send transactions to a ledger source.
            //       Do we care about keeping void numbers? Maybe only for recovery?
            //
            let _ = self.ledger.push(LedgerData::Sender(void_number));
        }

        for (utxo, encrypted_asset) in utxos.into_iter().zip(encrypted_assets) {
            // TODO: Only keep the ones we care about. For internal transactions we know the `utxo`
            //       ahead of time. For external ones, we have to get the `asset` first.
            //
            // TODO: Decrypt them on the way in ... threads? For internal transactions we know the
            //       `encrypted_asset` ahead of time, and we know it decrypted too. For external
            //       transactions we have to keep all of them since we have to try and decrypt all
            //       of them.
            //
            let _ = self
                .ledger
                .push(LedgerData::Receiver(utxo, encrypted_asset));
        }

        self.ledger.set_checkpoint(checkpoint);

        // FIXME: Deposit into `secret_assets` and `public_assets`.

        Ok(())
    }

    /// Sends the `transfers` to the `ledger`.
    #[inline]
    pub async fn send<LS>(
        &mut self,
        transfers: Vec<TransferPost<C>>,
        ledger: &LS,
    ) -> Result<(), LS::Error>
    where
        LS: LedgerSource<C, Checkpoint = L::Checkpoint> + ?Sized,
    {
        // FIXME: How do to batched transfers? Those above are not necessarily "batched-atomic".
        //
        // TODO: When sending to the ledger, we really have to set up a backup state in case we
        //       missed the "send window", and we need to recover. We can also hint to the local
        //       ledger that we are about to send some transactions and so it should know which
        //       `utxo`s and such are important to keep when it sees them appear later in the real
        //       ledger state.
        //
        //       Sender Posts:   `void_number`
        //       Receiver Posts: `utxo`, `encrypted_asset`
        //

        let mut keys = Vec::new();

        for transfer in &transfers {
            for sender in &transfer.sender_posts {
                keys.push(
                    self.ledger
                        .prepare(PostEntry::Sender(sender), Default::default()),
                );
            }
            for receiver in &transfer.receiver_posts {
                keys.push(
                    self.ledger
                        .prepare(PostEntry::Receiver(receiver), Default::default()),
                );
            }
        }

        keys.shrink_to_fit();

        let SendResponse {
            checkpoint,
            responses,
        } = ledger.send(transfers).await?;

        // TODO: Revoke keys if the transfer failed, otherwise recover from the failure.

        let _ = responses;

        self.ledger.set_checkpoint(checkpoint);

        // FIXME: Withdraw from `secret_assets` and `public_assets`.

        todo!()
    }
}

/* TODO:
/// Wallet
pub struct Wallet<C, D, LL, SM, PM = SM>
where
    C: transfer::Configuration,
    D: DerivedSecretKeyGenerator<SecretKey = C::SecretKey>,
    LL: LocalLedger<C>,
    SM: AssetMap,
    PM: AssetMap,
{
    /// Wallet Signer
    signer: Signer<D>,

    /// Wallet Balance State
    balance_state: BalanceState<C, LL, SM, PM>,
}
*/

/// Wallet
pub struct Wallet<D>
where
    D: DerivedSecretKeyGenerator,
{
    /// Wallet Signer
    signer: Signer<D>,
}

impl<D> Wallet<D>
where
    D: DerivedSecretKeyGenerator,
{
    /// Builds a new [`Wallet`] for `signer`.
    #[inline]
    pub fn new(signer: Signer<D>) -> Self {
        Self { signer }
    }

    /// Builds a [`Mint`] transaction to mint `asset` and returns the [`OpenSpend`] for that asset.
    #[inline]
    pub fn mint<C, R>(
        &mut self,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        rng: &mut R,
    ) -> Result<(Mint<C>, OpenSpend<C>), MintError<D, C>>
    where
        C: transfer::Configuration<SecretKey = D::SecretKey>,
        R: CryptoRng + RngCore + ?Sized,
        Standard: Distribution<AssetParameters<C>>,
    {
        Mint::from_identity(
            self.signer
                .next_internal()
                .map_err(MintError::SecretKeyError)?,
            commitment_scheme,
            asset,
            rng,
        )
        .map_err(MintError::EncryptionError)
    }

    /// TODO: Builds [`PrivateTransfer`] transactions to send `asset` to an `external_receiver`.
    #[inline]
    pub fn batch_private_transfer_external<C, R>(
        &self,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        external_receiver: ShieldedIdentity<C, C::IntegratedEncryptionScheme>,
        rng: &mut R,
    ) -> Option<Vec<PrivateTransfer<C>>>
    where
        C: transfer::Configuration,
        R: CryptoRng + RngCore + ?Sized,
    {
        // TODO: spec:
        // 1. check that we have enough `asset` in the secret_assets map
        // 2. find out which keys have control over `asset`
        // 3. build two senders and build a receiver and a change receiver for the extra change

        let _ = external_receiver.into_receiver(commitment_scheme, asset, rng);
        // TODO: PrivateTransfer::build([fst, snd], [external_receiver, change])
        todo!()
    }

    /// TODO: Builds a [`Reclaim`] transaction.
    #[inline]
    pub fn reclaim<C, R>(
        &self,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        rng: &mut R,
    ) -> Option<Reclaim<C>>
    where
        C: transfer::Configuration,
        R: CryptoRng + RngCore + ?Sized,
    {
        let _ = (commitment_scheme, asset, rng);
        // TODO: Reclaim::build(senders, receiver, reclaim);
        todo!()
    }
}

impl<D> Load for Wallet<D>
where
    D: DerivedSecretKeyGenerator,
    Signer<D>: Load,
{
    type Path = <Signer<D> as Load>::Path;

    type LoadingKey = <Signer<D> as Load>::LoadingKey;

    type Error = <Signer<D> as Load>::Error;

    #[inline]
    fn load<P>(path: P, loading_key: &Self::LoadingKey) -> Result<Self, Self::Error>
    where
        P: AsRef<Self::Path>,
    {
        // TODO: Also add a way to save `BalanceState`.
        Ok(Self::new(Signer::<D>::load(path, loading_key)?))
    }
}

impl<D> Save for Wallet<D>
where
    D: DerivedSecretKeyGenerator,
    Signer<D>: Save,
{
    type Path = <Signer<D> as Save>::Path;

    type SavingKey = <Signer<D> as Save>::SavingKey;

    type Error = <Signer<D> as Save>::Error;

    #[inline]
    fn save<P>(self, path: P, saving_key: &Self::SavingKey) -> Result<(), Self::Error>
    where
        P: AsRef<Self::Path>,
    {
        // TODO: Also add a way to save `BalanceState`.
        self.signer.save(path, saving_key)
    }
}

/// Mint Error
///
/// This `enum` is the error state for the [`mint`] method on [`Wallet`].
/// See its documentation for more.
///
/// [`mint`]: Wallet::mint
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
