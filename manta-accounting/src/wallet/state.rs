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

//! Wallet State

use crate::{
    asset::{Asset, AssetBalance, AssetId},
    identity::{self, AssetParameters, Utxo, VoidNumber},
    keys::{DerivedSecretKeyGenerator, Index, KeyKind},
    transfer::{self, EncryptedAsset, ReceiverPost, SenderPost, TransferPost},
    wallet::{
        ledger::{self, SendResponse, SyncResponse},
        signer::{self, InternalReceiver, SecretKeyGenerationError, Signer},
    },
};
use alloc::vec::Vec;
use core::{fmt::Debug, hash::Hash, marker::PhantomData};
use manta_crypto::ies::IntegratedEncryptionScheme;
use rand::{
    distributions::{Distribution, Standard},
    CryptoRng, RngCore,
};

/// Asset Map
pub trait AssetMap {
    /// Key Type
    ///
    /// Keys are used to access the underlying asset balances. See [`withdraw`](Self::withdraw)
    /// and [`deposit`](Self::deposit) for uses of the [`Key`](Self::Key) type.
    type Key;

    /// Assets Iterator Type
    ///
    /// This type is returned by [`select`](Self::select) when looking for assets in the map.
    type Assets: IntoIterator<Item = (Self::Key, AssetBalance)>;

    /// Error Type
    type Error;

    /// Selects asset keys which total up to at least `asset` in value.
    fn select(&self, asset: Asset) -> AssetSelection<Self>;

    /// Withdraws the asset stored at `key`.
    fn withdraw(&mut self, key: Self::Key) -> Result<(), Self::Error>;

    /// Deposits `asset` at the key stored at `kind` and `index`.
    fn deposit(&mut self, key: Self::Key, asset: Asset) -> Result<(), Self::Error>;

    /// Returns the current balance associated with this `id`.
    fn balance(&self, id: AssetId) -> AssetBalance;

    /// Returns true if `self` contains at least `asset.value` of the asset of kind `asset.id`.
    #[inline]
    fn contains(&self, asset: Asset) -> bool {
        self.balance(asset.id) >= asset.value
    }
}

/// Asset Selection
pub struct AssetSelection<S>
where
    S: AssetMap + ?Sized,
{
    /// Change Amount
    pub change: AssetBalance,

    /// Sender Assets
    pub assets: S::Assets,
}

impl<S> AssetSelection<S>
where
    S: AssetMap + ?Sized,
{
    /// Builds an [`InternalReceiver`] to capture the `change` from the given [`AssetSelection`].
    #[inline]
    pub fn change_receiver<D, C, I, R>(
        &self,
        signer: &mut Signer<D>,
        asset_id: AssetId,
        commitment_scheme: &C::CommitmentScheme,
        rng: &mut R,
    ) -> Result<InternalReceiver<D, C, I>, SecretKeyGenerationError<D, I::Error>>
    where
        S: AssetMap<Key = Index<D>>,
        D: DerivedSecretKeyGenerator,
        C: identity::Configuration<SecretKey = D::SecretKey>,
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        R: CryptoRng + RngCore + ?Sized,
        Standard: Distribution<AssetParameters<C>>,
    {
        signer.next_internal_receiver(commitment_scheme, Asset::new(asset_id, self.change), rng)
    }

    /// Builds a vector of `n` internal receivers to capture the `change` from the given
    /// [`AssetSelection`].
    ///
    /// # Panics
    ///
    /// This method panics if `n == 0`.
    #[inline]
    pub fn change_receivers<D, C, I, R>(
        &self,
        signer: &mut Signer<D>,
        asset_id: AssetId,
        n: usize,
        commitment_scheme: &C::CommitmentScheme,
        rng: &mut R,
    ) -> Result<Vec<InternalReceiver<D, C, I>>, SecretKeyGenerationError<D, I::Error>>
    where
        S: AssetMap<Key = Index<D>>,
        D: DerivedSecretKeyGenerator,
        C: identity::Configuration<SecretKey = D::SecretKey>,
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        R: CryptoRng + RngCore + ?Sized,
        Standard: Distribution<AssetParameters<C>>,
    {
        self.change
            .make_change(n)
            .unwrap()
            .map(move |value| {
                signer.next_internal_receiver(commitment_scheme, Asset::new(asset_id, value), rng)
            })
            .collect()
    }
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

/// Local Ledger State
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
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "M: Clone, L: Clone"),
    Copy(bound = "M: Copy, L: Copy"),
    Debug(bound = "M: Debug, L: Debug"),
    Default(bound = "M: Default, L: Default"),
    Eq(bound = "M: Eq, L: Eq"),
    Hash(bound = "M: Hash, L: Hash"),
    PartialEq(bound = "M: PartialEq, L: PartialEq")
)]
pub struct BalanceState<C, L, M>
where
    C: transfer::Configuration,
    L: LocalLedger<C>,
    M: AssetMap,
{
    /// Local Ledger
    ledger: L,

    /// Asset Map
    asset_map: M,

    /// Type Parameter Marker
    __: PhantomData<C>,
}

impl<C, L, M> BalanceState<C, L, M>
where
    C: transfer::Configuration,
    L: LocalLedger<C>,
    M: AssetMap,
{
    /// Returns the current balance associated with this `id`.
    #[inline]
    pub fn balance(&self, id: AssetId) -> AssetBalance {
        self.asset_map.balance(id)
    }

    /// Returns true if `self` contains at least `asset.value` of the asset of kind `asset.id`.
    #[inline]
    pub fn contains(&self, asset: Asset) -> bool {
        self.asset_map.contains(asset)
    }

    /// Returns the [`Checkpoint`](LocalLedger::Checkpoint) associated with the local ledger.
    #[inline]
    pub fn checkpoint(&self) -> &L::Checkpoint {
        self.ledger.checkpoint()
    }

    ///
    #[inline]
    pub async fn sign<D, SC>(
        &mut self,
        signer: &mut SC,
        request: signer::Request<D, C>,
    ) -> Result<(), signer::Error<D, C>>
    where
        D: DerivedSecretKeyGenerator<SecretKey = C::SecretKey>,
        SC: signer::Connection<D, C>,
    {
        let signer::Response { owner, transfers } = signer.sign(request).await?;

        let _ = owner;
        let _ = transfers;

        todo!()
    }

    /// Synchronizes `self` with the `ledger`.
    #[inline]
    pub async fn sync<LC>(&mut self, ledger: &LC) -> Result<(), LC::Error>
    where
        LC: ledger::Connection<C, Checkpoint = L::Checkpoint>,
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

        // FIXME: Deposit into `asset_map`.

        Ok(())
    }

    /// Sends the `transfers` to the `ledger`.
    #[inline]
    pub async fn send_transfers<LC>(
        &mut self,
        transfers: Vec<TransferPost<C>>,
        ledger: &LC,
    ) -> Result<(), LC::Error>
    where
        LC: ledger::Connection<C, Checkpoint = L::Checkpoint>,
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
            failure_index,
        } = ledger.send(transfers).await?;

        // TODO: Revoke keys if the transfer failed, otherwise recover from the failure.

        let _ = failure_index;

        self.ledger.set_checkpoint(checkpoint);

        // FIXME: Withdraw from `asset_map`

        todo!()
    }
}

/// Full Wallet
pub struct Wallet<D, C, L, M, SC, LC>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
    L: LocalLedger<C>,
    M: AssetMap,
    SC: signer::Connection<D, C>,
    LC: ledger::Connection<C>,
{
    /// Wallet Balance State
    _state: BalanceState<C, L, M>,

    /// Signer Connection
    _signer: SC,

    /// Ledger Connection
    _ledger: LC,

    /// Type Parameter Marker
    __: PhantomData<D>,
}

impl<D, C, L, M, SC, LC> Wallet<D, C, L, M, SC, LC>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
    L: LocalLedger<C>,
    M: AssetMap,
    SC: signer::Connection<D, C>,
    LC: ledger::Connection<C>,
{
}
