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

//! Full Wallet Implementation

use crate::{
    asset::{Asset, AssetId, AssetValue},
    key::{HierarchicalKeyDerivationScheme, Index},
    transfer::{
        canonical::{Transaction, TransactionKind},
        Configuration, ReceivingKey, SecretKey,
    },
    wallet::{
        ledger::{self, Checkpoint, PullResponse, PushResponse},
        signer::{self, SignResponse, SyncState},
    },
};
use alloc::{
    collections::btree_map::{BTreeMap, Entry as BTreeMapEntry},
    vec::Vec,
};
use core::marker::PhantomData;

#[cfg(feature = "std")]
use std::{
    collections::hash_map::{Entry as HashMapEntry, HashMap, RandomState},
    hash::BuildHasher,
};

/// Balance State
pub trait BalanceState {
    /// Returns the current balance associated with this `id`.
    fn balance(&self, id: AssetId) -> AssetValue;

    /// Returns true if `self` contains at least `asset.value` of the asset of kind `asset.id`.
    #[inline]
    fn contains(&self, asset: Asset) -> bool {
        self.balance(asset.id) >= asset.value
    }

    /// Deposits `asset` into the balance state, increasing the balance of the asset stored at
    /// `asset.id` by an amount equal to `asset.value`.
    fn deposit(&mut self, asset: Asset);

    /// Deposits every asset in `assets` into the balance state.
    #[inline]
    fn deposit_all<I>(&mut self, assets: I)
    where
        I: IntoIterator<Item = Asset>,
    {
        assets.into_iter().for_each(move |a| self.deposit(a));
    }

    /// Withdraws `asset` from the balance state without checking if it would overdraw.
    ///
    /// # Panics
    ///
    /// This method does not check if withdrawing `asset` from the balance state would cause an
    /// overdraw, but if it were to overdraw, this method must panic.
    fn withdraw_unchecked(&mut self, asset: Asset);
}

/// Performs an unchecked withdraw on `balance`, panicking on overflow.
#[inline]
fn withdraw_unchecked(balance: Option<&mut AssetValue>, withdraw: AssetValue) {
    let balance = balance.expect("Trying to withdraw from a zero balance.");
    *balance = balance
        .checked_sub(withdraw)
        .expect("Overdrawn balance state.");
}

/// Vector [`BalanceState`] Implementation
pub type VecBalanceState = Vec<Asset>;

impl BalanceState for VecBalanceState {
    #[inline]
    fn balance(&self, id: AssetId) -> AssetValue {
        self.iter()
            .find_map(move |a| a.value_of(id))
            .unwrap_or_default()
    }

    #[inline]
    fn deposit(&mut self, asset: Asset) {
        self.push(asset);
    }

    #[inline]
    fn withdraw_unchecked(&mut self, asset: Asset) {
        if !asset.is_zero() {
            withdraw_unchecked(
                self.iter_mut().find_map(move |a| a.value_of_mut(asset.id)),
                asset.value,
            );
        }
    }
}

/// Adds implementation of [`BalanceState`] for a map type with the given `$entry` type.
macro_rules! impl_balance_state_map_body {
    ($entry:tt) => {
        #[inline]
        fn balance(&self, id: AssetId) -> AssetValue {
            self.get(&id).copied().unwrap_or_default()
        }

        #[inline]
        fn deposit(&mut self, asset: Asset) {
            match self.entry(asset.id) {
                $entry::Vacant(entry) => {
                    entry.insert(asset.value);
                }
                $entry::Occupied(entry) => {
                    *entry.into_mut() += asset.value;
                }
            }
        }

        #[inline]
        fn withdraw_unchecked(&mut self, asset: Asset) {
            if !asset.is_zero() {
                withdraw_unchecked(self.get_mut(&asset.id), asset.value);
            }
        }
    };
}

/// B-Tree Map [`BalanceState`] Implementation
pub type BTreeMapBalanceState = BTreeMap<AssetId, AssetValue>;

impl BalanceState for BTreeMapBalanceState {
    impl_balance_state_map_body! { BTreeMapEntry }
}

/// Hash Map [`BalanceState`] Implementation
#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
pub type HashMapBalanceState<S = RandomState> = HashMap<AssetId, AssetValue, S>;

#[cfg(feature = "std")]
impl<S> BalanceState for HashMapBalanceState<S>
where
    S: BuildHasher,
{
    impl_balance_state_map_body! { HashMapEntry }
}

/// Wallet
pub struct Wallet<H, C, L, S, B = BTreeMapBalanceState>
where
    H: HierarchicalKeyDerivationScheme<SecretKey = SecretKey<C>>,
    C: Configuration,
    L: ledger::Connection<C>,
    S: signer::Connection<H, C>,
    B: BalanceState,
{
    /// Ledger Connection
    ledger: L,

    /// Ledger Checkpoint
    checkpoint: L::Checkpoint,

    /// Signer Connection
    signer: S,

    /// Signer Synchronization State
    sync_state: SyncState,

    /// Balance State
    assets: B,

    /// Type Parameter Marker
    __: PhantomData<(H, C)>,
}

impl<H, C, L, S, B> Wallet<H, C, L, S, B>
where
    H: HierarchicalKeyDerivationScheme<SecretKey = SecretKey<C>>,
    C: Configuration,
    L: ledger::Connection<C>,
    S: signer::Connection<H, C>,
    B: BalanceState,
{
    /// Builds a new [`Wallet`].
    #[inline]
    pub fn new(
        signer: S,
        sync_state: SyncState,
        ledger: L,
        checkpoint: L::Checkpoint,
        assets: B,
    ) -> Self {
        Self {
            signer,
            sync_state,
            ledger,
            checkpoint,
            assets,
            __: PhantomData,
        }
    }

    /// Returns the current balance associated with this `id`.
    #[inline]
    pub fn balance(&self, id: AssetId) -> AssetValue {
        self.assets.balance(id)
    }

    /// Returns true if `self` contains at least `asset.value` of the asset of kind `asset.id`.
    #[inline]
    pub fn contains(&self, asset: Asset) -> bool {
        self.assets.contains(asset)
    }

    /// Returns the [`Checkpoint`](ledger::Connection::Checkpoint) representing the current state
    /// of this wallet.
    #[inline]
    pub fn checkpoint(&self) -> &L::Checkpoint {
        &self.checkpoint
    }

    /// Pulls data from the `ledger`, synchronizing the wallet and balance state.
    #[inline]
    pub async fn sync(&mut self) -> Result<(), Error<H, C, L, S>> {
        // TODO: How to recover from an `InconsistentSynchronization` error? Need some sort of
        //       recovery mode, like starting from the beginning of the state?
        let PullResponse {
            checkpoint,
            receiver_data,
        } = self
            .ledger
            .pull(&self.checkpoint)
            .await
            .map_err(Error::LedgerError)?;
        self.assets.deposit_all(
            self.signer
                .sync(
                    self.sync_state,
                    self.checkpoint.receiver_index(),
                    receiver_data,
                )
                .await?
                .assets,
        );
        self.sync_state = SyncState::Commit;
        self.checkpoint = checkpoint;
        Ok(())
    }

    /// Checks if `transaction` can be executed on the balance state of `self`, returning the
    /// kind of update that should be performed on the balance state if the transaction is
    /// successfully posted to the ledger.
    ///
    /// # Safety
    ///
    /// This method is already called by [`post`](Self::post), but can be used by custom
    /// implementations to perform checks elsewhere.
    #[inline]
    pub fn check(&self, transaction: &Transaction<C>) -> Result<TransactionKind, Asset> {
        transaction.check(move |a| self.contains(a))
    }

    /// Tries to commit to the current signer state.
    #[inline]
    async fn try_commit(&mut self) {
        if self.signer.commit().await.is_err() {
            self.sync_state = SyncState::Commit;
        }
    }

    /// Tries to rollback to the previous signer state.
    #[inline]
    async fn try_rollback(&mut self) {
        if self.signer.rollback().await.is_err() {
            self.sync_state = SyncState::Rollback;
        }
    }

    /// Posts a transaction to the ledger, returning `true` if the `transaction` was successfully
    /// saved onto the ledger. This method automatically synchronizes with the ledger before
    /// posting. To amortize the cost of future calls to [`post`](Self::post), the
    /// [`sync`](Self::sync) method can be used to synchronize with the ledger.
    ///
    /// # Failure Conditions
    ///
    /// This method returns `false` when there were no errors in producing transfer data and
    /// sending and receiving from the ledger, but instead the ledger just did not accept the
    /// transaction as is. This could be caused by an external update to the ledger while the
    /// signer was building the transaction that caused the wallet and the ledger to get out of
    /// sync. In this case, [`post`](Self::post) can safely be called again, to retry the
    /// transaction.
    ///
    /// This method returns an error in any other case. The internal state of the wallet is kept
    /// consistent between calls and recoverable errors are returned for the caller to handle.
    #[inline]
    pub async fn post(&mut self, transaction: Transaction<C>) -> Result<bool, Error<H, C, L, S>> {
        self.sync().await?;
        let balance_update = self
            .check(&transaction)
            .map_err(Error::InsufficientBalance)?;
        let SignResponse { posts } = self.signer.sign(transaction).await?;
        match self.ledger.push(posts).await {
            Ok(PushResponse {
                checkpoint,
                success: true,
            }) => {
                self.try_commit().await;
                match balance_update {
                    TransactionKind::Deposit(asset) => self.assets.deposit(asset),
                    TransactionKind::Withdraw(asset) => self.assets.withdraw_unchecked(asset),
                }
                self.checkpoint = checkpoint;
                Ok(true)
            }
            Ok(PushResponse { success: false, .. }) => {
                // FIXME: What about the checkpoint returned in the response?
                self.try_rollback().await;
                Ok(false)
            }
            Err(err) => {
                self.try_rollback().await;
                Err(Error::LedgerError(err))
            }
        }
    }

    /// Returns a [`ReceivingKey`] for `self` to receive assets with `index`.
    #[inline]
    pub async fn receiving_key(
        &mut self,
        index: Index<H>,
    ) -> Result<ReceivingKey<C>, signer::Error<H, C, S::Error>> {
        self.signer.receiving_key(index).await
    }
}

/// Wallet Error
///
/// This `enum` is the error state for [`Wallet`] methods. See [`sync`](Wallet::sync) and
/// [`post`](Wallet::post) for more.
pub enum Error<H, C, L, S>
where
    H: HierarchicalKeyDerivationScheme<SecretKey = SecretKey<C>>,
    C: Configuration,
    L: ledger::Connection<C>,
    S: signer::Connection<H, C>,
{
    /// Insufficient Balance
    InsufficientBalance(Asset),

    /// Ledger Error
    LedgerError(L::Error),

    /// Signer Error
    SignerError(signer::Error<H, C, S::Error>),
}

impl<H, C, L, S> From<signer::Error<H, C, S::Error>> for Error<H, C, L, S>
where
    H: HierarchicalKeyDerivationScheme<SecretKey = SecretKey<C>>,
    C: Configuration,
    L: ledger::Connection<C>,
    S: signer::Connection<H, C>,
{
    #[inline]
    fn from(err: signer::Error<H, C, S::Error>) -> Self {
        Self::SignerError(err)
    }
}
