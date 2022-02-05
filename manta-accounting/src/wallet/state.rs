// Copyright 2019-2022 Manta Network.
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
    asset::{Asset, AssetId, AssetList, AssetValue},
    transfer::{
        canonical::{Transaction, TransactionKind},
        Configuration, ReceivingKey,
    },
    wallet::{
        ledger::{self, Checkpoint, PullResponse, PushResponse},
        signer::{self, SignError, SignResponse, SyncError, SyncRequest, SyncResponse},
    },
};
use alloc::collections::btree_map::{BTreeMap, Entry as BTreeMapEntry};
use core::{fmt::Debug, marker::PhantomData};

#[cfg(feature = "std")]
use std::{
    collections::hash_map::{Entry as HashMapEntry, HashMap, RandomState},
    hash::BuildHasher,
};

/// Balance State
pub trait BalanceState: Default {
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

    /// Withdraws every asset in `assets` from the balance state without checking if it would
    /// overdraw.
    ///
    /// # Panics
    ///
    /// This method does not check if withdrawing `asset` from the balance state would cause an
    /// overdraw, but if it were to overdraw, this method must panic.
    #[inline]
    fn withdraw_all_unchecked<I>(&mut self, assets: I)
    where
        I: IntoIterator<Item = Asset>,
    {
        assets
            .into_iter()
            .for_each(move |a| self.withdraw_unchecked(a))
    }

    /// Clears the entire balance state.
    fn clear(&mut self);
}

impl BalanceState for AssetList {
    #[inline]
    fn balance(&self, id: AssetId) -> AssetValue {
        self.value(id)
    }

    #[inline]
    fn deposit(&mut self, asset: Asset) {
        self.deposit(asset)
    }

    #[inline]
    fn withdraw_unchecked(&mut self, asset: Asset) {
        self.withdraw_unchecked(asset)
    }

    #[inline]
    fn clear(&mut self) {
        self.clear();
    }
}

/// Performs an unchecked withdraw on `balance`, panicking on overflow.
#[inline]
fn withdraw_unchecked(balance: Option<&mut AssetValue>, withdraw: AssetValue) {
    let balance = match balance {
        Some(balance) => balance,
        _ => panic!("Trying to withdraw `{:?}` from a zero balance.", withdraw),
    };
    *balance = match balance.checked_sub(withdraw) {
        Some(balance) => balance,
        _ => panic!(
            "Overdrawn balance state. Tried to subtract `{:?}` from `{:?}`.",
            withdraw, balance
        ),
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
            if asset.is_zero() {
                return;
            }
            match self.entry(asset.id) {
                $entry::Vacant(entry) => {
                    entry.insert(asset.value);
                }
                $entry::Occupied(entry) => *entry.into_mut() += asset.value,
            }
        }

        #[inline]
        fn withdraw_unchecked(&mut self, asset: Asset) {
            if !asset.is_zero() {
                withdraw_unchecked(self.get_mut(&asset.id), asset.value);
            }
        }

        #[inline]
        fn clear(&mut self) {
            self.clear();
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
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
impl<S> BalanceState for HashMapBalanceState<S>
where
    S: BuildHasher + Default,
{
    impl_balance_state_map_body! { HashMapEntry }
}

/// Wallet
pub struct Wallet<C, L, S = signer::Signer<C>, B = BTreeMapBalanceState>
where
    C: Configuration,
    L: ledger::Connection<C>,
    S: signer::Connection<C>,
    B: BalanceState,
{
    /// Ledger Connection
    ledger: L,

    /// Ledger Checkpoint
    checkpoint: L::Checkpoint,

    /// Signer Connection
    signer: S,

    /// Balance State
    assets: B,

    /// Type Parameter Marker
    __: PhantomData<C>,
}

impl<C, L, S, B> Wallet<C, L, S, B>
where
    C: Configuration,
    L: ledger::Connection<C>,
    S: signer::Connection<C>,
    B: BalanceState,
{
    /// Builds a new [`Wallet`].
    #[inline]
    pub fn new(ledger: L, checkpoint: L::Checkpoint, signer: S, assets: B) -> Self {
        Self {
            ledger,
            checkpoint,
            signer,
            assets,
            __: PhantomData,
        }
    }

    /// Starts a new [`Wallet`] from `signer` and `ledger` connections.
    #[inline]
    pub fn empty(ledger: L, signer: S) -> Self {
        Self::new(ledger, Default::default(), signer, Default::default())
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

    /// Returns a shared reference to the balance state associated to `self`.
    #[inline]
    pub fn assets(&self) -> &B {
        &self.assets
    }

    /// Returns a shared reference to the ledger connection associated to `self`.
    #[inline]
    pub fn ledger(&self) -> &L {
        &self.ledger
    }

    /// Returns the [`Checkpoint`](ledger::Connection::Checkpoint) representing the current state
    /// of this wallet.
    #[inline]
    pub fn checkpoint(&self) -> &L::Checkpoint {
        &self.checkpoint
    }

    /// Pulls data from the `ledger`, synchronizing the wallet and balance state.
    #[inline]
    pub fn sync(&mut self) -> Result<(), Error<C, L, S>> {
        let PullResponse {
            checkpoint,
            receivers,
            senders,
        } = self
            .ledger
            .pull(&self.checkpoint)
            .map_err(Error::LedgerConnectionError)?;
        if checkpoint < self.checkpoint {
            return Err(Error::InconsistentCheckpoint);
        }
        match self
            .signer
            .sync(SyncRequest {
                starting_index: self.checkpoint.receiver_index(),
                inserts: receivers.into_iter().collect(),
                removes: senders.into_iter().collect(),
            })
            .map_err(Error::SignerConnectionError)?
        {
            Ok(SyncResponse::Partial { deposit, withdraw }) => {
                self.assets.deposit_all(deposit);
                self.assets.withdraw_all_unchecked(withdraw);
            }
            Ok(SyncResponse::Full { assets }) => {
                self.assets.clear();
                self.assets.deposit_all(assets);
            }
            Err(SyncError::InconsistentSynchronization { starting_index }) => {
                // FIXME: What should be done when we receive an `InconsistentSynchronization` error
                //        from the signer?
                //          - One option is to do some sort of (exponential) backoff algorithm to
                //            find the point at which the signer and the wallet are able to
                //            synchronize again. The correct algorithm may be simply to exchange
                //            some checkpoints between the signer and the wallet until they can
                //            agree on a minimal one.
                //          - In the worst case we would have to recover the entire wallet.
                //
                let _ = starting_index;
                todo!()
            }
        }
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

    /// Posts a transaction to the ledger, returning `true` if the `transaction` was successfully
    /// saved onto the ledger. This method automatically synchronizes with the ledger before
    /// posting, _but not after_. To amortize the cost of future calls to [`post`](Self::post), the
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
    pub fn post(&mut self, transaction: Transaction<C>) -> Result<bool, Error<C, L, S>> {
        self.sync()?;
        self.check(&transaction)
            .map_err(Error::InsufficientBalance)?;
        let SignResponse { posts } = self
            .signer
            .sign(transaction)
            .map_err(Error::SignerConnectionError)?
            .map_err(Error::SignError)?;
        let PushResponse { success } = self
            .ledger
            .push(posts)
            .map_err(Error::LedgerConnectionError)?;
        Ok(success)
    }

    /// Returns a new [`ReceivingKey`] for `self` to receive assets.
    #[inline]
    pub fn receiving_key(&mut self) -> Result<ReceivingKey<C>, S::Error> {
        self.signer.receiving_key()
    }
}

/// Wallet Error
///
/// This `enum` is the error state for [`Wallet`] methods. See [`sync`](Wallet::sync) and
/// [`post`](Wallet::post) for more.
#[derive(derivative::Derivative)]
#[derivative(Debug(bound = "SignError<C>: Debug, S::Error: Debug, L::Error: Debug"))]
pub enum Error<C, L, S>
where
    C: Configuration,
    L: ledger::Connection<C>,
    S: signer::Connection<C>,
{
    /// Insufficient Balance
    InsufficientBalance(Asset),

    /// Inconsistent Checkpoint Error
    InconsistentCheckpoint,

    /// Signing Error
    SignError(SignError<C>),

    /// Signer Connection Error
    SignerConnectionError(S::Error),

    /// Ledger Connection Error
    LedgerConnectionError(L::Error),
}
