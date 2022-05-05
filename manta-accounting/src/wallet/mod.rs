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

//! Wallet Abstractions
//!
//! This module defines the notion of a "wallet" which can store and manage accounts that control
//! private assets, those defined in [`crate::asset`] and [`crate::transfer`]. The [`Wallet`]
//! abstraction implements the main interface to an account and requires two asynchronous
//! connections, one to a zero-knowledge signing source and secret manager called the [`Signer`] and
//! another connection to the [`Ledger`] itself. The wallet itself only stores the information
//! related to the current balances of any particular account and queries the [`Signer`] and the
//! [`Ledger`] to get the newest balances from incoming transactions and to send out transactions of
//! its own.
//!
//! [`Signer`]: signer::Connection
//! [`Ledger`]: ledger::Connection

use crate::{
    asset::{Asset, AssetId, AssetMetadata, AssetValue},
    transfer::{
        canonical::{Transaction, TransactionKind},
        Configuration, ReceivingKey,
    },
    wallet::{
        balance::{BTreeMapBalanceState, BalanceState},
        ledger::{Checkpoint, PullResponse},
        signer::{
            ReceivingKeyRequest, SignError, SignRequest, SignResponse, SyncError, SyncRequest,
            SyncResponse,
        },
    },
};
use alloc::vec::Vec;
use core::{fmt::Debug, hash::Hash, marker::PhantomData};
use manta_util::ops::ControlFlow;

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

pub mod balance;
pub mod ledger;
pub mod signer;

#[cfg(feature = "test")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "test")))]
pub mod test;

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
    /// Builds a new [`Wallet`] without checking if `ledger`, `checkpoint`, `signer`, and `assets`
    /// are properly synchronized.
    #[inline]
    fn new_unchecked(ledger: L, checkpoint: L::Checkpoint, signer: S, assets: B) -> Self {
        Self {
            ledger,
            checkpoint,
            signer,
            assets,
            __: PhantomData,
        }
    }

    /// Starts a new [`Wallet`] from existing `signer` and `ledger` connections.
    ///
    /// # Setting Up the Wallet
    ///
    /// Creating a [`Wallet`] using this method should be followed with a call to [`sync`] or
    /// [`recover`] to retrieve the current checkpoint and balance for this [`Wallet`]. If the
    /// backing `signer` is known to be already initialized, a call to [`sync`] is enough,
    /// otherwise, a call to [`recover`] is necessary to retrieve the full balance state.
    ///
    /// [`sync`]: Self::sync
    /// [`recover`]: Self::recover
    #[inline]
    pub fn new(ledger: L, signer: S) -> Self {
        Self::new_unchecked(ledger, Default::default(), signer, Default::default())
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

    /// Returns the [`Checkpoint`](ledger::PullConfiguration::Checkpoint) representing the current
    /// state of this wallet.
    #[inline]
    pub fn checkpoint(&self) -> &L::Checkpoint {
        &self.checkpoint
    }

    /// Resets `self` to the default checkpoint and no balance. A call to this method should be
    /// followed by a call to [`sync`](Self::sync) to retrieve the correct checkpoint and balance.
    ///
    /// # Note
    ///
    /// This is not a "full wallet recovery" which would involve resetting the signer as well as
    /// this wallet state. See the [`recover`](Self::recover) method for more.
    #[inline]
    pub fn reset(&mut self) {
        self.checkpoint = Default::default();
        self.assets = Default::default();
    }

    /// Performs full wallet recovery.
    ///
    /// # Failure Conditions
    ///
    /// This method returns an element of type [`Error`] on failure, which can result from any
    /// number of synchronization issues between the wallet, the ledger, and the signer. See the
    /// [`InconsistencyError`] type for more information on the kinds of errors that can occur and
    /// how to resolve them.
    #[inline]
    pub async fn recover(&mut self) -> Result<(), Error<C, L, S>> {
        self.reset();
        while self.sync_with(true).await?.is_continue() {}
        Ok(())
    }

    /// Pulls data from the ledger, synchronizing the wallet and balance state. This method loops
    /// continuously calling [`sync_partial`](Self::sync_partial) until all the ledger data has
    /// arrived at and has been synchronized with the wallet.
    ///
    /// # Failure Conditions
    ///
    /// This method returns an element of type [`Error`] on failure, which can result from any
    /// number of synchronization issues between the wallet, the ledger, and the signer. See the
    /// [`InconsistencyError`] type for more information on the kinds of errors that can occur and
    /// how to resolve them.
    #[inline]
    pub async fn sync(&mut self) -> Result<(), Error<C, L, S>> {
        while self.sync_partial().await?.is_continue() {}
        Ok(())
    }

    /// Pulls data from the ledger, synchronizing the wallet and balance state. This method returns
    /// a [`ControlFlow`] for matching against to determine if the wallet requires more
    /// synchronization.
    ///
    /// # Failure Conditions
    ///
    /// This method returns an element of type [`Error`] on failure, which can result from any
    /// number of synchronization issues between the wallet, the ledger, and the signer. See the
    /// [`InconsistencyError`] type for more information on the kinds of errors that can occur and
    /// how to resolve them.
    #[inline]
    pub async fn sync_partial(&mut self) -> Result<ControlFlow, Error<C, L, S>> {
        self.sync_with(false).await
    }

    /// Pulls data from the ledger, synchronizing the wallet and balance state.
    #[inline]
    async fn sync_with(&mut self, with_recovery: bool) -> Result<ControlFlow, Error<C, L, S>> {
        let PullResponse {
            should_continue,
            checkpoint,
            receivers,
            senders,
        } = self
            .ledger
            .pull(&self.checkpoint)
            .await
            .map_err(Error::LedgerConnectionError)?;
        if checkpoint < self.checkpoint {
            return Err(Error::Inconsistency(InconsistencyError::LedgerCheckpoint));
        }
        match self
            .signer
            .sync(SyncRequest {
                with_recovery,
                starting_index: self.checkpoint.receiver_index(),
                inserts: receivers.into_iter().collect(),
                removes: senders.into_iter().collect(),
            })
            .await
            .map_err(Error::SignerConnectionError)?
        {
            Ok(SyncResponse::Partial { deposit, withdraw }) => {
                self.assets.deposit_all(deposit);
                if !self.assets.withdraw_all(withdraw) {
                    return Err(Error::Inconsistency(InconsistencyError::WalletBalance));
                }
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
                //          - In the worst case we would have to recover the wallet (not necessarily
                //            the signer), which is what the docs currently recommend.
                //
                let _ = starting_index;
                return Err(Error::Inconsistency(
                    InconsistencyError::SignerSynchronization,
                ));
            }
        }
        self.checkpoint = checkpoint;
        Ok(ControlFlow::should_continue(should_continue))
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
    pub async fn post(
        &mut self,
        transaction: Transaction<C>,
        metadata: Option<AssetMetadata>,
    ) -> Result<L::PushResponse, Error<C, L, S>> {
        self.sync().await?;
        self.check(&transaction)
            .map_err(Error::InsufficientBalance)?;
        let SignResponse { posts } = self
            .signer
            .sign(SignRequest {
                transaction,
                metadata,
            })
            .await
            .map_err(Error::SignerConnectionError)?
            .map_err(Error::SignError)?;
        self.ledger
            .push(posts)
            .await
            .map_err(Error::LedgerConnectionError)
    }

    /// Returns public receiving keys according to the `request`.
    #[inline]
    pub async fn receiving_keys(
        &mut self,
        request: ReceivingKeyRequest,
    ) -> Result<Vec<ReceivingKey<C>>, S::Error> {
        self.signer.receiving_keys(request).await
    }
}

/// Inconsistency Error
///
/// This `enum` is the error state for the [`sync`](Wallet::sync) method on [`Wallet`]. See its
/// documentation for more. The variants below describe their error conditions and how to solve the
/// issue whenever they arise.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InconsistencyError {
    /// Ledger Checkpoint Inconsistency
    ///
    /// This error state arises when the ledger checkpoint is behind the checkpoint of the wallet.
    /// To resolve this error, ensure that the ledger connection is correct and try again. This
    /// error does not result in a bad wallet state.
    LedgerCheckpoint,

    /// Wallet Balance Inconsistency
    ///
    /// ⚠️  This error causes the wallet system to enter an inconsistent state. ⚠️
    ///
    /// This error state arises whenever the signer requests a withdraw from the wallet that would
    /// overdraw the balance. To resolve this error, ensure that the signer connection is correct
    /// and perform a wallet reset by resetting the checkpoint and balance state with a call to
    /// [`reset`](Wallet::reset). If other errors continue or if there is reason to suspect that the
    /// signer or ledger connections (or their true state) are corrupted, a full recovery is
    /// required. See the [`recover`](Wallet::recover) method for more.
    WalletBalance,

    /// Signer Synchronization Inconsistency
    ///
    /// ⚠️  This error causes the wallet system to enter an inconsistent state. ⚠️
    ///
    /// This error state arises whenever the signer gets behind the wallet checkpoint. To resolve
    /// this error, ensure that the signer connection is correct and perform a wallet reset by
    /// resetting the checkpoint and balance state with a call to [`reset`](Wallet::reset). If other
    /// errors continue or if there is reason to suspect that the signer or ledger connections (or
    /// their true state) are corrupted, a full recovery is required. See the
    /// [`recover`](Wallet::recover) method for more.
    SignerSynchronization,
}

/// Wallet Error
///
/// This `enum` is the error state for [`Wallet`] methods. See [`sync`](Wallet::sync) and
/// [`post`](Wallet::post) for more.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = r"
                SignError<C>: Deserialize<'de>,
                L::Error: Deserialize<'de>,
                S::Error: Deserialize<'de>
            ",
            serialize = r"
                SignError<C>: Serialize,
                L::Error: Serialize,
                S::Error: Serialize
            "
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "SignError<C>: Clone, L::Error: Clone, S::Error: Clone"),
    Copy(bound = "SignError<C>: Copy, L::Error: Copy, S::Error: Copy"),
    Debug(bound = "SignError<C>: Debug, L::Error: Debug, S::Error: Debug"),
    Eq(bound = "SignError<C>: Eq, L::Error: Eq, S::Error: Eq"),
    Hash(bound = "SignError<C>: Hash, L::Error: Hash, S::Error: Hash"),
    PartialEq(bound = "SignError<C>: PartialEq, L::Error: PartialEq, S::Error: PartialEq")
)]
pub enum Error<C, L, S>
where
    C: Configuration,
    L: ledger::Connection<C>,
    S: signer::Connection<C>,
{
    /// Insufficient Balance
    InsufficientBalance(Asset),

    /// Inconsistency Error
    ///
    /// See the documentation of [`InconsistencyError`] for more.
    Inconsistency(InconsistencyError),

    /// Signing Error
    SignError(SignError<C>),

    /// Signer Connection Error
    SignerConnectionError(S::Error),

    /// Ledger Connection Error
    LedgerConnectionError(L::Error),
}
