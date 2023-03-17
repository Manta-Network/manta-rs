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
//! connections, one to a transaction signer and secret manager called the [`Signer`] and another
//! connection to the [`Ledger`] itself. The wallet itself only stores the information related to
//! the current balances of any particular account and queries the [`Signer`] and the [`Ledger`] to
//! get the newest balances from incoming transactions and to send out transactions of its own.
//!
//! [`Signer`]: signer::Connection
//! [`Ledger`]: ledger::Connection

use crate::{
    asset::AssetList,
    transfer::{
        canonical::{Transaction, TransactionKind},
        Address, Asset, Configuration, IdentifiedAsset, TransferPost, UtxoAccumulatorModel,
    },
    wallet::{
        balance::{BTreeMapBalanceState, BalanceState},
        ledger::ReadResponse,
        signer::{
            BalanceUpdate, IdentityRequest, IdentityResponse, InitialSyncData, SignError,
            SignRequest, SignResponse, SignWithTransactionDataResponse, SyncData, SyncError,
            SyncRequest, SyncResponse, TransactionDataRequest, TransactionDataResponse,
        },
    },
};
use alloc::vec::Vec;
use core::{fmt::Debug, hash::Hash, marker::PhantomData, ops::AddAssign};
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
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "L: Deserialize<'de>, S::Checkpoint: Deserialize<'de>, S: Deserialize<'de>, B: Deserialize<'de>",
            serialize = "L: Serialize, S::Checkpoint: Serialize, S: Serialize, B: Serialize",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "L: Clone, S::Checkpoint: Clone, S: Clone, B: Clone"),
    Copy(bound = "L: Copy, S::Checkpoint: Copy, S: Copy, B: Copy"),
    Debug(bound = "L: Debug, S::Checkpoint: Debug, S: Debug, B: Debug"),
    Default(bound = "L: Default, S::Checkpoint: Default, S: Default, B: Default"),
    Eq(bound = "L: Eq, S::Checkpoint: Eq, S: Eq, B: Eq"),
    Hash(bound = "L: Hash, S::Checkpoint: Hash, S: Hash, B: Hash"),
    PartialEq(bound = "L: PartialEq, S::Checkpoint: PartialEq, S: PartialEq, B: PartialEq")
)]
pub struct Wallet<
    C,
    L,
    S = signer::Signer<C>,
    B = BTreeMapBalanceState<<C as Configuration>::AssetId, <C as Configuration>::AssetValue>,
> where
    C: Configuration,
    L: ledger::Connection,
    S: signer::Connection<C>,
    B: BalanceState<C::AssetId, C::AssetValue>,
{
    /// Ledger Connection
    ledger: L,

    /// Ledger Checkpoint
    checkpoint: S::Checkpoint,

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
    L: ledger::Connection,
    S: signer::Connection<C>,
    B: BalanceState<C::AssetId, C::AssetValue>,
{
    /// Builds a new [`Wallet`] without checking if `ledger`, `checkpoint`, `signer`, and `assets`
    /// are properly synchronized.
    #[inline]
    fn new_unchecked(ledger: L, checkpoint: S::Checkpoint, signer: S, assets: B) -> Self {
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
    /// [`restart`] to retrieve the current checkpoint and balance for this [`Wallet`]. If the
    /// backing `signer` is known to be already initialized, a call to [`sync`] is enough,
    /// otherwise, a call to [`restart`] is necessary to retrieve the full balance state.
    ///
    /// [`sync`]: Self::sync
    /// [`restart`]: Self::restart
    #[inline]
    pub fn new(ledger: L, signer: S) -> Self {
        Self::new_unchecked(ledger, Default::default(), signer, Default::default())
    }

    /// Returns a mutable reference to the [`Connection`](signer::Connection).
    ///
    /// # Crypto Safety
    ///
    /// Calls to this function cannot modify the signer in any way that would leave the
    /// [`BalanceState`] invalid.
    #[inline]
    pub fn signer_mut(&mut self) -> &mut S {
        &mut self.signer
    }

    /// Starts a new wallet with `ledger` and `signer` connections.
    #[inline]
    pub async fn start(ledger: L, signer: S) -> Result<Self, Error<C, L, S>>
    where
        L: ledger::Read<SyncData<C>, Checkpoint = S::Checkpoint>,
    {
        let mut wallet = Self::new(ledger, signer);
        wallet.restart().await?;
        Ok(wallet)
    }

    /// Resets the state of the wallet to the default starting state.
    #[inline]
    pub fn reset_state(&mut self) {
        self.checkpoint = Default::default();
        self.assets = Default::default();
    }

    /// Returns the current balance associated with this `id`.
    #[inline]
    pub fn balance(&self, id: &C::AssetId) -> C::AssetValue {
        self.assets.balance(id)
    }

    /// Returns true if `self` contains at least `asset.value` of the asset of kind `asset.id`.
    #[inline]
    pub fn contains(&self, asset: &Asset<C>) -> bool {
        self.assets.contains(asset)
    }

    /// Returns `true` if `self` contains at least every asset in `assets`. Assets are combined
    /// first by asset id before checking for membership.
    #[inline]
    pub fn contains_all<A>(&self, assets: A) -> bool
    where
        C::AssetId: Ord,
        C::AssetValue: AddAssign + Default,
        A: IntoIterator<Item = Asset<C>>,
    {
        AssetList::from_iter(assets)
            .into_iter()
            .all(|asset| self.contains(&asset))
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

    /// Returns the [`Checkpoint`](ledger::Checkpoint) representing the current state of this
    /// wallet.
    #[inline]
    pub fn checkpoint(&self) -> &S::Checkpoint {
        &self.checkpoint
    }

    /// Restarts `self` with an empty state and performs a synchronization against the signer and
    /// ledger to catch up to the current checkpoint and balance state.
    ///
    /// # Failure Conditions
    ///
    /// This method returns an element of type [`Error`] on failure, which can result from any
    /// number of synchronization issues between the wallet, the ledger, and the signer. See the
    /// [`InconsistencyError`] type for more information on the kinds of errors that can occur and
    /// how to resolve them.
    #[inline]
    pub async fn restart(&mut self) -> Result<(), Error<C, L, S>>
    where
        L: ledger::Read<SyncData<C>, Checkpoint = S::Checkpoint>,
    {
        self.reset_state();
        self.load_initial_state().await?;
        while self.sync_with().await?.is_continue() {}
        Ok(())
    }

    /// Loads initial checkpoint and balance state from the signer. This method is used by
    /// [`restart`](Self::restart) to avoid querying the ledger at genesis when a known later
    /// checkpoint exists.
    #[inline]
    pub async fn load_initial_state(&mut self) -> Result<(), Error<C, L, S>> {
        self.signer_sync(Default::default()).await
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
    pub async fn sync(&mut self) -> Result<(), Error<C, L, S>>
    where
        L: ledger::Read<SyncData<C>, Checkpoint = S::Checkpoint>,
    {
        while self.sync_partial().await?.is_continue() {}
        Ok(())
    }

    ///
    #[inline]
    pub async fn initial_sync(&mut self) -> Result<(), Error<C, L, S>>
    where
        L: ledger::Read<InitialSyncData<C>, Checkpoint = S::Checkpoint>,
    {
        while self.initial_sync_partial().await?.is_continue() {}
        Ok(())
    }

    ///
    #[inline]
    pub async fn initial_sync_partial(&mut self) -> Result<ControlFlow, Error<C, L, S>>
    where
        L: ledger::Read<InitialSyncData<C>, Checkpoint = S::Checkpoint>,
    {
        let ReadResponse {
            should_continue,
            data,
        } = self
            .ledger
            .read(&self.checkpoint)
            .await
            .map_err(Error::LedgerConnectionError)?;
        self.signer_initial_sync(data).await?;
        Ok(ControlFlow::should_continue(should_continue))
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
    pub async fn sync_partial(&mut self) -> Result<ControlFlow, Error<C, L, S>>
    where
        L: ledger::Read<SyncData<C>, Checkpoint = S::Checkpoint>,
    {
        self.sync_with().await
    }

    /// Pulls data from the ledger, synchronizing the wallet and balance state.
    #[inline]
    async fn sync_with(&mut self) -> Result<ControlFlow, Error<C, L, S>>
    where
        L: ledger::Read<SyncData<C>, Checkpoint = S::Checkpoint>,
    {
        let ReadResponse {
            should_continue,
            data,
        } = self
            .ledger
            .read(&self.checkpoint)
            .await
            .map_err(Error::LedgerConnectionError)?;
        self.signer_sync(SyncRequest {
            origin_checkpoint: self.checkpoint.clone(),
            data,
        })
        .await?;
        Ok(ControlFlow::should_continue(should_continue))
    }

    /// Performs a synchronization with the signer against the given `request`.
    #[inline]
    async fn signer_sync(
        &mut self,
        request: SyncRequest<C, S::Checkpoint>,
    ) -> Result<(), Error<C, L, S>> {
        match self
            .signer
            .sync(request)
            .await
            .map_err(Error::SignerConnectionError)?
        {
            Ok(SyncResponse {
                checkpoint,
                balance_update,
            }) => {
                match balance_update {
                    BalanceUpdate::Partial { deposit, withdraw } => {
                        self.assets.deposit_all(deposit);
                        if !self.assets.withdraw_all(withdraw) {
                            return Err(Error::Inconsistency(InconsistencyError::WalletBalance));
                        }
                    }
                    BalanceUpdate::Full { assets } => {
                        self.assets.clear();
                        self.assets.deposit_all(assets);
                    }
                }
                self.checkpoint = checkpoint;
                Ok(())
            }
            Err(SyncError::InconsistentSynchronization { checkpoint }) => {
                if checkpoint < self.checkpoint {
                    self.checkpoint = checkpoint;
                }
                Err(Error::Inconsistency(
                    InconsistencyError::SignerSynchronization,
                ))
            }
            Err(SyncError::MissingProofAuthorizationKey) => {
                Err(Error::MissingProofAuthorizationKey)
            }
        }
    }

    ///
    #[inline]
    async fn signer_initial_sync(
        &mut self,
        request: InitialSyncData<C>,
    ) -> Result<(), Error<C, L, S>> {
        match self
            .signer
            .initial_sync(request)
            .await
            .map_err(Error::SignerConnectionError)?
        {
            Ok(SyncResponse {
                checkpoint,
                balance_update,
            }) => {
                match balance_update {
                    BalanceUpdate::Full { assets } => {
                        self.assets.clear();
                        self.assets.deposit_all(assets);
                    }
                    _ => {
                        unreachable!("No transactions could have happened on a new account.");
                    }
                }
                self.checkpoint = checkpoint;
                Ok(())
            }
            Err(SyncError::InconsistentSynchronization { checkpoint }) => {
                if checkpoint < self.checkpoint {
                    self.checkpoint = checkpoint;
                }
                Err(Error::Inconsistency(
                    InconsistencyError::SignerSynchronization,
                ))
            }
            Err(SyncError::MissingProofAuthorizationKey) => {
                Err(Error::MissingProofAuthorizationKey)
            }
        }
    }

    /// Checks if `transaction` can be executed on the balance state of `self`, returning the
    /// kind of update that should be performed on the balance state if the transaction is
    /// successfully posted to the ledger.
    ///
    /// # Crypto Safety
    ///
    /// This method is already called by [`post`](Self::post), but can be used by custom
    /// implementations to perform checks elsewhere.
    #[inline]
    fn check<'s>(
        &'s self,
        transaction: &'s Transaction<C>,
    ) -> Result<TransactionKind<C>, Asset<C>> {
        transaction
            .check(move |a| self.contains(a))
            .map_err(Clone::clone)
    }

    /// Signs the `transaction` using the signer connection, sending `metadata` for context. This
    /// method _does not_ automatically sychronize with the ledger. To do this, call the
    /// [`sync`](Self::sync) method separately.
    #[inline]
    pub async fn sign(
        &mut self,
        transaction: Transaction<C>,
        metadata: Option<S::AssetMetadata>,
    ) -> Result<SignResponse<C>, Error<C, L, S>> {
        self.check(&transaction)
            .map_err(Error::InsufficientBalance)?;
        self.signer
            .sign(SignRequest {
                transaction,
                metadata,
            })
            .await
            .map_err(Error::SignerConnectionError)?
            .map_err(Error::SignError)
    }

    /// Attempts to process [`TransferPost`]s and returns the corresponding
    /// [`TransactionData`](crate::transfer::canonical::TransactionData).
    #[inline]
    pub async fn transaction_data(
        &mut self,
        transfer_posts: Vec<TransferPost<C>>,
    ) -> Result<TransactionDataResponse<C>, Error<C, L, S>> {
        self.signer
            .transaction_data(TransactionDataRequest(transfer_posts))
            .await
            .map_err(Error::SignerConnectionError)
    }

    /// Attempts to process [`IdentifiedAsset`]s and returns the corresponding
    /// [`IdentityProof`](crate::transfer::IdentityProof)s.
    #[inline]
    pub async fn identity_proof(
        &mut self,
        request: Vec<(IdentifiedAsset<C>, C::AccountId)>,
    ) -> Result<IdentityResponse<C>, Error<C, L, S>>
    where
        UtxoAccumulatorModel<C>: Clone,
    {
        self.signer
            .identity_proof(IdentityRequest(request))
            .await
            .map_err(Error::SignerConnectionError)
    }

    /// Posts a transaction to the ledger, returning a success [`Response`] if the `transaction`
    /// was successfully posted to the ledger. This method automatically synchronizes with the
    /// ledger before posting, _but not after_. To amortize the cost of future calls to [`post`],
    /// the [`sync`] method can be used to synchronize with the ledger.
    ///
    /// # Failure Conditions
    ///
    /// This method returns a [`Response`] when there were no errors in producing transfer data and
    /// sending and receiving from the ledger, but instead the ledger just did not accept the
    /// transaction as is. This could be caused by an external update to the ledger while the signer
    /// was building the transaction that caused the wallet and the ledger to get out of sync. In
    /// this case, [`post`] can safely be called again, to retry the transaction.
    ///
    /// This method returns an error in any other case. The internal state of the wallet is kept
    /// consistent between calls and recoverable errors are returned for the caller to handle.
    ///
    /// [`Response`]: ledger::Write::Response
    /// [`post`]: Self::post
    /// [`sync`]: Self::sync
    #[inline]
    pub async fn post(
        &mut self,
        transaction: Transaction<C>,
        metadata: Option<S::AssetMetadata>,
    ) -> Result<L::Response, Error<C, L, S>>
    where
        L: ledger::Read<SyncData<C>, Checkpoint = S::Checkpoint>
            + ledger::Write<Vec<TransferPost<C>>>,
    {
        self.sync().await?;
        let SignResponse { posts } = self.sign(transaction, metadata).await?;
        self.ledger
            .write(posts)
            .await
            .map_err(Error::LedgerConnectionError)
    }

    /// Returns the address.
    #[inline]
    pub async fn address(&mut self) -> Result<Option<Address<C>>, S::Error> {
        self.signer.address().await
    }

    /// Signs `transaction` and returns the [`TransferPost`]s and the
    /// associated [`TransactionData`](crate::transfer::canonical::TransactionData) if successful.
    #[inline]
    pub async fn sign_with_transaction_data(
        &mut self,
        transaction: Transaction<C>,
        metadata: Option<S::AssetMetadata>,
    ) -> Result<SignWithTransactionDataResponse<C>, Error<C, L, S>>
    where
        TransferPost<C>: Clone,
    {
        self.check(&transaction)
            .map_err(Error::InsufficientBalance)?;
        self.signer
            .sign_with_transaction_data(SignRequest {
                transaction,
                metadata,
            })
            .await
            .map_err(Error::SignerConnectionError)?
            .map_err(Error::SignError)
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
    /// Wallet Balance Inconsistency
    ///
    /// ⚠️  This error causes the wallet system to enter an inconsistent state. ⚠️
    ///
    /// This error state arises whenever the signer requests a withdraw from the wallet that would
    /// overdraw the balance. To resolve this error, ensure that the signer connection is correct
    /// and perform a wallet restart by resetting the checkpoint and balance state with a call to
    /// [`restart`](Wallet::restart). If other errors continue or if there is reason to suspect that
    /// the signer or ledger connections (or their true state) are corrupted, a full recovery is
    /// required.
    WalletBalance,

    /// Signer Synchronization Inconsistency
    ///
    /// ⚠️  This error causes the wallet system to enter an inconsistent state. ⚠️
    ///
    /// This error state arises whenever the signer gets behind the wallet checkpoint. To resolve
    /// this error, ensure that the signer connection is correct and perform a wallet reset by
    /// resetting the checkpoint and balance state with a call to [`restart`](Wallet::restart). If
    /// other errors continue or if there is reason to suspect that the signer or ledger connections
    /// (or their true state) are corrupted, a full recovery is required.
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
                Asset<C>: Deserialize<'de>,
                SignError<C>: Deserialize<'de>,
                L::Error: Deserialize<'de>,
                S::Error: Deserialize<'de>
            ",
            serialize = r"
                Asset<C>: Serialize,
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
    Clone(bound = "Asset<C>: Clone, SignError<C>: Clone, L::Error: Clone, S::Error: Clone"),
    Copy(bound = "Asset<C>: Copy, SignError<C>: Copy, L::Error: Copy, S::Error: Copy"),
    Debug(bound = "Asset<C>: Debug, SignError<C>: Debug, L::Error: Debug, S::Error: Debug"),
    Eq(bound = "Asset<C>: Eq, SignError<C>: Eq, L::Error: Eq, S::Error: Eq"),
    Hash(bound = "Asset<C>: Hash, SignError<C>: Hash, L::Error: Hash, S::Error: Hash"),
    PartialEq(
        bound = "Asset<C>: PartialEq, SignError<C>: PartialEq, L::Error: PartialEq, S::Error: PartialEq"
    )
)]
pub enum Error<C, L, S>
where
    C: Configuration,
    L: ledger::Connection,
    S: signer::Connection<C>,
{
    /// Insufficient Balance
    InsufficientBalance(Asset<C>),

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

    /// Missing Spending Key Error
    MissingSpendingKey,

    /// Missing Proof Authorization Key Error
    MissingProofAuthorizationKey,
}

impl<C, L, S> From<InconsistencyError> for Error<C, L, S>
where
    C: Configuration,
    L: ledger::Connection,
    S: signer::Connection<C>,
{
    #[inline]
    fn from(err: InconsistencyError) -> Self {
        Self::Inconsistency(err)
    }
}
