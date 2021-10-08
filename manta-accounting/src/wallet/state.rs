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

//! Wallet Full State Implementation

use crate::{
    asset::{Asset, AssetBalance, AssetId},
    keys::DerivedSecretKeyGenerator,
    transfer::{Configuration, ShieldedIdentity},
    wallet::{
        ledger::{self, PullResponse, PushResponse},
        signer::{self, SignRequest, SignResponse, SyncState},
    },
};
use core::marker::PhantomData;

/// Balance State
pub trait BalanceState {
    /// Returns the current balance associated with this `id`.
    fn balance(&self, id: AssetId) -> AssetBalance;

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
        for asset in assets {
            self.deposit(asset)
        }
    }

    /// Withdraws `asset` from the balance state without checking if it would overdraw.
    ///
    /// # Panics
    ///
    /// This method does not check if withdrawing `asset` from the balance state would cause an
    /// overdraw, but if it were to overdraw, this method must panic.
    fn withdraw_unchecked(&mut self, asset: Asset);
}

/* TODO: Implement these:
impl BalanceState for Vec<Asset> {}
impl BalanceState for BTreeMap<Asset> {}
impl BalanceState for HashMap<Asset> {}
*/

/// Wallet Error
///
/// This `enum` is the error state for [`Wallet`] methods. See [`sync`](Wallet::sync) and
/// [`post`](Wallet::post) for more.
pub enum Error<D, C, S, L>
where
    D: DerivedSecretKeyGenerator,
    C: Configuration<SecretKey = D::SecretKey>,
    S: signer::Connection<D, C>,
    L: ledger::Connection<C> + ?Sized,
{
    /// Insufficient Balance
    InsufficientBalance(Asset),

    /// Signer Error
    SignerError(signer::Error<D, C, S::Error>),

    /// Ledger Error
    LedgerError(L::Error),
}

impl<D, C, S, L> From<signer::Error<D, C, S::Error>> for Error<D, C, S, L>
where
    D: DerivedSecretKeyGenerator,
    C: Configuration<SecretKey = D::SecretKey>,
    S: signer::Connection<D, C>,
    L: ledger::Connection<C> + ?Sized,
{
    #[inline]
    fn from(err: signer::Error<D, C, S::Error>) -> Self {
        Self::SignerError(err)
    }
}
/// Wallet
pub struct Wallet<D, C, S, L, B>
where
    D: DerivedSecretKeyGenerator,
    C: Configuration<SecretKey = D::SecretKey>,
    S: signer::Connection<D, C>,
    L: ledger::Connection<C>,
    B: BalanceState,
{
    /// Signer Connection
    signer: S,

    /// Signer Synchronization State
    sync_state: SyncState,

    /// Ledger Connection
    ledger: L,

    /// Ledger Checkpoint
    checkpoint: L::Checkpoint,

    /// Balance State
    assets: B,

    /// Type Parameter Marker
    __: PhantomData<(D, C)>,
}

impl<D, C, S, L, B> Wallet<D, C, S, L, B>
where
    D: DerivedSecretKeyGenerator,
    C: Configuration<SecretKey = D::SecretKey>,
    S: signer::Connection<D, C>,
    L: ledger::Connection<C>,
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
    pub fn balance(&self, id: AssetId) -> AssetBalance {
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
    pub async fn sync(&mut self) -> Result<(), Error<D, C, S, L>> {
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
                .sync(receiver_data, self.sync_state)
                .await?
                .assets,
        );
        self.sync_state = SyncState::Commit;
        self.checkpoint = checkpoint;
        Ok(())
    }

    /// Checks if there is enough balance in the balance state to perform the `transaction`.
    #[inline]
    fn prepare(&self, transaction: &SignRequest<C>) -> Result<TransactionKind, Asset> {
        let asset = transaction.asset();
        if transaction.is_deposit() {
            Ok(TransactionKind::Deposit(asset.id))
        } else if self.assets.contains(asset) {
            Ok(TransactionKind::Withdraw(asset))
        } else {
            Err(asset)
        }
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
    pub async fn post(&mut self, transaction: SignRequest<C>) -> Result<bool, Error<D, C, S, L>> {
        self.sync().await?;
        let transaction_kind = self
            .prepare(&transaction)
            .map_err(Error::InsufficientBalance)?;
        let SignResponse { deposit, posts } = self.signer.sign(transaction).await?;
        match self.ledger.push(posts).await {
            Ok(PushResponse { success: true }) => {
                self.try_commit().await;
                match transaction_kind {
                    TransactionKind::Deposit(asset_id) => {
                        self.assets.deposit(asset_id.with(deposit));
                    }
                    TransactionKind::Withdraw(asset) => {
                        self.assets.withdraw_unchecked(asset);
                        self.assets.deposit(asset.id.with(deposit));
                    }
                }
                Ok(true)
            }
            Ok(PushResponse { success: false }) => {
                self.try_rollback().await;
                Ok(false)
            }
            Err(err) => {
                self.try_rollback().await;
                Err(Error::LedgerError(err))
            }
        }
    }

    /// Returns a new shielded identity to receive external assets at this wallet.
    #[inline]
    pub async fn external_receiver(
        &mut self,
    ) -> Result<ShieldedIdentity<C>, signer::Error<D, C, S::Error>> {
        self.signer.external_receiver().await
    }
}

/// Transaction Kind
enum TransactionKind {
    /// Deposit Transaction
    Deposit(AssetId),

    /// Withdraw Transaction
    Withdraw(Asset),
}
