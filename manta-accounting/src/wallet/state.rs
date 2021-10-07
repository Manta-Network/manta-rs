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
    asset::{Asset, AssetBalance, AssetId, AssetMap, AssetSelection},
    keys::{DerivedSecretKeyGenerator, Index},
    transfer::{self, ShieldedIdentity},
    wallet::{
        ledger::{self, PullResponse, PushResponse},
        signer::{self, SignRequest, SignResponse, SyncState},
    },
};
use core::marker::PhantomData;

/// Wallet Transaction
pub enum Transaction<C>
where
    C: transfer::Configuration,
{
    /// Mint a Private Asset
    Mint(Asset),

    /// Transfer a Private Asset
    PrivateTransfer(Asset, ShieldedIdentity<C>),

    /// Reclaim a Private Asset
    Reclaim(Asset),
}

/// Wallet Error
///
/// This `enum` is the error state for [`Wallet`] methods. See [`sync`](Wallet::sync) and
/// [`post`](Wallet::post) for more.
pub enum Error<D, C, S, L>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
    S: signer::Connection<D, C>,
    L: ledger::Connection<C> + ?Sized,
{
    /// Signer Error
    SignerError(signer::Error<D, C, S::Error>),

    /// Insufficient Balance Error
    InsufficientBalance(Asset),

    /// Ledger Error
    LedgerError(L::Error),
}

impl<D, C, S, L> From<signer::Error<D, C, S::Error>> for Error<D, C, S, L>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
    S: signer::Connection<D, C>,
    L: ledger::Connection<C> + ?Sized,
{
    #[inline]
    fn from(err: signer::Error<D, C, S::Error>) -> Self {
        Self::SignerError(err)
    }
}
/// Wallet
pub struct Wallet<D, C, M, S, L>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
    M: AssetMap<Key = Index<D>>,
    S: signer::Connection<D, C>,
    L: ledger::Connection<C>,
{
    /// Asset Distribution
    assets: M,

    /// Signer Connection
    signer: S,

    /// Signer Synchronization State
    sync_state: SyncState,

    /// Ledger Connection
    ledger: L,

    /// Ledger Checkpoint
    checkpoint: L::Checkpoint,

    /// Type Parameter Marker
    __: PhantomData<(D, C)>,
}

impl<D, C, M, S, L> Wallet<D, C, M, S, L>
where
    D: DerivedSecretKeyGenerator,
    C: transfer::Configuration<SecretKey = D::SecretKey>,
    M: AssetMap<Key = Index<D>>,
    S: signer::Connection<D, C>,
    L: ledger::Connection<C>,
{
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

    /// Pulls data from the `ledger`, synchronizing the wallet and asset distribution.
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
        self.assets.insert_all(
            self.signer
                .sync(receiver_data, self.sync_state)
                .await?
                .assets
                .into_iter()
                .map(move |(k, a)| (k.reduce(), a)),
        );
        self.checkpoint = checkpoint;
        Ok(())
    }

    /// Selects `asset` from the asset distribution, returning it back if there was an insufficient
    /// balance.
    #[inline]
    fn select(&mut self, asset: Asset) -> Result<AssetSelection<M>, Asset> {
        self.assets.select(asset).ok_or(asset)
    }

    /// Prepares a `transaction` for signing.
    #[inline]
    fn prepare(
        &mut self,
        transaction: Transaction<C>,
    ) -> Result<(AssetId, SignRequest<D, C>), Asset> {
        match transaction {
            Transaction::Mint(asset) => Ok((asset.id, SignRequest::Mint(asset))),
            Transaction::PrivateTransfer(asset, receiver) => {
                let AssetSelection { change, balances } = self.select(asset)?;
                Ok((
                    asset.id,
                    SignRequest::PrivateTransfer {
                        total: asset,
                        change,
                        balances: balances.collect(),
                        receiver,
                    },
                ))
            }
            Transaction::Reclaim(asset) => {
                let AssetSelection { change, balances } = self.select(asset)?;
                Ok((
                    asset.id,
                    SignRequest::Reclaim {
                        total: asset,
                        change,
                        balances: balances.collect(),
                    },
                ))
            }
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
    /// saved onto the ledger.
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
    pub async fn post(&mut self, transaction: Transaction<C>) -> Result<bool, Error<D, C, S, L>> {
        self.sync().await?;
        let (asset_id, request) = self
            .prepare(transaction)
            .map_err(Error::InsufficientBalance)?;
        let SignResponse { balances, posts } = self.signer.sign(request).await?;
        match self.ledger.push(posts).await {
            Ok(PushResponse { success: true }) => {
                self.try_commit().await;
                self.assets.insert_all_same(
                    asset_id,
                    balances.into_iter().map(move |(k, b)| (k.reduce(), b)),
                );
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
