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
    asset::{Asset, AssetBalance, AssetId, AssetMap},
    keys::{DerivedSecretKeyGenerator, Index},
    transfer::{self, ShieldedIdentity},
    wallet::{
        ledger::{self, LedgerData, PullResponse},
        signer::{self, SyncResponse},
    },
};
use core::marker::PhantomData;

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

    /// Pulls data from the `ledger`, synchronizing the asset distribution.
    #[inline]
    pub async fn sync(&mut self) -> Result<(), Error<D, C, S, L>> {
        let PullResponse { checkpoint, data } = self
            .ledger
            .pull(&self.checkpoint)
            .await
            .map_err(Error::LedgerError)?;

        // NOTE: We only care about void numbers when we are doing recovery.
        // TODO: Add an optimization path here, so we can decide if we want void
        //       numbers or not when doing a `LedgerConnection::pull`.
        let updates = data.into_iter().filter_map(LedgerData::receiver).collect();

        let SyncResponse { deposit, .. } = self.signer.sync(updates).await?;

        for (key, asset) in deposit {
            self.assets.deposit(key, asset);
        }

        // TODO: ...

        self.checkpoint = checkpoint;

        // TODO: ...

        todo!()
    }

    /// Posts data to the ledger.
    #[inline]
    pub async fn post(&mut self) -> Result<(), Error<D, C, S, L>> {
        // TODO: Should we do a `sync` first or let the user do that?
        //
        // TODO:
        // 1. Send transfer request to signer to build transfer posts, setting rollback-checkpoint
        //    to current state in case the transaction fails. If error, rollback state.
        // 2. Send transfer posts to ledger and wait for result.
        // 3. If error, rollback signer and return.
        // 4. If success, send ok to signer to use new state and update checkpoint / asset
        //    distribution accordingly
        todo!()
    }

    /// Returns a new shielded identity to receive external assets at this wallet.
    #[inline]
    pub async fn new_receiver(
        &mut self,
    ) -> Result<ShieldedIdentity<C>, signer::Error<D, C, S::Error>> {
        self.signer.new_receiver().await
    }
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
