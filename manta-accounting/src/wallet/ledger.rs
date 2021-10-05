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

//! Ledger Source

use crate::{
    identity::{Utxo, VoidNumber},
    transfer::{self, EncryptedAsset, TransferPost},
};
use alloc::{vec, vec::Vec};
use core::future::Future;

/// Ledger Source Connection
pub trait Connection<C>
where
    C: transfer::Configuration,
{
    /// Pull Future Type
    ///
    /// Future for the [`pull`](Self::pull) method.
    type PullFuture: Future<Output = Result<PullResponse<C, Self>, Self::Error>>;

    /// Push Future Type
    ///
    /// Future for the [`push`](Self::push) method.
    type PushFuture: Future<Output = Result<PushResponse<C, Self>, Self::Error>>;

    /// Ledger State Checkpoint Type
    type Checkpoint: Default + Ord;

    /// Error Type
    type Error;

    /// Pulls data from the ledger starting from `checkpoint`, returning the current
    /// [`Checkpoint`](Self::Checkpoint).
    fn pull(&self, checkpoint: &Self::Checkpoint) -> Self::PullFuture;

    /// Pulls all of the data from the entire history of the ledger, returning the current
    /// [`Checkpoint`](Self::Checkpoint).
    #[inline]
    fn pull_all(&self) -> Self::PullFuture {
        self.pull(&Default::default())
    }

    /// Sends `transfers` to the ledger, returning the current [`Checkpoint`](Self::Checkpoint)
    /// and the status of the transfers if successful.
    fn push(&self, transfers: Vec<TransferPost<C>>) -> Self::PushFuture;

    /// Sends `transfer` to the ledger, returning the current [`Checkpoint`](Self::Checkpoint)
    /// and the status of the transfer if successful.
    #[inline]
    fn push_one(&self, transfer: TransferPost<C>) -> Self::PushFuture {
        self.push(vec![transfer])
    }
}

/// Ledger Source Pull Response
///
/// This `struct` is created by the [`pull`](Connection::pull) method on [`Connection`].
/// See its documentation for more.
pub struct PullResponse<C, LC>
where
    C: transfer::Configuration,
    LC: Connection<C> + ?Sized,
{
    /// Current Ledger Checkpoint
    pub checkpoint: LC::Checkpoint,

    /// New Void Numbers
    pub void_numbers: Vec<VoidNumber<C>>,

    /// New UTXOS
    pub utxos: Vec<Utxo<C>>,

    /// New Encrypted Assets
    pub encrypted_assets: Vec<EncryptedAsset<C>>,
}

/// Ledger Source Push Response
///
/// This `struct` is created by the [`push`](Connection::push) method on [`Connection`].
/// See its documentation for more.
pub struct PushResponse<C, LC>
where
    C: transfer::Configuration,
    LC: Connection<C> + ?Sized,
{
    /// Current Ledger Checkpoint
    pub checkpoint: LC::Checkpoint,

    /// Transaction Failed at the Given Index
    pub failure_index: Option<usize>,
}
