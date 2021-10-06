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
use alloc::vec::Vec;
use core::future::Future;

/// Ledger Source Connection
pub trait Connection<C>
where
    C: transfer::Configuration,
{
    /// Ledger State Checkpoint Type
    type Checkpoint: Default + Ord;

    /// Pull Future Type
    ///
    /// Future for the [`pull`](Self::pull) method.
    type PullFuture: Future<Output = Result<PullResponse<C, Self>, Self::Error>>;

    /// Pull Data Iterator Type
    type PullData: IntoIterator<Item = LedgerData<C>>;

    /// Push Future Type
    ///
    /// Future for the [`push`](Self::push) method.
    type PushFuture: Future<Output = Result<PushResponse<C, Self>, Self::Error>>;

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
}

/// Ledger Source Pull Response
///
/// This `struct` is created by the [`pull`](Connection::pull) method on [`Connection`].
/// See its documentation for more.
pub struct PullResponse<C, L>
where
    C: transfer::Configuration,
    L: Connection<C> + ?Sized,
{
    /// Current Ledger Checkpoint
    pub checkpoint: L::Checkpoint,

    /// Ledger Data
    pub data: L::PullData,
}

/// Ledger Source Push Response
///
/// This `struct` is created by the [`push`](Connection::push) method on [`Connection`].
/// See its documentation for more.
pub struct PushResponse<C, L>
where
    C: transfer::Configuration,
    L: Connection<C> + ?Sized,
{
    /// Current Ledger Checkpoint
    pub checkpoint: L::Checkpoint,

    /// Transaction Failed at the Given Index
    pub failure_index: Option<usize>,
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

impl<C> LedgerData<C>
where
    C: transfer::Configuration,
{
    /// Extracts the sender data, if `self` matches [`Self::Sender`].
    #[inline]
    pub fn sender(self) -> Option<VoidNumber<C>> {
        match self {
            Self::Sender(void_number) => Some(void_number),
            _ => None,
        }
    }

    /// Extracts the receiver data, if `self` matches [`Self::Receiver`].
    #[inline]
    pub fn receiver(self) -> Option<(Utxo<C>, EncryptedAsset<C>)> {
        match self {
            Self::Receiver(utxo, encryped_asset) => Some((utxo, encryped_asset)),
            _ => None,
        }
    }
}
