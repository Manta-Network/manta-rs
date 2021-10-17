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

// TODO: Move to asynchronous streaming model so we can process some of the data as it is incoming.
// TODO: Add non-atomic transactions. See similar comment in `crate::wallet::signer`.

use crate::{
    identity::{Utxo, VoidNumber},
    transfer::{Configuration, EncryptedAsset, TransferPost},
};
use alloc::vec::Vec;
use core::future::Future;

/// Ledger Checkpoint
pub trait Checkpoint: Default + PartialOrd {
    /// Returns the number of receivers that have participated in transactions on the ledger so far.
    fn receiver_index(&self) -> usize;

    /// Returns the number of senders that have participated in transactions on the ledger so far.
    fn sender_index(&self) -> usize;
}

/// Ledger Source Connection
pub trait Connection<C>
where
    C: Configuration,
{
    /// Ledger State Checkpoint Type
    type Checkpoint: Checkpoint;

    /// Receiver Data Iterator Type
    type ReceiverData: IntoIterator<Item = (Utxo<C>, EncryptedAsset<C>)>;

    /// Sender Data Iterator Type
    type SenderData: IntoIterator<Item = VoidNumber<C>>;

    /// Pull Future Type
    ///
    /// Future for the [`pull`](Self::pull) method.
    type PullFuture: Future<Output = PullResult<C, Self>>;

    /// Pull All Future Type
    ///
    /// Future for the [`pull_all`](Self::pull_all) method.
    type PullAllFuture: Future<Output = PullAllResult<C, Self>>;

    /// Push Future Type
    ///
    /// Future for the [`push`](Self::push) method.
    type PushFuture: Future<Output = PushResult<C, Self>>;

    /// Error Type
    type Error;

    /// Pulls receiver data from the ledger starting from `checkpoint`, returning the current
    /// [`Checkpoint`](Self::Checkpoint).
    fn pull(&self, checkpoint: &Self::Checkpoint) -> Self::PullFuture;

    /// Pulls all data from the ledger, returning the current [`Checkpoint`](Self::Checkpoint).
    fn pull_all(&self) -> Self::PullAllFuture;

    /// Sends `posts` to the ledger to be appended atomically, returning `false` if the posts were
    /// invalid.
    fn push(&self, posts: Vec<TransferPost<C>>) -> Self::PushFuture;
}

/// Ledger Source Pull Result
///
/// See the [`pull`](Connection::pull) method on [`Connection`] for more information.
pub type PullResult<C, L> = Result<PullResponse<C, L>, <L as Connection<C>>::Error>;

/// Ledger Source Pull All Result
///
/// See the [`pull_all`](Connection::pull_all) method on [`Connection`] for more information.
pub type PullAllResult<C, L> = Result<PullAllResponse<C, L>, <L as Connection<C>>::Error>;

/// Ledger Source Push Result
///
/// See the [`push`](Connection::push) method on [`Connection`] for more information.
pub type PushResult<C, L> = Result<PushResponse<C, L>, <L as Connection<C>>::Error>;

/// Ledger Source Pull Response
///
/// This `struct` is created by the [`pull`](Connection::pull) method on [`Connection`].
/// See its documentation for more.
pub struct PullResponse<C, L>
where
    C: Configuration,
    L: Connection<C> + ?Sized,
{
    /// Current Ledger Checkpoint
    pub checkpoint: L::Checkpoint,

    /// Ledger Receiver Data
    pub receiver_data: L::ReceiverData,
}

/// Ledger Source Pull All Response
///
/// This `struct` is created by the [`pull_all`](Connection::pull_all) method on [`Connection`].
/// See its documentation for more.
pub struct PullAllResponse<C, L>
where
    C: Configuration,
    L: Connection<C> + ?Sized,
{
    /// Current Ledger Checkpoint
    pub checkpoint: L::Checkpoint,

    /// Ledger Receiver Data
    pub receiver_data: L::ReceiverData,

    /// Ledger Sender Data
    pub sender_data: L::SenderData,
}

/// Ledger Source Push Response
///
/// This `struct` is created by the [`push`](Connection::push) method on [`Connection`].
/// See its documentation for more.
pub struct PushResponse<C, L>
where
    C: Configuration,
    L: Connection<C> + ?Sized,
{
    /// Current Ledger Checkpoint
    pub checkpoint: L::Checkpoint,

    /// Successful Push
    pub success: bool,
}
