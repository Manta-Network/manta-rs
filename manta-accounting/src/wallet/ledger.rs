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

//! Ledger Connection

// TODO: Report a more meaningful error on `push` failure. In some way, it must match the
//       `TransferPostError` variants.

use crate::transfer::{Configuration, EncryptedNote, TransferPost, Utxo, VoidNumber};
use alloc::vec::Vec;
use core::{fmt::Debug, hash::Hash};

/// Ledger Checkpoint
pub trait Checkpoint: Default + PartialOrd {
    /// Returns the index into the receiver set for the ledger.
    ///
    /// This index is used to ensure that wallets are synchronized even during connection failures
    /// or other errors during synchronization.
    fn receiver_index(&self) -> usize;
}

/// Ledger Source Connection
pub trait Connection<C>
where
    C: Configuration,
{
    /// Ledger State Checkpoint Type
    type Checkpoint: Checkpoint;

    /// Receiver Chunk Iterator Type
    type ReceiverChunk: IntoIterator<Item = (Utxo<C>, EncryptedNote<C>)>;

    /// Sender Chunk Iterator Type
    type SenderChunk: IntoIterator<Item = VoidNumber<C>>;

    /// Error Type
    type Error;

    /// Pulls receiver data from the ledger starting from `checkpoint`, returning the current
    /// [`Checkpoint`](Self::Checkpoint).
    fn pull(&mut self, checkpoint: &Self::Checkpoint) -> PullResult<C, Self>;

    /// Sends `posts` to the ledger, returning `true` or `false` depending on whether the entire
    /// batch succeeded or not.
    fn push(&mut self, posts: Vec<TransferPost<C>>) -> PushResult<C, Self>;
}

/// Ledger Source Pull Result
///
/// See the [`pull`](Connection::pull) method on [`Connection`] for more information.
pub type PullResult<C, L> = Result<PullResponse<C, L>, <L as Connection<C>>::Error>;

/// Ledger Source Push Result
///
/// See the [`push`](Connection::push) method on [`Connection`] for more information.
pub type PushResult<C, L> = Result<PushResponse, <L as Connection<C>>::Error>;

/// Ledger Source Pull Response
///
/// This `struct` is created by the [`pull`](Connection::pull) method on [`Connection`].
/// See its documentation for more.
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "L::Checkpoint: Clone, L::ReceiverChunk: Clone, L::SenderChunk: Clone"),
    Copy(bound = "L::Checkpoint: Copy, L::ReceiverChunk: Copy, L::SenderChunk: Copy"),
    Debug(bound = "L::Checkpoint: Debug, L::ReceiverChunk: Debug, L::SenderChunk: Debug"),
    Default(bound = "L::Checkpoint: Default, L::ReceiverChunk: Default, L::SenderChunk: Default"),
    Eq(bound = "L::Checkpoint: Eq, L::ReceiverChunk: Eq, L::SenderChunk: Eq"),
    Hash(bound = "L::Checkpoint: Hash, L::ReceiverChunk: Hash, L::SenderChunk: Hash"),
    PartialEq(
        bound = "L::Checkpoint: PartialEq, L::ReceiverChunk: PartialEq, L::SenderChunk: PartialEq"
    )
)]
pub struct PullResponse<C, L>
where
    C: Configuration,
    L: Connection<C> + ?Sized,
{
    /// Pull Continuation Flag
    ///
    /// The `should_continue` flag is set to `true` if the client should request more data from the
    /// ledger to finish the pull.
    pub should_continue: bool,

    /// Ledger Checkpoint
    ///
    /// If the `should_continue` flag is set to `true` then `checkpoint` is the next
    /// [`Checkpoint`](Connection::Checkpoint) to request data from the ledger. Otherwise, it
    /// represents the current ledger state.
    pub checkpoint: L::Checkpoint,

    /// Ledger Receiver Chunk
    pub receivers: L::ReceiverChunk,

    /// Ledger Sender Chunk
    pub senders: L::SenderChunk,
}

/// Ledger Source Push Response
///
/// This `struct` is created by the [`push`](Connection::push) method on [`Connection`].
/// See its documentation for more.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PushResponse {
    /// Transaction Success Flag
    ///
    /// The `success` flag is set to `true` if the ledger accepted the vector of [`TransferPost`]
    /// and the ledger has been updated to the new state.
    pub success: bool,
}
