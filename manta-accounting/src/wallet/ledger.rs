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

use crate::transfer::{Configuration, EncryptedNote, TransferPost, Utxo, VoidNumber};
use alloc::vec::Vec;
use core::{fmt::Debug, hash::Hash};
use manta_util::future::LocalBoxFutureResult;

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Ledger Checkpoint
///
/// The checkpoint type is responsible for keeping the ledger, signer, and wallet in sync with each
/// other making sure that they all have the same view of the ledger state. Checkpoints should
/// be orderable with a bottom element returned by [`Default::default`].
pub trait Checkpoint: Default + PartialOrd {
    /// Returns the index into the receiver set for the ledger.
    fn receiver_index(&self) -> usize;

    /// Returns the index into the sender set for the ledger.
    fn sender_index(&self) -> usize;
}

/// Ledger Pull Configuration
pub trait PullConfiguration<C>
where
    C: Configuration,
{
    /// Ledger State Checkpoint Type
    type Checkpoint: Checkpoint;

    /// Receiver Chunk Iterator Type
    type ReceiverChunk: IntoIterator<Item = (Utxo<C>, EncryptedNote<C>)>;

    /// Sender Chunk Iterator Type
    type SenderChunk: IntoIterator<Item = VoidNumber<C>>;
}

/// Ledger Source Connection
pub trait Connection<C>: PullConfiguration<C>
where
    C: Configuration,
{
    /// Push Response Type
    ///
    /// This is the return type of the [`push`](Self::push) method. Use this type to customize the
    /// ledger's response to posting a set of transactions, valid or otherwise. In most cases `bool`
    /// or some result type like `Result<(), Error>` is sufficient. In other cases where the ledger
    /// cannot respond immediately to the [`push`](Self::push) command, a subscription token can be
    /// returned instead which can be used to listen to the result later on.
    type PushResponse;

    /// Error Type
    ///
    /// This error type corresponds to the communication channel itself setup by the [`Connection`]
    /// rather than any errors introduced by the [`pull`](Self::pull) or [`push`](Self::push)
    /// methods themselves which would correspond to an empty [`PullResponse`] or whatever error
    /// variants are stored in [`PushResponse`](Self::PushResponse).
    type Error;

    /// Pulls receiver data from the ledger starting from `checkpoint`, returning the current
    /// [`Checkpoint`](PullConfiguration::Checkpoint).
    fn pull<'s>(
        &'s mut self,
        checkpoint: &'s Self::Checkpoint,
    ) -> LocalBoxFutureResult<'s, PullResponse<C, Self>, Self::Error>;

    /// Sends `posts` to the ledger, returning `true` or `false` depending on whether the entire
    /// batch succeeded or not.
    fn push(
        &mut self,
        posts: Vec<TransferPost<C>>,
    ) -> LocalBoxFutureResult<Self::PushResponse, Self::Error>;
}

/// Ledger Source Pull Response
///
/// This `struct` is created by the [`pull`](Connection::pull) method on [`Connection`].
/// See its documentation for more.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = r"
                L::Checkpoint: Deserialize<'de>,
                L::ReceiverChunk: Deserialize<'de>,
                L::SenderChunk: Deserialize<'de>
            ",
            serialize = r"
                L::Checkpoint: Serialize,
                L::ReceiverChunk: Serialize,
                L::SenderChunk: Serialize
            ",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
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
    L: PullConfiguration<C> + ?Sized,
{
    /// Pull Continuation Flag
    ///
    /// The `should_continue` flag is set to `true` if the client should request more data from the
    /// ledger to finish the pull.
    pub should_continue: bool,

    /// Ledger Checkpoint
    ///
    /// If the `should_continue` flag is set to `true` then `checkpoint` is the next
    /// [`Checkpoint`](PullConfiguration::Checkpoint) to request data from the ledger. Otherwise, it
    /// represents the current ledger state.
    pub checkpoint: L::Checkpoint,

    /// Ledger Receiver Chunk
    pub receivers: L::ReceiverChunk,

    /// Ledger Sender Chunk
    pub senders: L::SenderChunk,
}
