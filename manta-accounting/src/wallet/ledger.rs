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

use core::{fmt::Debug, hash::Hash};
use manta_util::future::LocalBoxFutureResult;

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Ledger Connection
///
/// This is the base `trait` for defining a connection with a ledger. To communicate with the
/// ledger, you can establish such a connection first and then interact via the [`Read`] and
/// [`Write`] traits which send messages along the connection.
pub trait Connection {
    /// Error Type
    ///
    /// This error type corresponds to the communication channel setup by the [`Connection`] rather
    /// than any errors introduced by [`read`] or [`write`] methods. Instead those methods should
    /// return errors in their `Response` types.
    ///
    /// [`read`]: Read::read
    /// [`write`]: Write::write
    type Error;
}

/// Ledger Checkpoint
///
/// The checkpoint type is responsible for keeping the ledger, signer, and wallet in sync with each
/// other making sure that they all have the same view of the ledger state. Checkpoints should
/// be orderable with a bottom element returned by [`Default::default`]. Types implementing this
/// `trait` must also implement [`Clone`] as it must be safe (but not necessarily efficient) to
/// copy a checkpoint value.
pub trait Checkpoint: Clone + Default + PartialOrd {}

/// Ledger Data Pruning
pub trait Prune<T>
where
    T: Checkpoint,
{
    /// Prunes the data in `self`, which was retrieved at `origin`, so that it meets the current
    /// `checkpoint`, dropping data that is older than the given `checkpoint`. This method should
    /// return `true` if it dropped data from `self`.
    fn prune(&mut self, origin: &T, checkpoint: &T) -> bool;
}

/// Ledger Connection Reading
pub trait Read<D>: Connection {
    /// Checkpoint Type
    type Checkpoint: Checkpoint;

    /// Gets data from the ledger starting from `checkpoint`, returning the current
    /// [`Checkpoint`](Self::Checkpoint).
    fn read<'s>(
        &'s mut self,
        checkpoint: &'s Self::Checkpoint,
    ) -> LocalBoxFutureResult<'s, ReadResponse<Self::Checkpoint, D>, Self::Error>;
}

/// Ledger Connection Read Response
///
/// This `struct` is created by the [`read`](Read::read) method on [`Read`].
/// See its documentation for more.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ReadResponse<T, D>
where
    T: Checkpoint,
{
    /// Read Continuation Flag
    ///
    /// The `should_continue` flag is set to `true` if the client should request more data from the
    /// ledger to finish the requested [`read`](Read::read).
    pub should_continue: bool,

    /// Next Ledger Checkpoint
    ///
    /// This checkpoint represents the new checkpoint that the client should be synchronized to when
    /// incorporating the [`data`] returned by the [`read`] request. To continue the request the
    /// client should send this checkpoint in their next call to [`read`].
    ///
    /// [`data`]: Self::data
    /// [`read`]: Read::read
    pub next_checkpoint: T,

    /// Data Payload
    ///
    /// This is the data payload that was returned by the ledger corresponding to the
    /// [`read`](Read::read) request.
    pub data: D,
}

/// Ledger Connection Writing
pub trait Write<R>: Connection {
    /// Ledger Response Type
    ///
    /// This is the return type of the [`write`] method. Use this type to customize the ledger's
    /// response to performing a [`write`] call, valid or otherwise. In most cases `bool` or some
    /// result type like `Result<(), Error>` is sufficient. In other cases where the ledger cannot
    /// respond immediately to the [`write`] command, a subscription token can be returned instead
    /// which can be used to listen to the result later on.
    type Response;

    /// Sends the `request` to the ledger, returning its [`Response`](Self::Response).
    fn write(&mut self, request: R) -> LocalBoxFutureResult<Self::Response, Self::Error>;
}
