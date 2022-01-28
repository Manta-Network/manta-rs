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

//! Signer Server Abstraction

use crate::{
    transfer::{canonical::Transaction, ReceivingKey},
    wallet::signer::{Configuration, Error, SignResponse, Signer, SyncRequest, SyncResponse},
};
use manta_util::message::{Channel, ChannelError};

/// Signer Server
pub struct Server<C, H>
where
    C: Configuration,
{
    /// Base Signer
    base: Signer<C>,

    /// Communication Channel
    channel: Option<H>,
}

impl<C, H> Server<C, H>
where
    C: Configuration,
{
    /// Builds a new [`Server`] from a given `base` signer.
    #[inline]
    pub fn new(base: Signer<C>) -> Self {
        Self {
            base,
            channel: None,
        }
    }

    /// Connects `self` along the given `channel`.
    #[inline]
    pub fn connect(&mut self, channel: H) {
        self.channel = Some(channel);
    }

    /// Disconnects `self` from the internal channel.
    #[inline]
    pub fn disconnect(&mut self) {
        self.channel = None;
    }

    /// Runs the `sync` command on the [`Signer`].
    #[inline]
    pub fn sync(&mut self) -> Result<bool, ChannelError<H::WriteError, H::ReadError>>
    where
        H: Channel<Result<SyncResponse, Error<C>>, SyncRequest<C>>,
    {
        if let Some(channel) = self.channel.as_mut() {
            channel
                .listen(|_, request| {
                    self.base
                        .sync(request.starting_index, request.inserts, request.removes)
                })
                .map(move |_| true)
        } else {
            Ok(false)
        }
    }

    /// Runs the `sign` command on the [`Signer`].
    #[inline]
    pub fn sign(&mut self) -> Result<bool, ChannelError<H::WriteError, H::ReadError>>
    where
        H: Channel<Result<SignResponse<C>, Error<C>>, Transaction<C>>,
    {
        if let Some(channel) = self.channel.as_mut() {
            channel
                .listen(|_, transaction| self.base.sign(transaction))
                .map(move |_| true)
        } else {
            Ok(false)
        }
    }

    /// Runs the `receiving_key` command on the [`Signer`].
    #[inline]
    pub fn receiving_key(&mut self) -> Result<bool, ChannelError<H::WriteError, H::ReadError>>
    where
        H: Channel<Result<ReceivingKey<C>, Error<C>>, ()>,
    {
        if let Some(channel) = self.channel.as_mut() {
            channel
                .listen(|_, _| self.base.receiving_key())
                .map(move |_| true)
        } else {
            Ok(false)
        }
    }
}
