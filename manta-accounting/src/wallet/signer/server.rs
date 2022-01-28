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
    transfer::canonical::Transaction,
    wallet::signer::{Configuration, Error, SignResponse, Signer},
};
use manta_util::message::{Channel, ChannelError};

///
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
    ///
    #[inline]
    pub fn new(base: Signer<C>) -> Self {
        Self {
            base,
            channel: None,
        }
    }

    ///
    #[inline]
    pub fn connect(&mut self, channel: H) {
        self.channel = Some(channel);
    }

    ///
    #[inline]
    pub fn disconnect(&mut self) {
        self.channel = None;
    }

    ///
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
}
