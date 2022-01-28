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

//! Signer Client Abstraction

use crate::{
    transfer::{canonical::Transaction, Configuration, ReceivingKey},
    wallet::signer::{self, SignResponse, SyncRequest, SyncResponse},
};
use core::marker::PhantomData;
use manta_util::message::{Channel, ChannelError, Input, Output, ParsingReadError, UniformChannel};

/// Parsing Error
pub enum ParsingError<SY, SI, RE> {
    /// Sync Response Error
    SyncResponse(SY),

    /// Sign Response Error
    SignResponse(SI),

    /// Receiving Key Response Error
    ReceivingKey(RE),
}

/// Error
pub enum Error<E, W, R, SY, SI, RE> {
    /// Signer Error
    Signer(E),

    /// Channel Error
    Channel(ChannelError<W, R>),

    /// Parsing Error
    Parse(ParsingError<SY, SI, RE>),
}

impl<E, W, R, SY, SI, RE> Error<E, W, R, SY, SI, RE> {
    ///
    #[inline]
    pub fn convert_sync<T>(
        result: Result<Result<T, E>, ChannelError<W, ParsingReadError<R, SY>>>,
    ) -> Result<T, Self> {
        match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(err)) => Err(Self::Signer(err)),
            Err(ChannelError::Write(err)) => Err(Self::Channel(ChannelError::Write(err))),
            Err(ChannelError::Read(ParsingReadError::Read(err))) => {
                Err(Self::Channel(ChannelError::Read(err)))
            }
            Err(ChannelError::Read(ParsingReadError::Parse(err))) => {
                Err(Self::Parse(ParsingError::SyncResponse(err)))
            }
        }
    }

    ///
    #[inline]
    pub fn convert_sign<T>(
        result: Result<Result<T, E>, ChannelError<W, ParsingReadError<R, SI>>>,
    ) -> Result<T, Self> {
        match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(err)) => Err(Self::Signer(err)),
            Err(ChannelError::Write(err)) => Err(Self::Channel(ChannelError::Write(err))),
            Err(ChannelError::Read(ParsingReadError::Read(err))) => {
                Err(Self::Channel(ChannelError::Read(err)))
            }
            Err(ChannelError::Read(ParsingReadError::Parse(err))) => {
                Err(Self::Parse(ParsingError::SignResponse(err)))
            }
        }
    }

    ///
    #[inline]
    pub fn convert_receiving_key<T>(
        result: Result<Result<T, E>, ChannelError<W, ParsingReadError<R, RE>>>,
    ) -> Result<T, Self> {
        match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(err)) => Err(Self::Signer(err)),
            Err(ChannelError::Write(err)) => Err(Self::Channel(ChannelError::Write(err))),
            Err(ChannelError::Read(ParsingReadError::Read(err))) => {
                Err(Self::Channel(ChannelError::Read(err)))
            }
            Err(ChannelError::Read(ParsingReadError::Parse(err))) => {
                Err(Self::Parse(ParsingError::ReceivingKey(err)))
            }
        }
    }
}

/// Client Connection
pub struct Client<C, E, H>
where
    C: Configuration,
{
    /// Communication Channel
    channel: H,

    /// Type Parameter Marker
    __: PhantomData<(C, E)>,
}

impl<C, E, H> Client<C, E, H>
where
    C: Configuration,
{
    /// Builds a new [`Client`] from `channel`.
    #[inline]
    pub fn new(channel: H) -> Self {
        Self {
            channel,
            __: PhantomData,
        }
    }
}

impl<C, E, H> signer::Connection<C> for Client<C, E, H>
where
    C: signer::Configuration,
    H: UniformChannel
        + Input<SyncRequest<C>>
        + Input<Transaction<C>>
        + Input<()>
        + Output<Result<SyncResponse, E>>
        + Output<Result<SignResponse<C>, E>>
        + Output<Result<ReceivingKey<C>, E>>,
{
    type Error = Error<
        E,
        <H as UniformChannel>::WriteError,
        <H as UniformChannel>::ReadError,
        <H as Output<Result<SyncResponse, E>>>::Error,
        <H as Output<Result<SignResponse<C>, E>>>::Error,
        <H as Output<Result<ReceivingKey<C>, E>>>::Error,
    >;

    #[inline]
    fn sync(&mut self, request: SyncRequest<C>) -> Result<SyncResponse, Self::Error> {
        Error::convert_sync(self.channel.request(request))
    }

    #[inline]
    fn sign(&mut self, transaction: Transaction<C>) -> Result<SignResponse<C>, Self::Error> {
        Error::convert_sign(self.channel.request(transaction))
    }

    #[inline]
    fn receiving_key(&mut self) -> Result<ReceivingKey<C>, Self::Error> {
        Error::convert_receiving_key(self.channel.request(()))
    }
}
