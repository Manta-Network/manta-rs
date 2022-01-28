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

//! Message-Passing Utilities

use crate::convert::{Into, TryInto};

/// Message-Passing Channel
pub trait Channel<R, W> {
    /// Read Error Type
    type ReadError;

    /// Write Error Type
    type WriteError;

    /// Reads a message of type `R` from the channel, or a [`ReadError`](Self::ReadError) if the
    /// read failed.
    fn read(&mut self) -> Result<R, Self::ReadError>;

    /// Writes a `message` of type `W` to the channel, or a [`WriteError`](Self::WriteError) if the
    /// write failed.
    fn write(&mut self, message: W) -> Result<(), Self::WriteError>;
}

/// Channel Error
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ChannelError<R, W> {
    /// Read Error
    Read(R),

    /// Write Error
    Write(W),
}

impl<R, W> ChannelError<R, W> {
    /// Converts `self` into an `Option` over [`R`](Channel::ReadError).
    #[inline]
    pub fn read(self) -> Option<R> {
        match self {
            Self::Read(err) => Some(err),
            _ => None,
        }
    }

    /// Converts `self` into an `Option` over [`W`](Channel::WriteError).
    #[inline]
    pub fn write(self) -> Option<W> {
        match self {
            Self::Write(err) => Some(err),
            _ => None,
        }
    }
}

impl<E, P> ChannelError<ParsingReadError<E, P>, E> {
    /// Unwraps the inner error.
    #[inline]
    pub fn into_parsing_error(self) -> ParsingError<E, P> {
        match self {
            Self::Read(err) => match err {
                ParsingReadError::Read(err) => ParsingError::Error(err),
                ParsingReadError::Parse(err) => ParsingError::Parse(err),
            },
            Self::Write(err) => ParsingError::Error(err),
        }
    }
}

impl<E> ChannelError<E, E> {
    /// Unwraps the inner error.
    #[inline]
    pub fn into_inner(self) -> E {
        match self {
            Self::Read(err) => err,
            Self::Write(err) => err,
        }
    }
}

/// Parsing Error
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ParsingError<E, P> {
    /// Base Error
    Error(E),

    /// Parse Error
    Parse(P),
}

/// Uniform Message-Passing Channel
pub trait UniformChannel {
    /// Message Type
    type Message;

    /// Read Error Type
    type ReadError;

    /// Write Error Type
    type WriteError;

    /// Reads a message from the channel, or a [`ReadError`](Self::ReadError) if the read failed.
    fn read(&mut self) -> Result<Self::Message, Self::ReadError>;

    /// Writes a `message` to the channel, or a [`WriteError`](Self::WriteError) if the write
    /// failed.
    fn write(&mut self, message: Self::Message) -> Result<(), Self::WriteError>;
}

impl<C, R, W> Channel<R, W> for C
where
    C: UniformChannel,
    C::Message: TryInto<R, C>,
    W: Into<C::Message, C>,
{
    type ReadError = ParsingReadError<C::ReadError, <C::Message as TryInto<R, C>>::Error>;
    type WriteError = C::WriteError;

    #[inline]
    fn read(&mut self) -> Result<R, Self::ReadError> {
        TryInto::try_into(self.read().map_err(ParsingReadError::Read)?)
            .map_err(ParsingReadError::Parse)
    }

    #[inline]
    fn write(&mut self, message: W) -> Result<(), Self::WriteError> {
        self.write(Into::into(message))
    }
}

/// Parsing Read Error
///
/// This `enum` is the error state for the [`Channel`] implementation of [`UniformChannel`] which
/// can either be a reading error or a parsing error when transforming a message from the uniform
/// format to the specific read type of the [`Channel`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ParsingReadError<R, P> {
    /// Read Error
    Read(R),

    /// Parse Error
    Parse(P),
}

/// Client Error Type
pub type ClientError<P> = ChannelError<
    <<P as MessageProtocol>::Client as Channel<
        <P as MessageProtocol>::Response,
        <P as MessageProtocol>::Request,
    >>::ReadError,
    <<P as MessageProtocol>::Client as Channel<
        <P as MessageProtocol>::Response,
        <P as MessageProtocol>::Request,
    >>::WriteError,
>;

/// Server Error Type
pub type ServerError<P> = ChannelError<
    <<P as MessageProtocol>::Server as Channel<
        <P as MessageProtocol>::Request,
        <P as MessageProtocol>::Response,
    >>::ReadError,
    <<P as MessageProtocol>::Server as Channel<
        <P as MessageProtocol>::Request,
        <P as MessageProtocol>::Response,
    >>::WriteError,
>;

/// Message-Passing Protocol
pub trait MessageProtocol {
    /// Request Type
    type Request;

    /// Response Type
    type Response;

    /// Client Channel Type
    type Client: Channel<Self::Response, Self::Request>;

    /// Server Channel Type
    type Server: Channel<Self::Request, Self::Response>;

    /// Sends the `request` from the `client` using [`write`](Channel::write), waiting for a
    /// [`read`](Channel::read) from the [`Server`](Self::Server) on the other end.
    #[inline]
    fn send(
        client: &mut Self::Client,
        request: Self::Request,
    ) -> Result<Self::Response, ClientError<Self>> {
        client.write(request).map_err(ChannelError::Write)?;
        client.read().map_err(ChannelError::Read)
    }

    /// Waits on the result of a [`read`](Channel::read) on the `server` end of the channel, then
    /// processes the result using `process` and sends the response using a
    /// [`write`](Channel::write).
    #[inline]
    fn recv<F>(server: &mut Self::Server, process: F) -> Result<(), ServerError<Self>>
    where
        F: FnOnce(&mut Self::Server, Self::Request) -> Self::Response,
    {
        let request = server.read().map_err(ChannelError::Read)?;
        let response = process(server, request);
        server.write(response).map_err(ChannelError::Write)
    }
}
