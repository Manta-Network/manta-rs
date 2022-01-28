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

/// Message-Passing Channel
pub trait Channel<W, R = W> {
    /// Write Error Type
    type WriteError;

    /// Read Error Type
    type ReadError;

    /// Writes a `message` of type `W` to the channel, or a [`WriteError`](Self::WriteError) if the
    /// write failed.
    fn write(&mut self, message: W) -> Result<(), Self::WriteError>;

    /// Reads a message of type `R` from the channel, or a [`ReadError`](Self::ReadError) if the
    /// read failed.
    fn read(&mut self) -> Result<R, Self::ReadError>;

    /// Sends a `request` of type `W` on the channel using [`write`](Self::write) waiting for a
    /// response of type `R` on the channel using [`read`](Self::read).
    #[inline]
    fn request(
        &mut self,
        request: W,
    ) -> Result<R, ChannelError<Self::WriteError, Self::ReadError>> {
        self.write(request).map_err(ChannelError::Write)?;
        self.read().map_err(ChannelError::Read)
    }

    /// Listens on the channel for a request of type `R` using [`read`](Self::read), processes the
    /// request using `process` and sends the response message back along the channel using
    /// [`write`](Self::write).
    #[inline]
    fn listen<F>(
        &mut self,
        process: F,
    ) -> Result<(), ChannelError<Self::WriteError, Self::ReadError>>
    where
        F: FnOnce(&mut Self, R) -> W,
    {
        let request = self.read().map_err(ChannelError::Read)?;
        let response = process(self, request);
        self.write(response).map_err(ChannelError::Write)
    }
}

/// Channel Error
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ChannelError<W, R> {
    /// Write Error
    Write(W),

    /// Read Error
    Read(R),
}

impl<W, R> ChannelError<W, R> {
    /// Converts `self` into an `Option` over [`W`](Channel::WriteError).
    #[inline]
    pub fn write(self) -> Option<W> {
        match self {
            Self::Write(err) => Some(err),
            _ => None,
        }
    }

    /// Converts `self` into an `Option` over [`R`](Channel::ReadError).
    #[inline]
    pub fn read(self) -> Option<R> {
        match self {
            Self::Read(err) => Some(err),
            _ => None,
        }
    }
}

impl<P, E> ChannelError<E, ParsingReadError<E, P>> {
    /// Unwraps the inner error.
    #[inline]
    pub fn into_parsing_error(self) -> ParsingError<E, P> {
        match self {
            Self::Write(err) => ParsingError::Error(err),
            Self::Read(err) => match err {
                ParsingReadError::Read(err) => ParsingError::Error(err),
                ParsingReadError::Parse(err) => ParsingError::Parse(err),
            },
        }
    }
}

impl<E> ChannelError<E, E> {
    /// Unwraps the inner error.
    #[inline]
    pub fn into_inner(self) -> E {
        match self {
            Self::Write(err) => err,
            Self::Read(err) => err,
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

/// Uniform Channel Input
pub trait Input<T>: UniformChannel {
    /// Converts `t` into a message that can be sent in the [`UniformChannel`].
    fn convert(t: T) -> Self::Message;
}

/// Uniform Channel Output
pub trait Output<T>: UniformChannel {
    /// Parsing Error
    type Error;

    /// Parses an incoming message that was just output from the [`UniformChannel`] and tries to
    /// convert it into `T`.
    fn parse(message: Self::Message) -> Result<T, Self::Error>;
}

/// Uniform Message-Passing Channel
pub trait UniformChannel {
    /// Message Type
    type Message;

    /// Write Error Type
    type WriteError;

    /// Read Error Type
    type ReadError;

    /// Writes a `message` to the channel, or a [`WriteError`](Self::WriteError) if the write
    /// failed.
    fn write(&mut self, message: Self::Message) -> Result<(), Self::WriteError>;

    /// Reads a message from the channel, or a [`ReadError`](Self::ReadError) if the read failed.
    fn read(&mut self) -> Result<Self::Message, Self::ReadError>;
}

impl<C, W, R> Channel<W, R> for C
where
    C: UniformChannel + Input<W> + Output<R>,
{
    type WriteError = C::WriteError;
    type ReadError = ParsingReadError<C::ReadError, <C as Output<R>>::Error>;

    #[inline]
    fn write(&mut self, message: W) -> Result<(), Self::WriteError> {
        self.write(Self::convert(message))
    }

    #[inline]
    fn read(&mut self) -> Result<R, Self::ReadError> {
        Self::parse(self.read().map_err(ParsingReadError::Read)?).map_err(ParsingReadError::Parse)
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
