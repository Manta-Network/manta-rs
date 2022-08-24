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

//! Codec Utilities

use ark_std::io::{self, Error, ErrorKind};
use manta_util::codec::{Read, ReadExactError, Write};

pub use manta_crypto::arkworks::serialize::{
    CanonicalDeserialize, CanonicalSerialize, SerializationError,
};

/// Scale-Codec Input as Reader Wrapper
#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
#[derive(Debug, Eq, Hash, PartialEq)]
pub struct ScaleCodecReader<'i, I>(pub &'i mut I)
where
    I: scale_codec::Input;

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl<I> io::Read for ScaleCodecReader<'_, I>
where
    I: scale_codec::Input,
{
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let len = buf.len();
        self.read_exact(buf).map(|_| len)
    }

    #[inline]
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        scale_codec::Input::read(self.0, buf).map_err(|_| ErrorKind::Other.into())
    }
}

/// Serialization Hook
pub trait HasSerialization<'s>: 's {
    /// Serialize Type
    type Serialize: CanonicalSerialize + From<&'s Self>;
}

/// Deserialization Hook
pub trait HasDeserialization: Sized {
    /// Deserialize Type
    type Deserialize: CanonicalDeserialize + Into<Self>;
}

/// Arkworks Reader
pub struct ArkReader<R>
where
    R: Read,
{
    /// Reader State
    state: Result<R, R::Error>,
}

impl<R> ArkReader<R>
where
    R: Read,
{
    /// Builds a new [`ArkReader`] from `reader`.
    #[inline]
    pub fn new(reader: R) -> Self {
        Self { state: Ok(reader) }
    }

    /// Updates the internal reader state by performing the `f` computation.
    #[inline]
    fn update<T, F>(&mut self, f: F) -> Option<T>
    where
        F: FnOnce(&mut R) -> Result<T, R::Error>,
    {
        if let Ok(reader) = self.state.as_mut() {
            match f(reader) {
                Ok(value) => return Some(value),
                Err(err) => self.state = Err(err),
            }
        }
        None
    }

    /// Returns the reader state back or an error if it occured during any [`Read`](io::Read)
    /// methods.
    #[inline]
    pub fn finish(self) -> Result<R, R::Error> {
        self.state
    }
}

impl<R> io::Read for ArkReader<R>
where
    R: Read,
{
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.update(|reader| reader.read(buf))
            .ok_or_else(|| Error::new(ErrorKind::Other, "Reading Error"))
    }

    #[inline]
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        match self.update(|reader| match reader.read_exact(buf) {
            Ok(value) => Ok(Ok(value)),
            Err(ReadExactError::Read(err)) => Err(err),
            Err(ReadExactError::UnexpectedEnd(err)) => Ok(Err(err)),
        }) {
            Some(Ok(_)) => Ok(()),
            Some(Err(_)) => Err(Error::new(
                ErrorKind::UnexpectedEof,
                "Unexpected end of buffer.",
            )),
            _ => Err(Error::new(ErrorKind::Other, "Reading Error")),
        }
    }
}

/// Arkworks Writer
pub struct ArkWriter<W>
where
    W: Write,
{
    /// Writer State
    state: Result<W, W::Error>,
}

impl<W> ArkWriter<W>
where
    W: Write,
{
    /// Builds a new [`ArkWriter`] from `writer`.
    #[inline]
    pub fn new(writer: W) -> Self {
        Self { state: Ok(writer) }
    }

    /// Updates the internal writer state by performing the `f` computation.
    #[inline]
    fn update<T, F>(&mut self, f: F) -> Option<T>
    where
        F: FnOnce(&mut W) -> Result<T, W::Error>,
    {
        if let Ok(writer) = self.state.as_mut() {
            match f(writer) {
                Ok(value) => return Some(value),
                Err(err) => self.state = Err(err),
            }
        }
        None
    }

    /// Returns the writer state back or an error if it occured during any [`Write`](io::Write)
    /// methods.
    #[inline]
    pub fn finish(self) -> Result<W, W::Error> {
        self.state
    }
}

impl<W> io::Write for ArkWriter<W>
where
    W: Write,
{
    #[inline]
    fn write(&mut self, mut buf: &[u8]) -> Result<usize, Error> {
        self.update(|writer| writer.write(&mut buf))
            .ok_or_else(|| Error::new(ErrorKind::Other, "Writing Error"))
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Error> {
        // NOTE: We can't necessarily do better than this for now, unfortunately.
        Ok(())
    }

    #[inline]
    fn write_all(&mut self, mut buf: &[u8]) -> Result<(), Error> {
        self.update(|writer| writer.write(&mut buf))
            .map(|_| ())
            .ok_or_else(|| Error::new(ErrorKind::Other, "Writing Error"))
    }
}
