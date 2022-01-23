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

//! Encoding and Decoding Utilities

// TODO: Add `ReadFrom` and `WriteInto` traits for conversion between different serde/codec impls
//       which are specialized so that you can automatically convert between a type and itself.

use core::{convert::Infallible, fmt::Debug, hash::Hash};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Reader
pub trait Read {
    /// Error Type
    type Error;

    /// Reads bytes from `self`, pushing them to `output`. The reader need not fill the `output`
    /// buffer, but this method must return the number of bytes read into the `output`.
    fn read<T>(&mut self, output: &mut T) -> Result<usize, Self::Error>
    where
        T: AsMut<[u8]> + ?Sized;

    /// Reads bytes from `self`, pushing them to `output` until exhausting the buffer inside of
    /// `output`.
    fn read_exact<T>(&mut self, output: &mut T) -> Result<(), ReadExactError<Self>>
    where
        T: AsMut<[u8]> + ?Sized;

    /// Creates a “by mutable reference” adaptor for this instance of [`Read`].
    #[inline]
    fn by_ref(&mut self) -> &mut Self {
        self
    }
}

/// Reader Extension Trait
pub trait ReadExt: Read {
    /// Reads all bytes from `self`, pushing them to `output`, returning the number of bytes read if
    /// successful.
    #[cfg(feature = "alloc")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
    fn read_all(&mut self, output: &mut Vec<u8>) -> Result<usize, Self::Error>;
}

impl<R> Read for &mut R
where
    R: Read,
{
    type Error = R::Error;

    #[inline]
    fn read<T>(&mut self, output: &mut T) -> Result<usize, Self::Error>
    where
        T: AsMut<[u8]> + ?Sized,
    {
        (*self).read(output)
    }

    #[inline]
    fn read_exact<T>(&mut self, output: &mut T) -> Result<(), ReadExactError<Self>>
    where
        T: AsMut<[u8]> + ?Sized,
    {
        (*self).read_exact(output).map_err(ReadExactError::map_same)
    }
}

impl<R> ReadExt for &mut R
where
    R: ReadExt,
{
    #[cfg(feature = "alloc")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
    #[inline]
    fn read_all(&mut self, output: &mut Vec<u8>) -> Result<usize, Self::Error> {
        (*self).read_all(output)
    }
}

impl Read for &[u8] {
    type Error = Infallible;

    #[inline]
    fn read<T>(&mut self, output: &mut T) -> Result<usize, Self::Error>
    where
        T: AsMut<[u8]> + ?Sized,
    {
        let output = output.as_mut();
        let output_len = output.len();
        output.copy_from_slice(&self[..output_len]);
        *self = &self[output_len..];
        Ok(output_len)
    }

    #[inline]
    fn read_exact<T>(&mut self, output: &mut T) -> Result<(), ReadExactError<Self>>
    where
        T: AsMut<[u8]> + ?Sized,
    {
        let output = output.as_mut();
        let output_len = output.len();
        let len = self.len();
        if output_len > len {
            return Err(ReadExactError::UnexpectedEnd(output_len - len));
        }
        output.copy_from_slice(&self[..output_len]);
        *self = &self[output_len..];
        Ok(())
    }
}

impl ReadExt for &[u8] {
    #[cfg(feature = "alloc")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
    #[inline]
    fn read_all(&mut self, output: &mut Vec<u8>) -> Result<usize, Self::Error> {
        output.write(self)
    }
}

impl<const N: usize> Read for [u8; N] {
    type Error = Infallible;

    #[inline]
    fn read<T>(&mut self, output: &mut T) -> Result<usize, Self::Error>
    where
        T: AsMut<[u8]> + ?Sized,
    {
        let output = output.as_mut();
        let output_len = output.len();
        output.copy_from_slice(&self[..output_len]);
        Ok(output_len)
    }

    #[inline]
    fn read_exact<T>(&mut self, output: &mut T) -> Result<(), ReadExactError<Self>>
    where
        T: AsMut<[u8]> + ?Sized,
    {
        let output = output.as_mut();
        let output_len = output.len();
        let len = self.len();
        if output_len > len {
            return Err(ReadExactError::UnexpectedEnd(output_len - len));
        }
        output.copy_from_slice(&self[..output_len]);
        Ok(())
    }
}

impl<const N: usize> ReadExt for [u8; N] {
    #[cfg(feature = "alloc")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
    #[inline]
    fn read_all(&mut self, output: &mut Vec<u8>) -> Result<usize, Self::Error> {
        output.write(&mut self.as_ref())
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
impl Read for Vec<u8> {
    type Error = Infallible;

    #[inline]
    fn read<T>(&mut self, output: &mut T) -> Result<usize, Self::Error>
    where
        T: AsMut<[u8]> + ?Sized,
    {
        let mut slice = self.as_slice();
        let output_len = slice.read(output)?;
        let len = slice.len();
        self.drain(..(self.len() - len));
        Ok(output_len)
    }

    #[inline]
    fn read_exact<T>(&mut self, output: &mut T) -> Result<(), ReadExactError<Self>>
    where
        T: AsMut<[u8]> + ?Sized,
    {
        let mut slice = self.as_slice();
        slice.read_exact(output).map_err(ReadExactError::map_same)?;
        let len = slice.len();
        self.drain(..(self.len() - len));
        Ok(())
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
impl ReadExt for Vec<u8> {
    #[inline]
    fn read_all(&mut self, output: &mut Vec<u8>) -> Result<usize, Self::Error> {
        output.write_drain(self)
    }
}

/// I/O Reader
#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IoReader<R>(
    /// Reader
    pub R,
)
where
    R: std::io::Read;

#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
impl<R> Read for IoReader<R>
where
    R: std::io::Read,
{
    type Error = std::io::Error;

    #[inline]
    fn read<T>(&mut self, output: &mut T) -> Result<usize, Self::Error>
    where
        T: AsMut<[u8]> + ?Sized,
    {
        self.0.read(output.as_mut())
    }

    #[inline]
    fn read_exact<T>(&mut self, output: &mut T) -> Result<(), ReadExactError<Self>>
    where
        T: AsMut<[u8]> + ?Sized,
    {
        // NOTE: We can't use `ReadExactError::UnexpectedEnd` here since the `std::io::Read` trait
        //       doesn't expose any information about how many bytes remain in the output buffer.
        self.0
            .read_exact(output.as_mut())
            .map_err(ReadExactError::Read)
    }
}

#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
impl<R> ReadExt for IoReader<R>
where
    R: std::io::Read,
{
    #[inline]
    fn read_all(&mut self, output: &mut Vec<u8>) -> Result<usize, Self::Error> {
        self.0.read_to_end(output)
    }
}

/// Read-Exact Error
///
/// This `enum` is the error state for the [`read_exact`](Read::read_exact) method of [`Read`].
/// See its documentation for more.
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "R::Error: Clone"),
    Copy(bound = "R::Error: Copy"),
    Debug(bound = "R::Error: Debug"),
    Eq(bound = "R::Error: Eq"),
    Hash(bound = "R::Error: Hash"),
    PartialEq(bound = "R::Error: PartialEq")
)]
pub enum ReadExactError<R>
where
    R: Read + ?Sized,
{
    /// Unexpected End of Reader
    ///
    /// The reader finished producing bytes before the output buffer was filled. The amount
    /// of bytes remaining in the output buffer is returned to the caller here.
    UnexpectedEnd(usize),

    /// Reading Error
    Read(R::Error),
}

impl<R> ReadExactError<R>
where
    R: Read + ?Sized,
{
    /// Maps `self` along `f` for the [`Self::Read`] variant into another [`ReadExactError`].
    #[inline]
    pub fn map<S, F>(self, f: F) -> ReadExactError<S>
    where
        S: Read + ?Sized,
        F: FnOnce(R::Error) -> S::Error,
    {
        match self {
            Self::UnexpectedEnd(remaining) => ReadExactError::UnexpectedEnd(remaining),
            Self::Read(err) => ReadExactError::Read(f(err)),
        }
    }

    /// Maps `self` along `f` for the [`Self::Read`] variant into another [`ReadExactError`]
    /// using the same error value.
    #[inline]
    pub fn map_same<S>(self) -> ReadExactError<S>
    where
        S: Read<Error = R::Error> + ?Sized,
    {
        self.map(core::convert::identity)
    }
}

/// Writer
pub trait Write {
    /// Error Type
    type Error;

    /// Writes bytes into `self`, pulling them from `input` until exhausting the buffer inside of
    /// `self`. This method then resets the `input` slice to the remaining input data and returns
    /// the number of bytes written.
    ///
    /// To preserve the input slice and return the remaining data, use the
    /// [`write_ref`](Self::write_ref) method instead.
    fn write(&mut self, input: &mut &[u8]) -> Result<usize, Self::Error>;

    /// Writes bytes into `self` from the bytes of `input`, returning the bytes which were not
    /// written.
    #[inline]
    fn write_ref<'t, T>(&mut self, input: &'t T) -> Result<&'t [u8], Self::Error>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        let mut slice = input.as_ref();
        self.write(&mut slice)?;
        Ok(slice)
    }

    /// Writes bytes into `self` from an `input` vector of bytes.
    ///
    /// # Implementation Note
    ///
    /// This method is here to provide an optimization path against the [`Vec`] implemention of
    /// [`Write`]. The default implementation should be efficient enough for other cases.
    #[cfg(feature = "alloc")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
    #[inline]
    fn write_drain(&mut self, input: &mut Vec<u8>) -> Result<usize, Self::Error> {
        let len = input.len();
        let bytes_written = len - self.write_ref(input)?.len();
        input.drain(..bytes_written);
        Ok(bytes_written)
    }

    /// Creates a “by mutable reference” adaptor for this instance of [`Write`].
    #[inline]
    fn by_ref(&mut self) -> &mut Self {
        self
    }
}

impl<W> Write for &mut W
where
    W: Write,
{
    type Error = W::Error;

    #[inline]
    fn write(&mut self, input: &mut &[u8]) -> Result<usize, Self::Error> {
        (*self).write(input)
    }

    #[inline]
    fn write_ref<'t, T>(&mut self, input: &'t T) -> Result<&'t [u8], Self::Error>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        (*self).write_ref(input)
    }

    #[cfg(feature = "alloc")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
    #[inline]
    fn write_drain(&mut self, input: &mut Vec<u8>) -> Result<usize, Self::Error> {
        (*self).write_drain(input)
    }
}

impl Write for [u8] {
    type Error = Infallible;

    #[inline]
    fn write(&mut self, input: &mut &[u8]) -> Result<usize, Self::Error> {
        input.read(self)
    }
}

impl<const N: usize> Write for [u8; N] {
    type Error = Infallible;

    #[inline]
    fn write(&mut self, input: &mut &[u8]) -> Result<usize, Self::Error> {
        input.read(self)
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
impl Write for Vec<u8> {
    type Error = Infallible;

    #[inline]
    fn write(&mut self, input: &mut &[u8]) -> Result<usize, Self::Error> {
        let len = input.len();
        self.reserve(len);
        self.extend_from_slice(*input);
        Ok(len)
    }

    #[inline]
    fn write_drain(&mut self, input: &mut Vec<u8>) -> Result<usize, Self::Error> {
        let len = input.len();
        self.append(input);
        Ok(len)
    }
}

/// I/O Writer
#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IoWriter<W>(
    /// Writer
    pub W,
)
where
    W: std::io::Write;

#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
impl<W> Write for IoWriter<W>
where
    W: std::io::Write,
{
    type Error = std::io::Error;

    #[inline]
    fn write(&mut self, input: &mut &[u8]) -> Result<usize, Self::Error> {
        let len = input.len();
        self.0.write_all(input)?;
        *input = &input[..0];
        Ok(len)
    }
}

/// Pipelined Reader/Writer
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Pipeline<T>(pub T);

impl<R> Pipeline<R>
where
    R: Read,
{
    /// Reads bytes from `self`, pushing them to `output`. The reader need not fill the `output`
    /// buffer.
    #[inline]
    pub fn read<T>(mut self, output: &mut T) -> Result<Self, R::Error>
    where
        T: AsMut<[u8]> + ?Sized,
    {
        self.0.read(output)?;
        Ok(self)
    }

    /// Reads bytes from `self`, pushing them to `output` until exhausting the buffer inside of
    /// `output`.
    #[inline]
    pub fn read_exact<T>(mut self, output: &mut T) -> Result<Self, ReadExactError<R>>
    where
        T: AsMut<[u8]> + ?Sized,
    {
        self.0.read_exact(output)?;
        Ok(self)
    }
}

impl<R> Pipeline<R>
where
    R: ReadExt,
{
    /// Reads all bytes from `self`, pushing them to `output`.
    #[cfg(feature = "alloc")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
    #[inline]
    pub fn read_all(mut self, output: &mut Vec<u8>) -> Result<Self, R::Error> {
        self.0.read_all(output)?;
        Ok(self)
    }
}

impl<W> Pipeline<W>
where
    W: Write,
{
    /// Writes bytes into `self`, pulling them from `input` until exhausting the buffer inside of
    /// `self`. This method then resets the `input` slice to the remaining input data.
    ///
    /// To preserve the input slice, use the [`write_ref`](Self::write_ref) method instead.
    #[inline]
    pub fn write(mut self, input: &mut &[u8]) -> Result<Self, W::Error> {
        self.0.write(input)?;
        Ok(self)
    }

    /// Writes bytes into `self` from the bytes of `input`.
    #[inline]
    pub fn write_ref<T>(mut self, input: &T) -> Result<Self, W::Error>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        self.0.write_ref(input)?;
        Ok(self)
    }

    /// Writes bytes into `self` from an `input` vector of bytes.
    ///
    /// # Implementation Note
    ///
    /// This method is here to provide an optimization path against the [`Vec`] implemention of
    /// [`Write`]. The default implementation should be efficient enough for other cases.
    #[cfg(feature = "alloc")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
    #[inline]
    pub fn write_drain(mut self, input: &mut Vec<u8>) -> Result<Self, W::Error> {
        self.0.write_drain(input)?;
        Ok(self)
    }
}

/// Encoding
pub trait Encode<C = ()> {
    /// Appends representation of `self` in bytes to `buffer`.
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: Write;

    /// Converts `self` into a vector of bytes.
    #[cfg(feature = "alloc")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
    #[inline]
    fn to_vec(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        self.encode(&mut buffer)
            .expect("Writing to a `Vec<u8>` cannot fail.");
        buffer
    }
}

impl<C> Encode<C> for () {
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        let _ = writer;
        Ok(())
    }
}

impl Encode for u8 {
    #[inline]
    fn encode<W>(&self, mut writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        writer.write_ref(&[*self])?;
        Ok(())
    }
}

impl<T, C> Encode<C> for [T]
where
    T: Encode<C>,
{
    #[inline]
    fn encode<W>(&self, mut writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        for item in self {
            item.encode(&mut writer)?;
        }
        Ok(())
    }
}

impl<T, C, const N: usize> Encode<C> for [T; N]
where
    T: Encode<C>,
{
    #[inline]
    fn encode<W>(&self, mut writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        for item in self {
            item.encode(&mut writer)?;
        }
        Ok(())
    }
}

/// Exact Size Encoding
pub trait EncodeExactSize<C, const N: usize>: Encode<C> {
    /// Converts `self` into an exactly known byte array.
    #[inline]
    fn to_array(&self) -> [u8; N] {
        let mut buffer = [0; N];
        self.encode(&mut buffer)
            .expect("The implementation of this trait means that this cannot fail.");
        buffer
    }
}

/// Decoding
pub trait Decode<C = ()>: Sized {
    /// Error Type
    type Error;

    /// Parses the input `buffer` into a concrete value of type `Self` if possible.
    fn decode<R>(reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: Read;

    /// Converts a byte vector into a concrete value of type `Self` if possible.
    #[cfg(feature = "alloc")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
    #[inline]
    fn from_vec(buffer: Vec<u8>) -> Result<Self, Self::Error> {
        Self::decode(buffer)
            .map_err(move |err| err.decode().expect("Reading from `[u8]` cannot fail."))
    }
}

impl<C> Decode<C> for () {
    type Error = Infallible;

    #[inline]
    fn decode<R>(reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: Read,
    {
        let _ = reader;
        Ok(())
    }
}

/// Exact Size Decoding
pub trait DecodeExactSize<C, const N: usize>: Decode<C> {
    /// Converts a fixed-length byte array into a concrete value of type `Self`.
    #[inline]
    fn from_array(buffer: [u8; N]) -> Self {
        Self::decode(buffer)
            .ok()
            .expect("The implementation of this trait means that this cannot fail.")
    }
}

impl<C> DecodeExactSize<C, 0> for () {
    #[inline]
    fn from_array(buffer: [u8; 0]) -> Self {
        let _ = buffer;
    }
}

/// Decoding Error
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DecodeError<R, D> {
    /// Reading Error
    ///
    /// See [`Read`] for more.
    Read(R),

    /// Decoding Error
    ///
    /// See [`Decode`] for more.
    Decode(D),
}

impl<R, D> DecodeError<R, D> {
    /// Converts `self` into an option over [`R`](Read::Error).
    #[inline]
    pub fn read(self) -> Option<R> {
        match self {
            Self::Read(err) => Some(err),
            _ => None,
        }
    }

    /// Converts `self` into an option over [`D`](Decode::Error).
    #[inline]
    pub fn decode(self) -> Option<D> {
        match self {
            Self::Decode(err) => Some(err),
            _ => None,
        }
    }
}
