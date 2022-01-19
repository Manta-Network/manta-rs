// Copyright 2019-2021 Manta Network.
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

//! Serialization and Deserialization Utilities

use alloc::vec::Vec;
use core::{convert::Infallible, fmt::Debug, hash::Hash};

/// Reader
pub trait Read {
    /// Error Type
    type Error;

    /// Reads bytes from `self`, pushing them to `output` until exhausting the buffer inside of
    /// `output`.
    fn read<T>(&mut self, output: &mut T) -> Result<(), Self::Error>
    where
        T: AsMut<[u8]> + ?Sized;

    /// Reads all bytes from `self`, pushing them to `output`.
    fn read_all(&mut self, output: &mut Vec<u8>) -> Result<(), Self::Error>;
}

impl<R> Read for &mut R
where
    R: Read,
{
    type Error = R::Error;

    #[inline]
    fn read<T>(&mut self, output: &mut T) -> Result<(), Self::Error>
    where
        T: AsMut<[u8]> + ?Sized,
    {
        (*self).read(output)
    }

    #[inline]
    fn read_all(&mut self, output: &mut Vec<u8>) -> Result<(), Self::Error> {
        (*self).read_all(output)
    }
}

impl Read for &[u8] {
    type Error = usize;

    #[inline]
    fn read<T>(&mut self, output: &mut T) -> Result<(), Self::Error>
    where
        T: AsMut<[u8]> + ?Sized,
    {
        let output = output.as_mut();
        let output_len = output.len();
        let len = self.len();
        if output_len > len {
            return Err(output_len - len);
        }
        output.copy_from_slice(&self[..output_len]);
        *self = &self[output_len..];
        Ok(())
    }

    #[inline]
    fn read_all(&mut self, output: &mut Vec<u8>) -> Result<(), Self::Error> {
        output
            .write(self)
            .map_err(|_| unreachable!("Infallible cannot be constructed."))
    }
}

impl<const N: usize> Read for [u8; N] {
    type Error = usize;

    #[inline]
    fn read<T>(&mut self, output: &mut T) -> Result<(), Self::Error>
    where
        T: AsMut<[u8]> + ?Sized,
    {
        let output = output.as_mut();
        let output_len = output.len();
        let len = self.len();
        if output_len > len {
            return Err(output_len - len);
        }
        output.copy_from_slice(&self[..output_len]);
        Ok(())
    }

    #[inline]
    fn read_all(&mut self, output: &mut Vec<u8>) -> Result<(), Self::Error> {
        output
            .write(&mut self.as_ref())
            .map_err(|_| unreachable!("Infallible cannot be constructed."))
    }
}

impl Read for Vec<u8> {
    type Error = usize;

    #[inline]
    fn read<T>(&mut self, output: &mut T) -> Result<(), Self::Error>
    where
        T: AsMut<[u8]> + ?Sized,
    {
        let mut slice = self.as_slice();
        slice.read(output)?;
        let len = slice.len();
        self.drain(..(self.len() - len));
        Ok(())
    }

    #[inline]
    fn read_all(&mut self, output: &mut Vec<u8>) -> Result<(), Self::Error> {
        output
            .write_drain(self)
            .map_err(|_| unreachable!("Infallible cannot be constructed."))
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
    fn read<T>(&mut self, output: &mut T) -> Result<(), Self::Error>
    where
        T: AsMut<[u8]> + ?Sized,
    {
        self.0.read_exact(output.as_mut())
    }

    #[inline]
    fn read_all(&mut self, output: &mut Vec<u8>) -> Result<(), Self::Error> {
        self.0.read_to_end(output).map(|_| ())
    }
}

/// Writer
pub trait Write {
    /// Error Type
    type Error;

    /// Writes bytes into `self`, pulling them from `input` until exhausting the buffer inside of
    /// `self`.
    fn write(&mut self, input: &mut &[u8]) -> Result<(), Self::Error>;

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
    #[inline]
    fn write_drain(&mut self, input: &mut Vec<u8>) -> Result<(), Self::Error> {
        let slice_len = self.write_ref(input)?.len();
        input.drain(..(input.len() - slice_len));
        Ok(())
    }
}

impl<W> Write for &mut W
where
    W: Write,
{
    type Error = W::Error;

    #[inline]
    fn write(&mut self, input: &mut &[u8]) -> Result<(), Self::Error> {
        (*self).write(input)
    }

    #[inline]
    fn write_ref<'t, T>(&mut self, input: &'t T) -> Result<&'t [u8], Self::Error>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        (*self).write_ref(input)
    }

    #[inline]
    fn write_drain(&mut self, input: &mut Vec<u8>) -> Result<(), Self::Error> {
        (*self).write_drain(input)
    }
}

impl Write for [u8] {
    type Error = usize;

    #[inline]
    fn write(&mut self, input: &mut &[u8]) -> Result<(), Self::Error> {
        input.read(self)
    }
}

impl<const N: usize> Write for [u8; N] {
    type Error = usize;

    #[inline]
    fn write(&mut self, input: &mut &[u8]) -> Result<(), Self::Error> {
        input.read(self)
    }
}

impl Write for Vec<u8> {
    type Error = Infallible;

    #[inline]
    fn write(&mut self, input: &mut &[u8]) -> Result<(), Self::Error> {
        self.reserve(input.len());
        self.extend_from_slice(*input);
        Ok(())
    }

    #[inline]
    fn write_drain(&mut self, input: &mut Vec<u8>) -> Result<(), Self::Error> {
        self.append(input);
        Ok(())
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
    fn write(&mut self, input: &mut &[u8]) -> Result<(), Self::Error> {
        self.0.write_all(input)?;
        *input = &input[..0];
        Ok(())
    }
}

/// Serialization
pub trait Serialize<C = ()> {
    /// Appends representation of `self` in bytes to `buffer`.
    fn serialize<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: Write;

    /// Converts `self` into a vector of bytes.
    #[inline]
    fn to_vec(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        self.serialize(&mut buffer)
            .expect("Writing to a `Vec<u8>` cannot fail.");
        buffer
    }
}

impl Serialize for u8 {
    #[inline]
    fn serialize<W>(&self, mut writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        writer.write_ref(&[*self])?;
        Ok(())
    }
}

impl<T, C> Serialize<C> for [T]
where
    T: Serialize<C>,
{
    #[inline]
    fn serialize<W>(&self, mut writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        for item in self {
            item.serialize(&mut writer)?;
        }
        Ok(())
    }
}

impl<T, C, const N: usize> Serialize<C> for [T; N]
where
    T: Serialize<C>,
{
    #[inline]
    fn serialize<W>(&self, mut writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        for item in self {
            item.serialize(&mut writer)?;
        }
        Ok(())
    }
}

/// Exact Size Serialization
pub trait SerializeExactSize<C, const N: usize>: Serialize<C> {
    /// Converts `self` into an exactly known byte array.
    #[inline]
    fn to_array(&self) -> [u8; N] {
        let mut buffer = [0; N];
        self.serialize(&mut buffer)
            .expect("The implementation of this trait means that this cannot fail.");
        buffer
    }
}

/// Deserialization Error
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "R::Error: Clone, D::Error: Clone"),
    Copy(bound = "R::Error: Copy, D::Error: Copy"),
    Debug(bound = "R::Error: Debug, D::Error: Debug"),
    Eq(bound = "R::Error: Eq, D::Error: Eq"),
    Hash(bound = "R::Error: Hash, D::Error: Hash"),
    PartialEq(bound = "R::Error: PartialEq, D::Error: PartialEq")
)]
pub enum Error<R, D, C = ()>
where
    R: Read + ?Sized,
    D: Deserialize<C> + ?Sized,
{
    /// Reading Error
    ///
    /// See [`Read`] for more.
    Read(R::Error),

    /// Deserialization Error
    ///
    /// See [`Deserialize`] for more.
    Deserialize(D::Error),
}

impl<R, D, C> Error<R, D, C>
where
    R: Read + ?Sized,
    D: Deserialize<C> + ?Sized,
{
    /// Converts `self` into an option over [`R::Error`](Read::Error).
    #[inline]
    pub fn read(self) -> Option<R::Error> {
        match self {
            Self::Read(err) => Some(err),
            _ => None,
        }
    }

    /// Converts `self` into an option over [`D::Error`](Deserialize::Error).
    #[inline]
    pub fn deserialize(self) -> Option<D::Error> {
        match self {
            Self::Deserialize(err) => Some(err),
            _ => None,
        }
    }
}

/// Deserialization
pub trait Deserialize<C = ()>: Sized {
    /// Error Type
    type Error;

    /// Parses the input `buffer` into a concrete value of type `Self` if possible.
    fn deserialize<R>(reader: R) -> Result<Self, Error<R, Self, C>>
    where
        R: Read;

    /// Converts a byte vector into a concrete value of type `Self` if possible.
    #[inline]
    fn from_vec(buffer: Vec<u8>) -> Result<Self, Self::Error> {
        Self::deserialize(buffer)
            .map_err(move |err| err.deserialize().expect("Reading from `[u8]` cannot fail."))
    }
}

/// Exact Size Deserialization
pub trait DeserializeExactSize<C, const N: usize>: Deserialize<C> {
    /// Converts a fixed-length byte array into a concrete value of type `Self`.
    #[inline]
    fn from_array(buffer: [u8; N]) -> Self {
        Self::deserialize(buffer)
            .ok()
            .expect("The implementation of this trait means that this cannot fail.")
    }
}
