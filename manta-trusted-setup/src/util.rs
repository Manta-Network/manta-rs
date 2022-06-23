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

//! Utilities

use ark_std::io;
use core::marker::PhantomData;

pub use ark_ff::{One, Zero};
pub use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write,
};
pub use manta_crypto::rand::Sample;

/// Distribution Type Extension
pub trait HasDistribution {
    /// Distribution Type
    type Distribution;
}

/// Custom Serialization Adapter
///
/// In the majority of cases we can just use [`CanonicalSerialize`] and [`CanonicalDeserialize`] to
/// make data types compatible with the `arkworks` serialization system. However, in some cases we
/// need to provide a "non-canonical" serialization for an existing type. This `trait` provides an
/// interface for building a serialization over the type `T`. For deserialization see the
/// [`Deserializer`] `trait`.
///
/// [`CanonicalSerialize`]: ark_serialize::CanonicalSerialize
/// [`CanonicalDeserialize`]: ark_serialize::CanonicalDeserialize
pub trait Serializer<T> {
    /// Serializes `item` in uncompressed form to the `writer` without performing any
    /// well-formedness checks.
    fn serialize_unchecked<W>(item: &T, writer: &mut W) -> Result<(), io::Error>
    where
        W: Write;

    /// Serializes `item` in uncompressed form to the `writer`, performing all well-formedness
    /// checks.
    fn serialize_uncompressed<W>(item: &T, writer: &mut W) -> Result<(), io::Error>
    where
        W: Write;

    /// Returns the size in bytes of the uncompressed form of `item`.
    fn uncompressed_size(item: &T) -> usize;

    /// Serializes `item` in compressed form to the `writer`, performing all well-formedness checks.
    fn serialize_compressed<W>(item: &T, writer: &mut W) -> Result<(), io::Error>
    where
        W: Write;

    /// Returns the size in bytes of the compressed form of `item`.
    fn compressed_size(item: &T) -> usize;
}

/// Custom Deserialization Adapter
///
/// In the majority of cases we can just use [`CanonicalSerialize`] and [`CanonicalDeserialize`] to
/// make data types compatible with the `arkworks` serialization system. However, in some cases we
/// need to provide a "non-canonical" deserialization for an existing type. This `trait` provides an
/// interface for building a deserialization over the type `T`. For serialization see the
/// [`Serializer`] `trait`.
///
/// [`CanonicalSerialize`]: ark_serialize::CanonicalSerialize
/// [`CanonicalDeserialize`]: ark_serialize::CanonicalDeserialize
pub trait Deserializer<T> {
    /// Deserialization Error Type
    type Error: Into<SerializationError>;

    /// Checks that `item` is a valid element of type `T`.
    ///
    /// # Implementation Note
    ///
    /// Implementing this method is optional and by default it does nothing since callers should
    /// always rely on the `deserialize_*` methods directly. However, the
    /// [`deserialize_uncompressed`] method calls this method, so if the difference between
    /// [`deserialize_unchecked`] and [`deserialize_uncompressed`] is just a simple check on the
    /// type `T`, then this function should be implemented. Otherwise, [`deserialize_uncompressed`]
    /// should be implemented manually.
    ///
    /// [`deserialize_uncompressed`]: Self::deserialize_uncompressed
    /// [`deserialize_unchecked`]: Self::deserialize_unchecked
    #[inline]
    fn check(item: &T) -> Result<(), Self::Error> {
        let _ = item;
        Ok(())
    }

    /// Deserializes a single uncompressed item of type `T` from the `reader` with the minimal
    /// amount of checks required to form the type.
    fn deserialize_unchecked<R>(reader: &mut R) -> Result<T, Self::Error>
    where
        R: Read;

    /// Deserializes a single uncompressed item of type `T` from the `reader` with all validity
    /// checks enabled.
    ///
    /// # Implementation Note
    ///
    /// Implementing this method is optional whenever there exists a non-default implementation of
    /// [`check`](Self::check). See its documentation for more.
    #[inline]
    fn deserialize_uncompressed<R>(reader: &mut R) -> Result<T, Self::Error>
    where
        R: Read,
    {
        let item = Self::deserialize_unchecked(reader)?;
        Self::check(&item)?;
        Ok(item)
    }

    /// Deserializes a single compressed item of type `T` from the `reader` with all validity checks
    /// enabled.
    fn deserialize_compressed<R>(reader: &mut R) -> Result<T, Self::Error>
    where
        R: Read;
}

/// Deserialization Error for [`NonZero`]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NonZeroError<E> {
    /// Element was Zero when Deserialized
    IsZero,

    /// Other Deserialization Error
    Error(E),
}

impl<E> From<NonZeroError<E>> for SerializationError
where
    E: Into<SerializationError>,
{
    #[inline]
    fn from(err: NonZeroError<E>) -> Self {
        match err {
            NonZeroError::IsZero => SerializationError::IoError(io::Error::new(
                io::ErrorKind::Other,
                "Value was expected to be non-zero but instead had value zero.",
            )),
            NonZeroError::Error(err) => err.into(),
        }
    }
}

/// Non-Zero Checking Deserializer
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NonZero<D>(PhantomData<D>);

impl<D> NonZero<D> {
    /// Checks if `item` is zero, returning [`NonZeroError::IsZero`] if so.
    #[inline]
    fn is_zero<T>(item: &T) -> Result<(), NonZeroError<D::Error>>
    where
        D: Deserializer<T>,
        T: Zero,
    {
        if item.is_zero() {
            return Err(NonZeroError::IsZero);
        }
        Ok(())
    }
}

impl<T, D> Deserializer<T> for NonZero<D>
where
    D: Deserializer<T>,
    T: Zero,
{
    type Error = NonZeroError<D::Error>;

    #[inline]
    fn check(item: &T) -> Result<(), Self::Error> {
        Self::is_zero(item)?;
        D::check(item).map_err(Self::Error::Error)
    }

    #[inline]
    fn deserialize_unchecked<R>(reader: &mut R) -> Result<T, Self::Error>
    where
        R: Read,
    {
        let item = D::deserialize_unchecked(reader).map_err(Self::Error::Error)?;
        Self::is_zero(&item)?;
        Ok(item)
    }

    #[inline]
    fn deserialize_uncompressed<R>(reader: &mut R) -> Result<T, Self::Error>
    where
        R: Read,
    {
        let item = D::deserialize_uncompressed(reader).map_err(Self::Error::Error)?;
        Self::is_zero(&item)?;
        Ok(item)
    }

    #[inline]
    fn deserialize_compressed<R>(reader: &mut R) -> Result<T, Self::Error>
    where
        R: Read,
    {
        let item = D::deserialize_compressed(reader).map_err(Self::Error::Error)?;
        Self::is_zero(&item)?;
        Ok(item)
    }
}
