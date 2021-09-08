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

//! Parity SCALE + Arkworks Codec System

// FIXME: figure out how to "re-export" the `parity_scale_codec` crate so we don't have to explicitly
// depend on it downstream

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(doc_cfg, feature(doc_cfg))]
#![forbid(rustdoc::broken_intra_doc_links)]
#![forbid(missing_docs)]

use displaydoc::Display;
use manta_util::from_variant_impl;

pub use ark_serialize::{Read, SerializationError as ArkCodecError, Write};
pub use scale_codec::{
    Decode as ScaleDecode, Encode as ScaleEncode, Error as ScaleCodecError, Input, Output,
};

/// Codec Error Type
#[derive(Debug, Display)]
pub enum Error {
    /// Arkworks Codec Error
    #[displaydoc("Arkworks Codec Error: {0}")]
    ArkCodecError(ArkCodecError),

    /// SCALE Codec Error
    #[displaydoc("SCALE Codec Error: {0}")]
    ScaleCodecError(ScaleCodecError),
}

from_variant_impl!(Error, ArkCodecError, ArkCodecError);
from_variant_impl!(Error, ScaleCodecError, ScaleCodecError);

impl From<ark_std::io::Error> for Error {
    #[inline]
    fn from(err: ark_std::io::Error) -> Self {
        Self::ArkCodecError(ArkCodecError::IoError(err))
    }
}

impl ark_std::error::Error for Error {}

/// Decoding Result Alias
pub type DecodeResult<T> = Result<T, Error>;

/// Encoding Result Alias
pub type EncodeResult = Result<(), Error>;

/// Default Decode Implementation Marker Trait
pub trait DefaultDecode: ScaleDecode {}

/// Decoding Trait
pub trait Decode: Sized {
    /// Decodes `Self` from the reader.
    fn decode<R>(reader: &mut R) -> DecodeResult<Self>
    where
        R: Input + Read;
}

impl<D> Decode for D
where
    D: DefaultDecode,
{
    #[inline]
    fn decode<R>(reader: &mut R) -> DecodeResult<Self>
    where
        R: Input + Read,
    {
        scale_decode(reader)
    }
}

/// Default Encode Implementation Marker Trait
pub trait DefaultEncode: ScaleEncode {}

/// Encoding Trait
pub trait Encode {
    /// Encodes `self` to the writer.
    fn encode<W>(&self, writer: &mut W) -> EncodeResult
    where
        W: Output + Write;
}

impl<E> Encode for E
where
    E: DefaultEncode,
{
    #[inline]
    fn encode<W>(&self, writer: &mut W) -> EncodeResult
    where
        W: Output + Write,
    {
        scale_encode(self, writer)
    }
}

/// Codec Trait
pub trait Codec: Decode + Encode {}

impl<S> Codec for S where S: Decode + Encode {}

/// Decodes a value of type `T` from `reader` using the SCALE codec.
#[inline]
pub fn scale_decode<T, R>(reader: &mut R) -> DecodeResult<T>
where
    T: ScaleDecode,
    R: Input,
{
    Ok(T::decode(reader)?)
}

/// Encodes a value `t` to `writer` using the SCALE codec.
#[inline]
pub fn scale_encode<T, W>(t: &T, writer: &mut W) -> EncodeResult
where
    T: ScaleEncode,
    W: Write,
{
    Ok(writer.write_all(t.encode().as_ref())?)
}
