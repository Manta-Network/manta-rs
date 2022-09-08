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

//! Serde-Compatible Encrypted Filesystem
//!
//! To facilitate the encryption and file I/O of structured data, we define the [`Serializer`] and
//! [`Deserializer`] which use a [`File`] to encrypt and decrypt [`Block`] data during reading and
//! writing from the file system. The encoding scheme is a binary-only concatenative format which
//! stores no type or name metadata for the smallest data sizes: it is not a self-describing nor
//! human-readable format. See the [`test`](mod@test) module for testing of encrypting serialization
//! and decrypting deserialization.

use crate::fs::{Block, File};
use alloc::{format, string::String, vec::Vec};
use core::{
    fmt::{self, Debug, Display},
    write,
};
use derive_more::Display;
use manta_util::{
    into_array_unchecked, num,
    serde::{
        self,
        de::{
            DeserializeSeed, Deserializer as _, EnumAccess, IntoDeserializer, MapAccess, SeqAccess,
            VariantAccess, Visitor,
        },
        ser::{
            SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple,
            SerializeTupleStruct, SerializeTupleVariant,
        },
    },
    FromBytes, IntoBytes,
};

#[doc(inline)]
pub use manta_util::serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Serialization Module
pub mod ser {
    use super::*;

    /// Unsupported Feature
    #[derive(Clone, Copy, Debug, Display, Eq, Hash, PartialEq)]
    pub enum UnsupportedFeature {
        /// Unknown Length Iterators
        UnknownLengthIterators,
    }

    /// Serialization Error
    #[derive(derivative::Derivative)]
    #[derivative(Debug(bound = "F::Error: Debug"))]
    pub enum Error<F>
    where
        F: File,
    {
        /// Unsupported Features
        UnsupportedFeature(UnsupportedFeature),

        /// Serialization Error
        Serialization(String),

        /// Encrypted File I/O Error
        Io(F::Error),
    }

    impl<F> Display for Error<F>
    where
        F: File,
        F::Error: Display,
    {
        #[inline]
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                Self::UnsupportedFeature(feature) => write!(f, "Unsupported Feature: {}", feature),
                Self::Serialization(msg) => write!(f, "Serialization Error: {}", msg),
                Self::Io(err) => write!(f, "File I/O Error: {}", err),
            }
        }
    }

    impl<F> serde::ser::StdError for Error<F>
    where
        F: File,
        F::Error: Debug + Display,
    {
    }

    impl<F> serde::ser::Error for Error<F>
    where
        F: File,
        F::Error: Debug + Display,
    {
        #[inline]
        fn custom<T>(msg: T) -> Self
        where
            T: Display,
        {
            Self::Serialization(format!("{}", msg))
        }
    }
}

/// Encrypting Serializer
pub struct Serializer<'f, F>
where
    F: File,
{
    /// Encrypted File
    file: &'f mut F,

    /// Current Block Data
    block_data: Vec<u8>,

    /// Recursion Depth
    recursion_depth: usize,
}

impl<'f, F> Serializer<'f, F>
where
    F: File,
{
    /// Builds a new [`Serializer`] for `file`.
    #[inline]
    pub fn new(file: &'f mut F) -> Self {
        Self {
            file,
            block_data: Vec::with_capacity(Block::SIZE),
            recursion_depth: 0,
        }
    }

    /// Extends the block data by appending `bytes`.
    #[inline]
    fn extend(&mut self, bytes: &[u8]) {
        self.block_data.extend_from_slice(bytes);
    }

    /// Extends the block data by appending the bytes extracted from `t`.
    #[inline]
    fn extend_bytes<T, const N: usize>(&mut self, value: T)
    where
        T: IntoBytes<N>,
    {
        self.extend(&value.into_bytes());
    }

    /// Flushes the currently full blocks to the encrypted file system.
    #[inline]
    fn flush_intermediate(&mut self) -> Result<(), F::Error> {
        // TODO: Design a block iterator for `self.block_data` to make this more efficient.
        while let Some(block) = Block::parse_full(&mut self.block_data) {
            self.file.write(block)?;
        }
        Ok(())
    }

    /// Flushes all the remaining blocks to the encrypted file system.
    #[inline]
    fn flush_end(&mut self) -> Result<(), F::Error> {
        while !self.block_data.is_empty() {
            self.file.write(Block::parse(&mut self.block_data))?;
        }
        Ok(())
    }

    /// Flushes bytes to the encrypted file system using either full blocks or the last,
    /// partially-full block, depending on the recursion depth.
    #[inline]
    fn flush(&mut self) -> Result<(), ser::Error<F>> {
        if self.recursion_depth == 0 {
            self.flush_end()
        } else {
            self.flush_intermediate()
        }
        .map_err(ser::Error::Io)
    }

    /// Writes the bytes of `t` after conversion into `self` and then flushes them to the encrypted
    /// file system.
    #[inline]
    fn write_bytes<T, const N: usize>(&mut self, value: T) -> Result<(), ser::Error<F>>
    where
        T: IntoBytes<N>,
    {
        self.extend_bytes(value);
        self.flush()
    }

    /// Starts a new sequence, increasing the recursion depth.
    #[inline]
    fn start_sequence(&mut self, len: Option<usize>) -> Result<&mut Self, ser::Error<F>> {
        if let Some(len) = len {
            self.recursion_depth += 1;
            self.extend_bytes(len as u64);
            Ok(self)
        } else {
            Err(ser::Error::UnsupportedFeature(
                ser::UnsupportedFeature::UnknownLengthIterators,
            ))
        }
    }

    /// Starts a new `struct` or `tuple`, increasing the recursion depth.
    #[inline]
    fn start_struct(&mut self) -> Result<&mut Self, ser::Error<F>> {
        self.recursion_depth += 1;
        Ok(self)
    }

    /// Starts a new `struct` or `tuple` relative to the `variant_index`, increasing the recursion
    /// depth.
    #[inline]
    fn start_struct_with_variant(
        &mut self,
        variant_index: u32,
        len: usize,
    ) -> Result<&mut Self, ser::Error<F>> {
        self.recursion_depth += 1;

        // TODO: Consider compression of the variant tag. Something like the following:
        //
        // ```rust
        // let leading_zeros = ((len - 1) as u32).leading_zeros();
        // self.extend(&variant_index.into_bytes()[leading_zeros as usize..]);
        // ```
        //
        let _ = len;
        self.extend_bytes(variant_index);
        Ok(self)
    }

    /// Ends the compound structure, decreasing the recursion depth and flushing to the encrypted
    /// file system.
    #[inline]
    fn end_compound(&mut self) -> Result<(), ser::Error<F>> {
        self.recursion_depth -= 1;
        self.flush()
    }
}

impl<'f, F> serde::Serializer for &mut Serializer<'f, F>
where
    F: File,
    F::Error: Debug + Display,
{
    type Ok = ();
    type Error = ser::Error<F>;
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    #[inline]
    fn serialize_bool(self, v: bool) -> Result<Self::Ok, Self::Error> {
        self.write_bytes(v as u8)
    }

    #[inline]
    fn serialize_i8(self, v: i8) -> Result<Self::Ok, Self::Error> {
        self.write_bytes(v)
    }

    #[inline]
    fn serialize_i16(self, v: i16) -> Result<Self::Ok, Self::Error> {
        self.write_bytes(v)
    }

    #[inline]
    fn serialize_i32(self, v: i32) -> Result<Self::Ok, Self::Error> {
        self.write_bytes(v)
    }

    #[inline]
    fn serialize_i64(self, v: i64) -> Result<Self::Ok, Self::Error> {
        self.write_bytes(v)
    }

    #[inline]
    fn serialize_i128(self, v: i128) -> Result<Self::Ok, Self::Error> {
        self.write_bytes(v)
    }

    #[inline]
    fn serialize_u8(self, v: u8) -> Result<Self::Ok, Self::Error> {
        self.write_bytes(v)
    }

    #[inline]
    fn serialize_u16(self, v: u16) -> Result<Self::Ok, Self::Error> {
        self.write_bytes(v)
    }

    #[inline]
    fn serialize_u32(self, v: u32) -> Result<Self::Ok, Self::Error> {
        self.write_bytes(v)
    }

    #[inline]
    fn serialize_u64(self, v: u64) -> Result<Self::Ok, Self::Error> {
        self.write_bytes(v)
    }

    #[inline]
    fn serialize_u128(self, v: u128) -> Result<Self::Ok, Self::Error> {
        self.write_bytes(v)
    }

    #[inline]
    fn serialize_f32(self, v: f32) -> Result<Self::Ok, Self::Error> {
        self.write_bytes(v)
    }

    #[inline]
    fn serialize_f64(self, v: f64) -> Result<Self::Ok, Self::Error> {
        self.write_bytes(v)
    }

    #[inline]
    fn serialize_char(self, v: char) -> Result<Self::Ok, Self::Error> {
        self.write_bytes(v)
    }

    #[inline]
    fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
        v.as_bytes().serialize(self)
    }

    #[inline]
    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
        self.extend_bytes(v.len() as u64);
        self.extend(v);
        self.flush()
    }

    #[inline]
    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        self.write_bytes(0u8)
    }

    #[inline]
    fn serialize_some<T>(self, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize + ?Sized,
    {
        self.extend_bytes(1u8);
        value.serialize(self)
    }

    #[inline]
    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    #[inline]
    fn serialize_unit_struct(self, name: &'static str) -> Result<Self::Ok, Self::Error> {
        let _ = name;
        Ok(())
    }

    #[inline]
    fn serialize_unit_variant(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        let _ = (name, variant);
        variant_index.serialize(self)
    }

    #[inline]
    fn serialize_newtype_struct<T>(
        self,
        name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize + ?Sized,
    {
        let _ = name;
        value.serialize(self)
    }

    #[inline]
    fn serialize_newtype_variant<T>(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize + ?Sized,
    {
        let _ = (name, variant);
        self.extend(&variant_index.to_le_bytes());
        value.serialize(self)
    }

    #[inline]
    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        self.start_sequence(len)
    }

    #[inline]
    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        let _ = len;
        self.start_struct()
    }

    #[inline]
    fn serialize_tuple_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        let _ = (name, len);
        self.start_struct()
    }

    #[inline]
    fn serialize_tuple_variant(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        let _ = (name, variant);
        self.start_struct_with_variant(variant_index, len)
    }

    #[inline]
    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        self.start_sequence(len)
    }

    #[inline]
    fn serialize_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        let _ = (name, len);
        self.start_struct()
    }

    #[inline]
    fn serialize_struct_variant(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        let _ = (name, variant);
        self.start_struct_with_variant(variant_index, len)
    }

    #[inline]
    fn is_human_readable(&self) -> bool {
        false
    }
}

impl<'f, F> SerializeSeq for &mut Serializer<'f, F>
where
    F: File,
    F::Error: Debug + Display,
{
    type Ok = ();
    type Error = ser::Error<F>;

    #[inline]
    fn serialize_element<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        value.serialize(&mut **self)
    }

    #[inline]
    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.end_compound()
    }
}

impl<'f, F> SerializeTuple for &mut Serializer<'f, F>
where
    F: File,
    F::Error: Debug + Display,
{
    type Ok = ();
    type Error = ser::Error<F>;

    #[inline]
    fn serialize_element<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        value.serialize(&mut **self)
    }

    #[inline]
    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.end_compound()
    }
}

impl<'f, F> SerializeTupleStruct for &mut Serializer<'f, F>
where
    F: File,
    F::Error: Debug + Display,
{
    type Ok = ();
    type Error = ser::Error<F>;

    #[inline]
    fn serialize_field<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        value.serialize(&mut **self)
    }

    #[inline]
    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.end_compound()
    }
}

impl<'f, F> SerializeTupleVariant for &mut Serializer<'f, F>
where
    F: File,
    F::Error: Debug + Display,
{
    type Ok = ();
    type Error = ser::Error<F>;

    #[inline]
    fn serialize_field<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        value.serialize(&mut **self)
    }

    #[inline]
    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.end_compound()
    }
}

impl<'f, F> SerializeMap for &mut Serializer<'f, F>
where
    F: File,
    F::Error: Debug + Display,
{
    type Ok = ();
    type Error = ser::Error<F>;

    #[inline]
    fn serialize_key<T>(&mut self, key: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        key.serialize(&mut **self)
    }

    #[inline]
    fn serialize_value<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        value.serialize(&mut **self)
    }

    #[inline]
    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.end_compound()
    }
}

impl<'f, F> SerializeStruct for &mut Serializer<'f, F>
where
    F: File,
    F::Error: Debug + Display,
{
    type Ok = ();
    type Error = ser::Error<F>;

    #[inline]
    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        let _ = key;
        value.serialize(&mut **self)
    }

    #[inline]
    fn skip_field(&mut self, key: &'static str) -> Result<(), Self::Error> {
        let _ = key;
        Ok(())
    }

    #[inline]
    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.end_compound()
    }
}

impl<'f, F> SerializeStructVariant for &mut Serializer<'f, F>
where
    F: File,
    F::Error: Debug + Display,
{
    type Ok = ();
    type Error = ser::Error<F>;

    #[inline]
    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        let _ = key;
        value.serialize(&mut **self)
    }

    #[inline]
    fn skip_field(&mut self, key: &'static str) -> Result<(), Self::Error> {
        let _ = key;
        Ok(())
    }

    #[inline]
    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.end_compound()
    }
}

/// Deserialization Module
pub mod de {
    use super::*;
    use alloc::string::FromUtf8Error;

    /// Unsupported Feature
    #[derive(Clone, Copy, Debug, Display, Eq, Hash, PartialEq)]
    pub enum UnsupportedFeature {
        /// Deserialize Any
        Any,

        /// Deserialize Identifier
        Identifier,

        /// Deserialize Ignored Any
        IgnoredAny,
    }

    /// Deserialization Error
    #[derive(derivative::Derivative)]
    #[derivative(Debug(bound = "F::Error: Debug"))]
    pub enum Error<F>
    where
        F: File,
    {
        /// Encrypted File I/O Error
        Io(F::Error),

        /// Missing Bytes
        MissingBytes,

        /// Unsupported Feature
        UnsupportedFeature(UnsupportedFeature),

        /// Invalid Boolean Tag
        InvalidBoolTag(u8),

        /// Invalid Option Tag
        InvalidOptionTag(u8),

        /// Invalid UTF-8 Character
        InvalidCharacter(u32),

        /// Large Length Tag
        LargeLengthTag(u64),

        /// From UTF-8 Error
        FromUtf8Error(FromUtf8Error),

        /// Deserialization Error
        Deserialization(String),
    }

    impl<F> Display for Error<F>
    where
        F: File,
        F::Error: Display,
    {
        #[inline]
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                Self::Io(err) => write!(f, "File I/O Error: {}", err),
                Self::MissingBytes => write!(f, "Missing Bytes"),
                Self::UnsupportedFeature(feature) => write!(f, "Unsupported Feature: {}", feature),
                Self::InvalidBoolTag(tag) => write!(f, "Invalid Bool Tag: {}", tag),
                Self::InvalidOptionTag(tag) => write!(f, "Invalid Option Tag: {}", tag),
                Self::InvalidCharacter(integer) => write!(f, "Invalid Character: {}", integer),
                Self::LargeLengthTag(len) => write!(f, "Large Length Tag: {}", len),
                Self::FromUtf8Error(err) => write!(f, "From UTF-8 Error: {}", err),
                Self::Deserialization(msg) => write!(f, "Deserialization Error: {}", msg),
            }
        }
    }

    impl<F> serde::de::StdError for Error<F>
    where
        F: File,
        F::Error: Debug + Display,
    {
    }

    impl<F> serde::de::Error for Error<F>
    where
        F: File,
        F::Error: Debug + Display,
    {
        #[inline]
        fn custom<T>(msg: T) -> Self
        where
            T: Display,
        {
            Self::Deserialization(format!("{}", msg))
        }
    }

    /// Length Access
    pub struct LengthAccess<'d, 'f, F>
    where
        F: File,
    {
        /// Known Length
        pub(super) len: usize,

        /// Deserializer
        pub(super) deserializer: &'d mut Deserializer<'f, F>,
    }
}

/// Decrypting Deserializer
pub struct Deserializer<'f, F>
where
    F: File,
{
    /// Encrypted File
    file: &'f mut F,

    /// Accumulated Block Data
    block_data: Vec<u8>,
}

impl<'f, F> Deserializer<'f, F>
where
    F: File,
{
    /// Builds a new [`Deserializer`] for `file`.
    #[inline]
    pub fn new(file: &'f mut F) -> Self {
        Self {
            file,
            block_data: Vec::with_capacity(Block::SIZE),
        }
    }

    /// Loads a block from the encrypted file system and appends it to the block data, returning
    /// `true` if the block was loaded and `false` otherwise.
    #[inline]
    fn load(&mut self) -> Result<bool, F::Error> {
        match self.file.read()? {
            Some(block) => {
                self.block_data.append(&mut block.into());
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Loads at least `n` bytes from the encrypted file system. If there are enough bytes in the
    /// block data then, it does not perform any reads, and if there are not enough, it continually
    /// reads until it meets the requirement `n`, returning `true` if the requirement was met.
    #[inline]
    fn load_bytes(&mut self, n: usize) -> Result<bool, F::Error> {
        while self.block_data.len() < n {
            if !self.load()? {
                return Ok(self.block_data.len() >= n);
            }
        }
        Ok(true)
    }

    /// Reads `len` bytes from the encrypted file system and loads them into an owned vector.
    #[inline]
    fn read_exact(&mut self, len: usize) -> Result<Vec<u8>, de::Error<F>> {
        if self.load_bytes(len).map_err(de::Error::Io)? {
            Ok(self.block_data.drain(..len).collect::<Vec<_>>())
        } else {
            Err(de::Error::MissingBytes)
        }
    }

    /// Reads an array of bytes of size `N` from the encrypted file system.
    #[inline]
    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], de::Error<F>> {
        Ok(into_array_unchecked(self.read_exact(N)?))
    }

    /// Reads one element of the type `T` from the encrypted file system.
    #[inline]
    fn read_bytes<T, const N: usize>(&mut self) -> Result<T, de::Error<F>>
    where
        T: FromBytes<N>,
    {
        Ok(T::from_bytes(self.read_array()?))
    }

    /// Reads a length tag from `self`, trying to fit it into a `usize`.
    #[inline]
    fn read_len(&mut self) -> Result<usize, de::Error<F>> {
        num::u64_as_usize(self.read_bytes()?).map_err(de::Error::LargeLengthTag)
    }

    /// Reads a byte vector from `self`.
    #[inline]
    fn read_byte_buf(&mut self) -> Result<Vec<u8>, de::Error<F>> {
        let len = self.read_len()?;
        self.read_exact(len)
    }

    /// Reads a string from `self`.
    #[inline]
    fn read_string(&mut self) -> Result<String, de::Error<F>> {
        String::from_utf8(self.read_byte_buf()?).map_err(de::Error::FromUtf8Error)
    }
}

impl<'de, 'f, F> serde::Deserializer<'de> for &mut Deserializer<'f, F>
where
    F: File,
    F::Error: Debug + Display,
{
    type Error = de::Error<F>;

    #[inline]
    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let _ = visitor;
        Err(Self::Error::UnsupportedFeature(de::UnsupportedFeature::Any))
    }

    #[inline]
    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.read_bytes()? {
            0u8 => visitor.visit_bool(false),
            1u8 => visitor.visit_bool(true),
            tag => Err(Self::Error::InvalidBoolTag(tag)),
        }
    }

    #[inline]
    fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_i8(self.read_bytes()?)
    }

    #[inline]
    fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_i16(self.read_bytes()?)
    }

    #[inline]
    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_i32(self.read_bytes()?)
    }

    #[inline]
    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_i64(self.read_bytes()?)
    }

    #[inline]
    fn deserialize_i128<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_i128(self.read_bytes()?)
    }

    #[inline]
    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u8(self.read_bytes()?)
    }

    #[inline]
    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u16(self.read_bytes()?)
    }

    #[inline]
    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u32(self.read_bytes()?)
    }

    #[inline]
    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u64(self.read_bytes()?)
    }

    #[inline]
    fn deserialize_u128<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u128(self.read_bytes()?)
    }

    #[inline]
    fn deserialize_f32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_f32(self.read_bytes()?)
    }

    #[inline]
    fn deserialize_f64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_f64(self.read_bytes()?)
    }

    #[inline]
    fn deserialize_char<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let integer = self.read_bytes()?;
        match char::from_u32(integer) {
            Some(c) => visitor.visit_char(c),
            _ => Err(Self::Error::InvalidCharacter(integer)),
        }
    }

    #[inline]
    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_str(&self.read_string()?)
    }

    #[inline]
    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_string(self.read_string()?)
    }

    #[inline]
    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_bytes(&self.read_byte_buf()?)
    }

    #[inline]
    fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_byte_buf(self.read_byte_buf()?)
    }

    #[inline]
    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.read_bytes()? {
            0u8 => visitor.visit_none(),
            1u8 => visitor.visit_some(&mut *self),
            tag => Err(Self::Error::InvalidOptionTag(tag)),
        }
    }

    #[inline]
    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_unit()
    }

    #[inline]
    fn deserialize_unit_struct<V>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let _ = name;
        visitor.visit_unit()
    }

    #[inline]
    fn deserialize_newtype_struct<V>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let _ = name;
        visitor.visit_newtype_struct(self)
    }

    #[inline]
    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let len = self.read_len()?;
        self.deserialize_tuple(len, visitor)
    }

    #[inline]
    fn deserialize_tuple<V>(self, len: usize, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_seq(de::LengthAccess {
            len,
            deserializer: self,
        })
    }

    #[inline]
    fn deserialize_tuple_struct<V>(
        self,
        name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let _ = name;
        self.deserialize_tuple(len, visitor)
    }

    #[inline]
    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_map(de::LengthAccess {
            len: self.read_len()?,
            deserializer: self,
        })
    }

    #[inline]
    fn deserialize_struct<V>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let _ = name;
        self.deserialize_tuple(fields.len(), visitor)
    }

    #[inline]
    fn deserialize_enum<V>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let _ = (name, variants);
        visitor.visit_enum(self)
    }

    #[inline]
    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let _ = visitor;
        Err(Self::Error::UnsupportedFeature(
            de::UnsupportedFeature::Identifier,
        ))
    }

    #[inline]
    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let _ = visitor;
        Err(Self::Error::UnsupportedFeature(
            de::UnsupportedFeature::IgnoredAny,
        ))
    }

    #[inline]
    fn is_human_readable(&self) -> bool {
        false
    }
}

impl<'d, 'de, 'f, F> SeqAccess<'de> for de::LengthAccess<'d, 'f, F>
where
    F: File,
    F::Error: Debug + Display,
{
    type Error = de::Error<F>;

    #[inline]
    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
    where
        T: DeserializeSeed<'de>,
    {
        if self.len > 0 {
            self.len -= 1;
            Ok(Some(seed.deserialize(&mut *self.deserializer)?))
        } else {
            Ok(None)
        }
    }

    #[inline]
    fn size_hint(&self) -> Option<usize> {
        Some(self.len)
    }
}

impl<'d, 'de, 'f, F> MapAccess<'de> for de::LengthAccess<'d, 'f, F>
where
    F: File,
    F::Error: Debug + Display,
{
    type Error = de::Error<F>;

    #[inline]
    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, Self::Error>
    where
        K: DeserializeSeed<'de>,
    {
        self.next_element_seed(seed)
    }

    #[inline]
    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, Self::Error>
    where
        V: DeserializeSeed<'de>,
    {
        seed.deserialize(&mut *self.deserializer)
    }

    #[inline]
    fn size_hint(&self) -> Option<usize> {
        Some(self.len)
    }
}

impl<'de, 'f, F> EnumAccess<'de> for &mut Deserializer<'f, F>
where
    F: File,
    F::Error: Debug + Display,
{
    type Error = de::Error<F>;
    type Variant = Self;

    #[inline]
    fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant), Self::Error>
    where
        V: DeserializeSeed<'de>,
    {
        let variant_index: u32 = self.read_bytes()?;
        Ok((seed.deserialize(variant_index.into_deserializer())?, self))
    }
}

impl<'de, 'f, F> VariantAccess<'de> for &mut Deserializer<'f, F>
where
    F: File,
    F::Error: Debug + Display,
{
    type Error = de::Error<F>;

    #[inline]
    fn unit_variant(self) -> Result<(), Self::Error> {
        Ok(())
    }

    #[inline]
    fn newtype_variant_seed<T>(self, seed: T) -> Result<T::Value, Self::Error>
    where
        T: DeserializeSeed<'de>,
    {
        seed.deserialize(self)
    }

    #[inline]
    fn tuple_variant<V>(self, len: usize, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_tuple(len, visitor)
    }

    #[inline]
    fn struct_variant<V>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_tuple(fields.len(), visitor)
    }
}

/// Testing Framework
pub mod test {
    use super::*;
    use manta_util::serde::de::DeserializeOwned;

    /// Asserts that the encryption and decryption of `data` at a new file `path` with `password`
    /// succeed without error, and that the decrypted value matches the initial data.
    #[inline]
    pub fn assert_decryption<F, P, T>(path: P, password: &[u8], data: T)
    where
        F: File,
        F::Error: Debug + Display,
        P: AsRef<F::Path>,
        T: Debug + DeserializeOwned + PartialEq + Serialize,
    {
        let path = path.as_ref();
        data.serialize(&mut Serializer::new(
            &mut F::options()
                .create_new(true)
                .write(true)
                .open(path, password)
                .expect("Unable to create file for writing."),
        ))
        .expect("Unable to serialize and encrypt the data.");
        let decrypted_data = T::deserialize(&mut Deserializer::new(
            &mut F::options()
                .read(true)
                .open(path, password)
                .expect("Unable to open file for reading."),
        ))
        .expect("Unable to decrypt and deserialize the data.");
        assert_eq!(data, decrypted_data, "Data and decrypted data don't match.");
    }
}
