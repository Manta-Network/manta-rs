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

use crate::fs::{Block, File};
use alloc::{format, string::String, vec::Vec};
use core::{
    fmt::{self, Debug, Display},
    write,
};
use manta_util::{
    into_array_unchecked,
    serde::{
        self,
        de::{Error, Visitor},
        ser::{
            SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple,
            SerializeTupleStruct, SerializeTupleVariant,
        },
        Serialize,
    },
};

/// Serialization Module
pub mod ser {
    use super::*;

    /// Serialization Error
    #[derive(derivative::Derivative)]
    #[derivative(Debug(bound = "F::Error: Debug"))]
    pub enum Error<F>
    where
        F: File,
    {
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
                Self::Serialization(msg) => write!(f, "Serialization Error: {}", msg),
                Self::Io(err) => write!(f, "File I/O Error: {}", err),
            }
        }
    }

    #[cfg(feature = "std")]
    impl<F> std::error::Error for Error<F>
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

    /// Pushes a single byte to the block data.
    #[inline]
    fn push(&mut self, byte: u8) {
        self.block_data.push(byte);
    }

    /// Extends the block data by appending `bytes`.
    #[inline]
    fn extend(&mut self, bytes: &[u8]) {
        self.block_data.extend_from_slice(bytes);
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

    /// Starts a new sequence, increasing the recursion depth.
    #[inline]
    fn start_sequence(&mut self, len: Option<usize>) -> Result<&mut Self, ser::Error<F>> {
        self.recursion_depth += 1;
        if let Some(len) = len {
            self.extend(&(len as u64).to_le_bytes());
        }
        Ok(self)
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
        // self.extend(&variant_index.to_le_bytes()[leading_zeros as usize..]);
        // ```
        //
        let _ = len;
        self.extend(&variant_index.to_le_bytes());
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

impl<'s, 'f, F> serde::Serializer for &'s mut Serializer<'f, F>
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
        self.push(v as u8);
        self.flush()
    }

    #[inline]
    fn serialize_i8(self, v: i8) -> Result<Self::Ok, Self::Error> {
        self.extend(&v.to_le_bytes());
        self.flush()
    }

    #[inline]
    fn serialize_i16(self, v: i16) -> Result<Self::Ok, Self::Error> {
        self.extend(&v.to_le_bytes());
        self.flush()
    }

    #[inline]
    fn serialize_i32(self, v: i32) -> Result<Self::Ok, Self::Error> {
        self.extend(&v.to_le_bytes());
        self.flush()
    }

    #[inline]
    fn serialize_i64(self, v: i64) -> Result<Self::Ok, Self::Error> {
        self.extend(&v.to_le_bytes());
        self.flush()
    }

    #[inline]
    fn serialize_i128(self, v: i128) -> Result<Self::Ok, Self::Error> {
        self.extend(&v.to_le_bytes());
        self.flush()
    }

    #[inline]
    fn serialize_u8(self, v: u8) -> Result<Self::Ok, Self::Error> {
        self.extend(&v.to_le_bytes());
        self.flush()
    }

    #[inline]
    fn serialize_u16(self, v: u16) -> Result<Self::Ok, Self::Error> {
        self.extend(&v.to_le_bytes());
        self.flush()
    }

    #[inline]
    fn serialize_u32(self, v: u32) -> Result<Self::Ok, Self::Error> {
        self.extend(&v.to_le_bytes());
        self.flush()
    }

    #[inline]
    fn serialize_u64(self, v: u64) -> Result<Self::Ok, Self::Error> {
        self.extend(&v.to_le_bytes());
        self.flush()
    }

    #[inline]
    fn serialize_u128(self, v: u128) -> Result<Self::Ok, Self::Error> {
        self.extend(&v.to_le_bytes());
        self.flush()
    }

    #[inline]
    fn serialize_f32(self, v: f32) -> Result<Self::Ok, Self::Error> {
        self.extend(&v.to_le_bytes());
        self.flush()
    }

    #[inline]
    fn serialize_f64(self, v: f64) -> Result<Self::Ok, Self::Error> {
        self.extend(&v.to_le_bytes());
        self.flush()
    }

    #[inline]
    fn serialize_char(self, v: char) -> Result<Self::Ok, Self::Error> {
        (v as u32).serialize(self)
    }

    #[inline]
    fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
        v.as_bytes().serialize(self)
    }

    #[inline]
    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
        self.extend(v);
        self.flush()
    }

    #[inline]
    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        0u8.serialize(self)
    }

    #[inline]
    fn serialize_some<T>(self, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize + ?Sized,
    {
        self.push(1u8);
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

impl<'s, 'f, F> SerializeSeq for &'s mut Serializer<'f, F>
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

impl<'s, 'f, F> SerializeTuple for &'s mut Serializer<'f, F>
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

impl<'s, 'f, F> SerializeTupleStruct for &'s mut Serializer<'f, F>
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

impl<'s, 'f, F> SerializeTupleVariant for &'s mut Serializer<'f, F>
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

impl<'s, 'f, F> SerializeMap for &'s mut Serializer<'f, F>
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

impl<'s, 'f, F> SerializeStruct for &'s mut Serializer<'f, F>
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

impl<'s, 'f, F> SerializeStructVariant for &'s mut Serializer<'f, F>
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

    /// Deserialization Error
    #[derive(derivative::Derivative)]
    #[derivative(Debug(bound = "F::Error: Debug"))]
    pub enum Error<F>
    where
        F: File,
    {
        /// Deserialization Error
        Deserialization(String),

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
                Self::Deserialization(msg) => write!(f, "Deserialization Error: {}", msg),
                Self::Io(err) => write!(f, "File I/O Error: {}", err),
            }
        }
    }

    #[cfg(feature = "std")]
    impl<F> std::error::Error for Error<F>
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
            if self.load()? {
                continue;
            } else {
                return Ok(self.block_data.len() >= n);
            }
        }
        Ok(true)
    }

    /// Reads an array of bytes of size `N` from the encrypted file system, returning `None` if
    /// there weren't enough bytes loaded.
    #[inline]
    fn read_bytes<const N: usize>(&mut self) -> Result<Option<[u8; N]>, F::Error> {
        if self.load_bytes(N)? {
            Ok(Some(into_array_unchecked(
                self.block_data.drain(..N).collect::<Vec<_>>(),
            )))
        } else {
            Ok(None)
        }
    }

    /// Reads one `u8` from the encrypted file system, returning `None` if the `u8` was missing.
    #[inline]
    fn read_u8(&mut self) -> Result<Option<u8>, F::Error> {
        Ok(self.read_bytes()?.map(u8::from_le_bytes))
    }

    /// Reads one `u32` from the encrypted file system, returning `None` if the `u32` was missing.
    #[inline]
    fn read_u32(&mut self) -> Result<Option<u32>, F::Error> {
        Ok(self.read_bytes()?.map(u32::from_le_bytes))
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
        Err(Self::Error::custom(
            "the Deserializer::deserialize_any method is not supported",
        ))
    }

    #[inline]
    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        todo!()
    }

    #[inline]
    fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        todo!()
    }

    #[inline]
    fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        todo!()
    }

    #[inline]
    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        todo!()
    }

    #[inline]
    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        todo!()
    }

    #[inline]
    fn deserialize_i128<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        todo!()
    }

    #[inline]
    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        todo!()
    }

    #[inline]
    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        todo!()
    }

    #[inline]
    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        todo!()
    }

    #[inline]
    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        todo!()
    }

    #[inline]
    fn deserialize_u128<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        todo!()
    }

    #[inline]
    fn deserialize_f32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        todo!()
    }

    #[inline]
    fn deserialize_f64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        todo!()
    }

    #[inline]
    fn deserialize_char<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        todo!()
    }

    #[inline]
    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        todo!()
    }

    #[inline]
    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        todo!()
    }

    #[inline]
    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        todo!()
    }

    #[inline]
    fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        todo!()
    }

    #[inline]
    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        todo!()
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
        todo!()
    }

    #[inline]
    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        todo!()
    }

    #[inline]
    fn deserialize_tuple<V>(self, len: usize, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        todo!()
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
        todo!()
    }

    #[inline]
    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        todo!()
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
        todo!()
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
        let _ = name;
        todo!()
    }

    #[inline]
    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let _ = visitor;
        Err(Self::Error::custom(
            "the Deserializer::deserialize_identifier method is not supported",
        ))
    }

    #[inline]
    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let _ = visitor;
        Err(Self::Error::custom(
            "the Deserializer::deserialize_ignored_any method is not supported",
        ))
    }

    #[inline]
    fn is_human_readable(&self) -> bool {
        false
    }
}
