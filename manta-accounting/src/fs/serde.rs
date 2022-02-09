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
use alloc::vec::Vec;
use core::marker::PhantomData;
use manta_util::serde::{
    self,
    de::Visitor,
    ser::{
        SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple,
        SerializeTupleStruct, SerializeTupleVariant,
    },
    Serialize,
};

/// Serialization Module
pub mod ser {
    use super::*;
    use core::fmt::Display;
    use derive_more::Display;

    /// Serialization Error
    #[derive(Debug, Display)]
    pub enum Error {}

    #[cfg(feature = "std")]
    impl std::error::Error for Error {}

    impl serde::ser::Error for Error {
        #[inline]
        fn custom<T>(msg: T) -> Self
        where
            T: Display,
        {
            todo!()
        }
    }

    /// Compound Data Structure
    pub struct Compound<'f, F>(PhantomData<&'f mut F>);
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
}

impl<'f, F> Serializer<'f, F>
where
    F: File,
{
    ///
    #[inline]
    pub fn new(file: &'f mut F) -> Self {
        Self {
            file,
            block_data: Vec::with_capacity(Block::SIZE),
        }
    }
}

impl<'f, F> serde::Serializer for &mut Serializer<'f, F>
where
    F: File,
{
    type Ok = ();
    type Error = ser::Error;
    type SerializeSeq = ser::Compound<'f, F>;
    type SerializeTuple = ser::Compound<'f, F>;
    type SerializeTupleStruct = ser::Compound<'f, F>;
    type SerializeTupleVariant = ser::Compound<'f, F>;
    type SerializeMap = ser::Compound<'f, F>;
    type SerializeStruct = ser::Compound<'f, F>;
    type SerializeStructVariant = ser::Compound<'f, F>;

    #[inline]
    fn serialize_bool(self, v: bool) -> Result<Self::Ok, Self::Error> {
        todo!()
    }

    #[inline]
    fn serialize_i8(self, v: i8) -> Result<Self::Ok, Self::Error> {
        todo!()
    }

    #[inline]
    fn serialize_i16(self, v: i16) -> Result<Self::Ok, Self::Error> {
        todo!()
    }

    #[inline]
    fn serialize_i32(self, v: i32) -> Result<Self::Ok, Self::Error> {
        todo!()
    }

    #[inline]
    fn serialize_i64(self, v: i64) -> Result<Self::Ok, Self::Error> {
        todo!()
    }

    #[inline]
    fn serialize_i128(self, v: i128) -> Result<Self::Ok, Self::Error> {
        todo!()
    }

    #[inline]
    fn serialize_u8(self, v: u8) -> Result<Self::Ok, Self::Error> {
        todo!()
    }

    #[inline]
    fn serialize_u16(self, v: u16) -> Result<Self::Ok, Self::Error> {
        todo!()
    }

    #[inline]
    fn serialize_u32(self, v: u32) -> Result<Self::Ok, Self::Error> {
        todo!()
    }

    #[inline]
    fn serialize_u64(self, v: u64) -> Result<Self::Ok, Self::Error> {
        todo!()
    }

    #[inline]
    fn serialize_u128(self, v: u128) -> Result<Self::Ok, Self::Error> {
        todo!()
    }

    #[inline]
    fn serialize_f32(self, v: f32) -> Result<Self::Ok, Self::Error> {
        todo!()
    }

    #[inline]
    fn serialize_f64(self, v: f64) -> Result<Self::Ok, Self::Error> {
        todo!()
    }

    #[inline]
    fn serialize_char(self, v: char) -> Result<Self::Ok, Self::Error> {
        todo!()
    }

    #[inline]
    fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
        todo!()
    }

    #[inline]
    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
        todo!()
    }

    #[inline]
    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        todo!()
    }

    #[inline]
    fn serialize_some<T>(self, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize + ?Sized,
    {
        todo!()
    }

    #[inline]
    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        todo!()
    }

    #[inline]
    fn serialize_unit_struct(self, name: &'static str) -> Result<Self::Ok, Self::Error> {
        todo!()
    }

    #[inline]
    fn serialize_unit_variant(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        todo!()
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
        todo!()
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
        todo!()
    }

    #[inline]
    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        todo!()
    }

    #[inline]
    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        todo!()
    }

    #[inline]
    fn serialize_tuple_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        todo!()
    }

    #[inline]
    fn serialize_tuple_variant(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        todo!()
    }

    #[inline]
    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        todo!()
    }

    #[inline]
    fn serialize_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        todo!()
    }

    #[inline]
    fn serialize_struct_variant(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        todo!()
    }

    #[inline]
    fn is_human_readable(&self) -> bool {
        false
    }
}

impl<'f, F> SerializeSeq for ser::Compound<'f, F> {
    type Ok = ();
    type Error = ser::Error;

    #[inline]
    fn serialize_element<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        todo!()
    }

    #[inline]
    fn end(self) -> Result<Self::Ok, Self::Error> {
        todo!()
    }
}

impl<'f, F> SerializeTuple for ser::Compound<'f, F> {
    type Ok = ();
    type Error = ser::Error;

    #[inline]
    fn serialize_element<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        todo!()
    }
    #[inline]
    fn end(self) -> Result<Self::Ok, Self::Error> {
        todo!()
    }
}

impl<'f, F> SerializeTupleStruct for ser::Compound<'f, F> {
    type Ok = ();
    type Error = ser::Error;

    #[inline]
    fn serialize_field<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        todo!()
    }

    #[inline]
    fn end(self) -> Result<Self::Ok, Self::Error> {
        todo!()
    }
}

impl<'f, F> SerializeTupleVariant for ser::Compound<'f, F> {
    type Ok = ();
    type Error = ser::Error;

    #[inline]
    fn serialize_field<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        todo!()
    }

    #[inline]
    fn end(self) -> Result<Self::Ok, Self::Error> {
        todo!()
    }
}

impl<'f, F> SerializeMap for ser::Compound<'f, F> {
    type Ok = ();
    type Error = ser::Error;

    #[inline]
    fn serialize_key<T>(&mut self, key: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        todo!()
    }

    #[inline]
    fn serialize_value<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        todo!()
    }

    #[inline]
    fn serialize_entry<K, V>(&mut self, key: &K, value: &V) -> Result<(), Self::Error>
    where
        K: Serialize + ?Sized,
        V: Serialize + ?Sized,
    {
        todo!()
    }

    #[inline]
    fn end(self) -> Result<Self::Ok, Self::Error> {
        todo!()
    }
}

impl<'f, F> SerializeStruct for ser::Compound<'f, F> {
    type Ok = ();
    type Error = ser::Error;

    #[inline]
    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        todo!()
    }

    #[inline]
    fn skip_field(&mut self, key: &'static str) -> Result<(), Self::Error> {
        todo!()
    }

    #[inline]
    fn end(self) -> Result<Self::Ok, Self::Error> {
        todo!()
    }
}

impl<'f, F> SerializeStructVariant for ser::Compound<'f, F> {
    type Ok = ();
    type Error = ser::Error;

    #[inline]
    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + ?Sized,
    {
        todo!()
    }

    #[inline]
    fn skip_field(&mut self, key: &'static str) -> Result<(), Self::Error> {
        todo!()
    }

    #[inline]
    fn end(self) -> Result<Self::Ok, Self::Error> {
        todo!()
    }
}

/// Deserialization Module
pub mod de {
    use super::*;
    use core::fmt::Display;
    use derive_more::Display;

    /// Deserialization Error
    #[derive(Debug, Display)]
    pub enum Error {}

    #[cfg(feature = "std")]
    impl std::error::Error for Error {}

    impl serde::de::Error for Error {
        #[inline]
        fn custom<T>(msg: T) -> Self
        where
            T: Display,
        {
            todo!()
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
}

impl<'f, F> Deserializer<'f, F>
where
    F: File,
{
    ///
    #[inline]
    pub fn new(file: &'f mut F) -> Self {
        Self { file }
    }
}

impl<'de, 'f, F> manta_util::serde::Deserializer<'de> for &mut Deserializer<'f, F>
where
    F: File,
{
    type Error = de::Error;

    #[inline]
    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        todo!()
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
        todo!()
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
        todo!()
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
        todo!()
    }

    #[inline]
    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        todo!()
    }

    #[inline]
    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        todo!()
    }

    #[inline]
    fn is_human_readable(&self) -> bool {
        false
    }
}
