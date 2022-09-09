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

//! Arkworks Canonical Serialize and Deserialize Backend

#[cfg(feature = "serde")]
use {
    alloc::vec::Vec,
    manta_util::serde::{de, ser, Deserialize, Deserializer, Serialize, Serializer},
};

#[doc(inline)]
pub use ark_serialize::*;

/// Serializes `data` using the [`CanonicalSerialize`] format with `S` as the [`Serializer`].
#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
#[inline]
pub fn canonical_serialize<T, S>(data: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: CanonicalSerialize,
    S: Serializer,
{
    let mut bytes = Vec::new();
    data.serialize(&mut bytes).map_err(ser::Error::custom)?;
    Serialize::serialize(&bytes, serializer)
}

/// Deserializes data of type `T` using the [`CanonicalDeserialize`] format with `D` as the
/// [`Deserializer`].
#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
#[inline]
pub fn canonical_deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: CanonicalDeserialize,
{
    let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
    CanonicalDeserialize::deserialize(bytes.as_slice()).map_err(de::Error::custom)
}
