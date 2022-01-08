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

//! Serialization Utilities

use alloc::vec::Vec;

/// Serialization
pub trait Serialize {
    /// Appends representation of `self` in bytes to `buffer`.
    fn serialize(&self, buffer: &mut Vec<u8>);

    /// Converts `self` into a vector of bytes.
    #[inline]
    fn to_vec(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        self.serialize(&mut buffer);
        buffer
    }
}

impl Serialize for u8 {
    #[inline]
    fn serialize(&self, buffer: &mut Vec<u8>) {
        buffer.push(*self);
    }
}

impl<T> Serialize for [T]
where
    T: Serialize,
{
    #[inline]
    fn serialize(&self, buffer: &mut Vec<u8>) {
        for item in self {
            item.serialize(buffer);
        }
    }
}

impl<T, const N: usize> Serialize for [T; N]
where
    T: Serialize,
{
    #[inline]
    fn serialize(&self, buffer: &mut Vec<u8>) {
        for item in self {
            item.serialize(buffer);
        }
    }
}

/// Exact Size Serialization
pub trait SerializeExactSize<const N: usize>: Serialize {
    /// Converts `self` into a exactly known byte array.
    fn to_array(&self) -> [u8; N];
}

/// Deserialization
pub trait Deserialize: Sized {
    /// Error Type
    type Error;

    /// Parses the input `buffer` into a concrete value of type `Self` if possible.
    fn deserialize(buffer: &mut Vec<u8>) -> Result<Self, Self::Error>;

    /// Converts a byte vector into a concrete value of type `Self` if possible.
    #[cfg(feature = "zeroize")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "zeroize")))]
    #[inline]
    fn from_vec(buffer: Vec<u8>) -> Result<Self, Self::Error> {
        let mut buffer = zeroize::Zeroizing::new(buffer);
        Self::deserialize(&mut buffer)
    }
}

/// Exact Size Deserialization
pub trait DeserializeExactSize<const N: usize>: Deserialize {
    /// Converts a fixed-length byte array into a concrete value of type `Self`.
    fn from_array(buffer: [u8; N]) -> Self;
}
