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

//! Utilities for Manipulating Bytes

/// Exact From Bytes Conversion
pub trait FromBytes<const SIZE: usize> {
    /// Converts an array of `bytes` into an element of type [`Self`].
    fn from_bytes(bytes: [u8; SIZE]) -> Self;
}

/// Exact Into Bytes Conversion
pub trait IntoBytes<const SIZE: usize> {
    /// Converts `self` into its byte array representation of the given `SIZE`.
    fn into_bytes(self) -> [u8; SIZE];
}

/// Exact Bytes Conversion
pub trait Bytes<const SIZE: usize>: FromBytes<SIZE> + IntoBytes<SIZE> {}

impl<B, const SIZE: usize> Bytes<SIZE> for B where B: FromBytes<SIZE> + IntoBytes<SIZE> {}

/// Implements [`Bytes`] for the primitive `$type` of a given `$size` using `from_le_bytes` and
/// `to_le_bytes` for little-endian conversion.
macro_rules! impl_bytes_primitive {
    ($type:tt, $size:expr) => {
        impl FromBytes<$size> for $type {
            #[inline]
            fn from_bytes(bytes: [u8; $size]) -> Self {
                Self::from_le_bytes(bytes)
            }
        }

        impl IntoBytes<$size> for $type {
            #[inline]
            fn into_bytes(self) -> [u8; $size] {
                self.to_le_bytes()
            }
        }
    };
    ($($type:tt),* $(,)?) => {
        $(impl_bytes_primitive!($type, { ($type::BITS / 8) as usize });)*
    };
}

impl_bytes_primitive!(i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize);
impl_bytes_primitive!(f32, 4);
impl_bytes_primitive!(f64, 8);

impl IntoBytes<4> for char {
    #[inline]
    fn into_bytes(self) -> [u8; 4] {
        (self as u32).into_bytes()
    }
}

impl<const N: usize> FromBytes<N> for [u8; N] {
    #[inline]
    fn from_bytes(bytes: [u8; N]) -> Self {
        bytes
    }
}

impl<const N: usize> IntoBytes<N> for [u8; N] {
    #[inline]
    fn into_bytes(self) -> [u8; N] {
        self
    }
}
