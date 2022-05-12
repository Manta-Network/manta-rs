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

//! Hash Function Implementations

pub mod poseidon;

/// Trait for Public Parameters in Hash Functions
pub trait ParamField: Sized {
    /// Number of bits of modulus of the field.
    const MODULUS_BITS: usize;

    /// Returns the additive identity of the parameter field
    fn zero() -> Self;

    /// Returns the multiplicative identity of the parameter field
    fn one() -> Self;

    /// Adds two parameter field elements together
    fn add(lhs: &Self, rhs: &Self) -> Self;

    /// Adds the `rhs` parameter field element to the `lhs` parameter field element, storing the value in `lhs`
    fn add_assign(lhs: &mut Self, rhs: &Self);

    /// Multiplies two parameter field elements together
    fn mul(lhs: &Self, rhs: &Self) -> Self;

    /// returns (lhs - rhs)
    fn sub(lhs: &Self, rhs: &Self) -> Self;

    /// returns (lhs == rhs)
    fn eq(lhs: &Self, rhs: &Self) -> bool;

    /// Computes the multiplicative inverse of a parameter field element
    fn inverse(elem: &Self) -> Option<Self>;

    /// Converts from bits into a parameter field element in little endian order. Return None if bits are out of range.
    fn try_from_bits_le(bits: &[bool]) -> Option<Self>;

    /// Converts from bytes into a parameter field element in little endian order. If the number of bytes is out of range, the result will be modulo.   
    fn from_le_bytes_mod_order(bytes: &[u8]) -> Self;

    /// Converts a u64 value to a parameter field element
    fn from_u64_to_param(elem: u64) -> Self;
}
