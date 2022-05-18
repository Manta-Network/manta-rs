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

//! Poseidon Hash Implementation

pub mod hasher;
pub mod parameter_generation;

/// Trait for Public Parameters in Hash Functions.
pub trait Field {
    /// Returns the additive identity of the field.
    fn zero() -> Self;

    /// Returns the multiplicative identity of the field.
    fn one() -> Self;

    /// Adds two field elements together.
    fn add(lhs: &Self, rhs: &Self) -> Self;

    /// Adds the `rhs` field element to the `self` field element, storing the value in `self`.
    fn add_assign(&mut self, rhs: &Self);

    /// Multiplies two field elements together.
    fn mul(lhs: &Self, rhs: &Self) -> Self;

    /// Subtracts `rhs` from `lhs`.
    fn sub(lhs: &Self, rhs: &Self) -> Self;

    /// Computes the multiplicative inverse of a field element.
    fn inverse(&self) -> Option<Self> where Self: Sized;

    /// Checks if `self` equals `rhs`.
    fn eq(&self, rhs: &Self) -> bool;
}

/// Field Element Generation
pub trait FieldGeneration {
    /// Number of bits of modulus of the field.
    const MODULUS_BITS: usize;

    /// Converts from `bits` into a field element in little endian order.
    /// Return `None` if `bits` are out of range.
    fn try_from_bits_le(bits: &[bool]) -> Option<Self> where Self: Sized;

    /// Converts from `bytes` into a field element in little endian order. 
    /// If the number of bytes is out of range, the result will be modulo.   
    fn from_le_bytes_mod_order(bytes: &[u8]) -> Self;

    /// Converts a `u64` value to a field element.
    fn from_u64(elem: u64) -> Self;
}
