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

//! UTXO Utilities

use alloc::vec::Vec;
use manta_crypto::{
    arkworks::{
        constraint::SynthesisError,
        ff::Field,
        r1cs_std::{R1CSVar, ToBytesGadget},
    },
    eclair::num::UnsignedInteger,
};

/// From a little endian vector `v` of a certain length, it returns a vector of length `n` after removing some zeroes.
///
/// # Panics
///
/// Panics if `vec` length is not at least equal to `n` or if any of it's elements
/// beyond index `n` are non-zero.
pub fn from_little_endian<T>(vec: Vec<T>, n: usize) -> Vec<T>
where
    T: manta_crypto::eclair::num::Zero + PartialEq + Clone,
{
    let vec_len = vec.len();
    assert!(vec_len >= n, "Vector length must be at least equal to N");
    assert!(
        vec[n..vec_len].iter().all(|z| *z == T::zero(&mut ())),
        "Extra elements of `vec` must be zero"
    );
    vec[0..n].to_vec()
}

/// Extracts a vector of bytes from `u`, where `u` implements
/// `ToBytesGadget`
pub fn bytes_from_gadget<U, F>(u: U) -> Result<Vec<u8>, SynthesisError>
where
    U: ToBytesGadget<F>,
    F: Field,
{
    u.to_bytes()?.into_iter().map(|x| x.value()).collect()
}

/// Extracts a vector of bytes from an [`UnsignedInteger`].
pub fn bytes_from_unsigned<T, F, const N: usize>(
    u: &UnsignedInteger<T, N>,
) -> Result<Vec<u8>, SynthesisError>
where
    T: ToBytesGadget<F>,
    F: Field,
{
    u.to_bytes()?.into_iter().map(|x| x.value()).collect()
}
