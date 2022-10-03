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

//! Arkworks Finite Field Backend

use manta_util::{byte_count, into_array_unchecked};

#[doc(inline)]
pub use ark_ff::*;

/// Implements a fallible conversion from `F` to `$type`.
macro_rules! field_try_into {
    ($($name:ident => $type:tt),* $(,)?) => {
        $(
            #[doc = "Tries to convert a field element `x` into an integer of type `"]
            #[doc = stringify!($type)]
            #[doc = "`."]
            #[inline]
            pub fn $name<F>(x: F) -> Option<$type>
            where
                F: PrimeField,
            {
                if x < F::from(2u8).pow([$type::BITS as u64]) {
                    let mut bytes = x.into_repr().to_bytes_le();
                    bytes.truncate(byte_count($type::BITS) as usize);
                    Some($type::from_le_bytes(into_array_unchecked(bytes)))
                } else {
                    None
                }
            }
        )*
    };
}

field_try_into! {
   try_into_u8 => u8,
   try_into_u16 => u16,
   try_into_u32 => u32,
   try_into_u64 => u64,
   try_into_u128 => u128,
}

/// Testing Suite
#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        arkworks::bn254::Fr,
        rand::{OsRng, Rand, RngCore, Sample},
    };
    use alloc::vec::Vec;
    use core::fmt::Debug;

    /// Asserts that a single conversion of `value` specified by `convert` is correct.
    #[inline]
    pub fn assert_valid_integer_conversion<F, T, C>(convert: C, value: T)
    where
        F: PrimeField,
        T: Copy + Debug + Into<F> + PartialEq,
        C: Fn(F) -> Option<T>,
    {
        assert_eq!(
            convert(value.into()),
            Some(value),
            "Conversion should have been the inverse of the `F::into` function."
        );
    }

    /// Asserts that the conversions specified by `convert` are valid.
    #[inline]
    pub fn assert_valid_integer_conversions<F, T, C, R, const ROUNDS: usize>(
        convert: C,
        test_vector: Vec<T>,
        rng: &mut R,
    ) where
        F: PrimeField,
        T: Copy + Debug + Into<F> + PartialEq + Sample,
        C: Fn(F) -> Option<T>,
        R: RngCore + ?Sized,
    {
        for element in test_vector {
            assert_valid_integer_conversion(&convert, element);
        }
        for _ in 0..ROUNDS {
            assert_valid_integer_conversion(&convert, rng.gen());
        }
    }

    /// Generates the conversion test for `$type` against the BN254 Curve.
    macro_rules! generate_test {
        ($name:ident, $convert:ident, $type:tt) => {
            #[test]
            fn $name() {
                assert_valid_integer_conversions::<Fr, _, _, _, 0xFFFF>(
                    $convert,
                    vec![0, 1, 2, $type::MAX - 2, $type::MAX - 1, $type::MAX],
                    &mut OsRng,
                );
            }
        };
    }

    generate_test!(u8_has_valid_conversions, try_into_u8, u8);
    generate_test!(u16_has_valid_conversions, try_into_u16, u16);
    generate_test!(u32_has_valid_conversions, try_into_u32, u32);
    generate_test!(u64_has_valid_conversions, try_into_u64, u64);
    generate_test!(u128_has_valid_conversions, try_into_u128, u128);
}
