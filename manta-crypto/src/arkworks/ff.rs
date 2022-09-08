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

use crate::{
    algebra,
    arkworks::codec,
    constraint::{Input, ProofSystem},
    eclair::{
        self,
        bool::{Bool, ConditionalSelect},
    },
    rand::{RngCore, Sample},
};
use alloc::vec::Vec;
use core::iter::{self, Extend};
use manta_util::{
    byte_count,
    codec::{Decode, DecodeError, Encode, Read, Write},
    into_array_unchecked, SizeLimit,
};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize, Serializer};

#[doc(inline)]
pub use ark_ff::*;

/// Field Element
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(deserialize = "", serialize = ""),
        crate = "manta_util::serde",
        deny_unknown_fields,
        try_from = "Vec<u8>"
    )
)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Fp<F>(
    /// Field Element
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "serialize_field_element::<F, _>")
    )]
    pub F,
)
where
    F: Field;

impl<F> From<u128> for Fp<F>
where
    F: Field,
{
    #[inline]
    fn from(value: u128) -> Self {
        Self(value.into())
    }
}

impl<F> ToConstraintField<F> for Fp<F>
where
    F: PrimeField,
{
    #[inline]
    fn to_field_elements(&self) -> Option<Vec<F>> {
        self.0.to_field_elements()
    }
}

impl<F, P> Input<P> for Fp<F>
where
    F: Field,
    P: ProofSystem + ?Sized,
    P::Input: Extend<F>,
{
    #[inline]
    fn extend(&self, input: &mut P::Input) {
        input.extend(iter::once(self.0))
    }
}

impl<F> Decode for Fp<F>
where
    F: Field,
{
    type Error = codec::SerializationError;

    #[inline]
    fn decode<R>(reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: Read,
    {
        let mut reader = codec::ArkReader::new(reader);
        match F::deserialize(&mut reader) {
            Ok(value) => reader
                .finish()
                .map(move |_| Self(value))
                .map_err(DecodeError::Read),
            Err(err) => Err(DecodeError::Decode(err)),
        }
    }
}

impl<F> Encode for Fp<F>
where
    F: Field,
{
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        let mut writer = codec::ArkWriter::new(writer);
        let _ = self.0.serialize(&mut writer);
        writer.finish().map(move |_| ())
    }
}

impl<F> eclair::cmp::PartialEq<Self> for Fp<F>
where
    F: Field,
{
    #[inline]
    fn eq(&self, rhs: &Self, _: &mut ()) -> bool {
        PartialEq::eq(self, rhs)
    }
}

impl<F> eclair::num::Zero for Fp<F>
where
    F: Field,
{
    type Verification = bool;

    #[inline]
    fn zero(_: &mut ()) -> Self {
        Self(F::zero())
    }

    #[inline]
    fn is_zero(&self, _: &mut ()) -> Self::Verification {
        self.0.is_zero()
    }
}

impl<F> eclair::num::One for Fp<F>
where
    F: Field,
{
    type Verification = bool;

    #[inline]
    fn one(_: &mut ()) -> Self {
        Self(F::one())
    }

    #[inline]
    fn is_one(&self, _: &mut ()) -> Self::Verification {
        self.0.is_one()
    }
}

impl<F> ConditionalSelect for Fp<F>
where
    F: Field,
{
    #[inline]
    fn select(bit: &Bool, true_value: &Self, false_value: &Self, _: &mut ()) -> Self {
        if *bit {
            *true_value
        } else {
            *false_value
        }
    }
}

impl<F> Sample for Fp<F>
where
    F: Field,
{
    #[inline]
    fn sample<R>(_: (), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self(F::rand(rng))
    }
}

impl<F> algebra::Group for Fp<F>
where
    F: Field,
{
    #[inline]
    fn add(&self, rhs: &Self, _: &mut ()) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl<F> algebra::Ring for Fp<F>
where
    F: Field,
{
    #[inline]
    fn mul(&self, rhs: &Self, _: &mut ()) -> Self {
        Self(self.0 * rhs.0)
    }
}

impl<F> SizeLimit for Fp<F>
where
    F: PrimeField,
{
    const SIZE: usize = byte_count(<F::Params as FpParameters>::MODULUS_BITS) as usize;
}

impl<F> TryFrom<Vec<u8>> for Fp<F>
where
    F: Field,
{
    type Error = codec::SerializationError;

    #[inline]
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        F::deserialize(&mut bytes.as_slice()).map(Self)
    }
}

/// Converts `element` into its canonical byte-representation.
#[inline]
pub fn field_element_as_bytes<F>(element: &F) -> Vec<u8>
where
    F: Field,
{
    let mut buffer = Vec::new();
    element
        .serialize(&mut buffer)
        .expect("Serialization is not allowed to fail.");
    buffer
}

/// Uses `serializer` to serialize `element`.
#[cfg(feature = "serde")]
#[inline]
fn serialize_field_element<F, S>(element: &F, serializer: S) -> Result<S::Ok, S::Error>
where
    F: Field,
    S: Serializer,
{
    serializer.serialize_bytes(&field_element_as_bytes(element))
}

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
    use crate::rand::{OsRng, Rand, RngCore, Sample};
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
                assert_valid_integer_conversions::<ark_bn254::Fr, _, _, _, 0xFFFF>(
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
