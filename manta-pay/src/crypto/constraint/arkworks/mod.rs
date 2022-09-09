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

//! Arkworks Constraint System and Proof System Implementations

use alloc::vec::Vec;
use core::iter::{self, Extend};
use manta_crypto::{
    algebra,
    arkworks::{
        ff::{Field, FpParameters, PrimeField, ToConstraintField},
        r1cs_std::{
            alloc::AllocVar, eq::EqGadget, fields::FieldVar, select::CondSelectGadget, ToBitsGadget,
        },
        relations::{
            ns,
            r1cs::{
                ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal,
                SynthesisMode,
            },
        },
    },
    constraint::{
        measure::{Count, Measure},
        Input, ProofSystem,
    },
    eclair::{
        self,
        alloc::{
            mode::{self, Public, Secret},
            Constant, Variable,
        },
        bool::{Assert, Bool, ConditionalSelect, ConditionalSwap},
        num::{AssertWithinBitRange, Zero},
        ops::{Add, BitAnd, BitOr},
        Has, NonNative,
    },
    rand::{RngCore, Sample},
};
use manta_util::{
    byte_count,
    codec::{Decode, DecodeError, Encode, Read, Write},
    SizeLimit,
};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize, Serializer};

pub use manta_crypto::arkworks::{
    r1cs_std::{bits::boolean::Boolean, fields::fp::FpVar},
    relations::r1cs::SynthesisError,
};

pub mod codec;
pub mod pairing;

#[cfg(feature = "groth16")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "groth16")))]
pub mod groth16;

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

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl<F> scale_codec::Decode for Fp<F>
where
    F: Field,
{
    #[inline]
    fn decode<I>(input: &mut I) -> Result<Self, scale_codec::Error>
    where
        I: scale_codec::Input,
    {
        Ok(Self(
            F::deserialize(codec::ScaleCodecReader(input)).map_err(|_| "Deserialization Error")?,
        ))
    }
}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl<F> scale_codec::Encode for Fp<F>
where
    F: Field,
{
    #[inline]
    fn using_encoded<R, Encoder>(&self, f: Encoder) -> R
    where
        Encoder: FnOnce(&[u8]) -> R,
    {
        f(&field_element_as_bytes::<F>(&self.0))
    }
}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl<F> scale_codec::EncodeLike for Fp<F> where F: Field {}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl<F> scale_codec::MaxEncodedLen for Fp<F>
where
    F: Field,
{
    #[inline]
    fn max_encoded_len() -> usize {
        byte_count(
            <<F::BasePrimeField as PrimeField>::Params as FpParameters>::MODULUS_BITS
                * (F::extension_degree() as u32),
        ) as usize
    }
}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl<F> scale_info::TypeInfo for Fp<F>
where
    F: Field,
{
    type Identity = [u8];

    #[inline]
    fn type_info() -> scale_info::Type {
        Self::Identity::type_info()
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

/// Synthesis Result
pub type SynthesisResult<T = ()> = Result<T, SynthesisError>;

/// Returns an empty variable assignment for setup mode.
///
/// # Warning
///
/// This does not work for all variable assignments! For some assignemnts, the variable inherits
/// some structure from its input, like its length or number of bits, which are only known at
/// run-time. For those cases, some mocking is required and this function can not be used directly.
#[inline]
pub fn empty<T>() -> SynthesisResult<T> {
    Err(SynthesisError::AssignmentMissing)
}

/// Returns a filled variable assignment with the given `value`.
#[inline]
pub fn full<T>(value: T) -> impl FnOnce() -> SynthesisResult<T> {
    move || Ok(value)
}

/// Arkworks Rank-1 Constraint System
pub struct R1CS<F>
where
    F: PrimeField,
{
    /// Constraint System
    pub(crate) cs: ConstraintSystemRef<F>,
}

impl<F> R1CS<F>
where
    F: PrimeField,
{
    /// Constructs a new constraint system which is ready for unknown variables.
    #[inline]
    pub fn for_contexts() -> Self {
        // FIXME: This might not be the right setup for all proof systems.
        let cs = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Setup);
        Self { cs }
    }

    /// Constructs a new constraint system which is ready for known variables.
    #[inline]
    pub fn for_proofs() -> Self {
        // FIXME: This might not be the right setup for all proof systems.
        let cs = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        Self { cs }
    }

    /// Check if all constraints are satisfied.
    #[inline]
    pub fn is_satisfied(&self) -> bool {
        self.cs
            .is_satisfied()
            .expect("is_satisfied is not allowed to fail")
    }
}

impl<F> NonNative for R1CS<F> where F: PrimeField {}

impl<F> Has<bool> for R1CS<F>
where
    F: PrimeField,
{
    type Type = Boolean<F>;
}

impl<F> Assert for R1CS<F>
where
    F: PrimeField,
{
    #[inline]
    fn assert(&mut self, b: &Boolean<F>) {
        b.enforce_equal(&Boolean::TRUE)
            .expect("Enforcing equality is not allowed to fail.");
    }
}

impl<F, const BITS: usize> AssertWithinBitRange<FpVar<F>, BITS> for R1CS<F>
where
    F: PrimeField,
{
    #[inline]
    fn assert_within_range(&mut self, value: &FpVar<F>) {
        assert!(
            BITS < F::Params::MODULUS_BITS as usize,
            "BITS must be strictly less than modulus bits of `F`."
        );
        let value_bits = value
            .to_bits_le()
            .expect("Bit decomposition is not allowed to fail.");
        for bit in &value_bits[BITS..] {
            bit.enforce_equal(&Boolean::FALSE)
                .expect("Enforcing equality is not allowed to fail.");
        }
    }
}

impl<F> Count<mode::Constant> for R1CS<F> where F: PrimeField {}

impl<F> Count<Public> for R1CS<F>
where
    F: PrimeField,
{
    #[inline]
    fn count(&self) -> Option<usize> {
        Some(self.cs.num_instance_variables())
    }
}

impl<F> Count<Secret> for R1CS<F>
where
    F: PrimeField,
{
    #[inline]
    fn count(&self) -> Option<usize> {
        Some(self.cs.num_witness_variables())
    }
}

impl<F> Measure for R1CS<F>
where
    F: PrimeField,
{
    #[inline]
    fn constraint_count(&self) -> usize {
        self.cs.num_constraints()
    }
}

impl<F> ConstraintSynthesizer<F> for R1CS<F>
where
    F: PrimeField,
{
    /// Generates constraints for `self` by copying them into `cs`. This method is necessary to hook
    /// into the proof system traits defined in `arkworks`.
    #[inline]
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> SynthesisResult {
        let precomputed_cs = self
            .cs
            .into_inner()
            .expect("We own this constraint system so we can consume it.");
        let mut target_cs = cs
            .borrow_mut()
            .expect("This is given to us to mutate so it can't be borrowed by anyone else.");
        *target_cs = precomputed_cs;
        Ok(())
    }
}

impl<F> Constant<R1CS<F>> for Boolean<F>
where
    F: PrimeField,
{
    type Type = bool;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
        AllocVar::new_constant(ns!(compiler.cs, "boolean constant"), this)
            .expect("Variable allocation is not allowed to fail.")
    }
}

impl<F> Variable<Public, R1CS<F>> for Boolean<F>
where
    F: PrimeField,
{
    type Type = bool;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
        Self::new_input(ns!(compiler.cs, "boolean public input"), full(this))
            .expect("Variable allocation is not allowed to fail.")
    }

    #[inline]
    fn new_unknown(compiler: &mut R1CS<F>) -> Self {
        Self::new_input(ns!(compiler.cs, "boolean public input"), empty::<bool>)
            .expect("Variable allocation is not allowed to fail.")
    }
}

impl<F> Variable<Secret, R1CS<F>> for Boolean<F>
where
    F: PrimeField,
{
    type Type = bool;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
        Self::new_witness(ns!(compiler.cs, "boolean secret witness"), full(this))
            .expect("Variable allocation is not allowed to fail.")
    }

    #[inline]
    fn new_unknown(compiler: &mut R1CS<F>) -> Self {
        Self::new_witness(ns!(compiler.cs, "boolean secret witness"), empty::<bool>)
            .expect("Variable allocation is not allowed to fail.")
    }
}

impl<F> eclair::cmp::PartialEq<Self, R1CS<F>> for Boolean<F>
where
    F: PrimeField,
{
    #[inline]
    fn eq(&self, rhs: &Self, compiler: &mut R1CS<F>) -> Boolean<F> {
        let _ = compiler;
        self.is_eq(rhs)
            .expect("Equality checking is not allowed to fail.")
    }
}

impl<F> BitAnd<Self, R1CS<F>> for Boolean<F>
where
    F: PrimeField,
{
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self, compiler: &mut R1CS<F>) -> Self::Output {
        let _ = compiler;
        self.and(&rhs).expect("Bitwise AND is not allowed to fail.")
    }
}

impl<F> BitOr<Self, R1CS<F>> for Boolean<F>
where
    F: PrimeField,
{
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self, compiler: &mut R1CS<F>) -> Self::Output {
        let _ = compiler;
        self.or(&rhs).expect("Bitwise OR is not allowed to fail.")
    }
}

impl<F> Constant<R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    type Type = Fp<F>;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
        AllocVar::new_constant(ns!(compiler.cs, "field constant"), this.0)
            .expect("Variable allocation is not allowed to fail.")
    }
}

impl<F> Constant<R1CS<F>> for Fp<F>
where
    F: PrimeField,
{
    type Type = Self;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
        let _ = compiler;
        *this
    }
}

impl<F> Variable<Public, R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    type Type = Fp<F>;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
        Self::new_input(ns!(compiler.cs, "field public input"), full(this.0))
            .expect("Variable allocation is not allowed to fail.")
    }

    #[inline]
    fn new_unknown(compiler: &mut R1CS<F>) -> Self {
        Self::new_input(ns!(compiler.cs, "field public input"), empty::<F>)
            .expect("Variable allocation is not allowed to fail.")
    }
}

impl<F> Variable<Secret, R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    type Type = Fp<F>;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
        Self::new_witness(ns!(compiler.cs, "field secret witness"), full(this.0))
            .expect("Variable allocation is not allowed to fail.")
    }

    #[inline]
    fn new_unknown(compiler: &mut R1CS<F>) -> Self {
        Self::new_witness(ns!(compiler.cs, "field secret witness"), empty::<F>)
            .expect("Variable allocation is not allowed to fail.")
    }
}

impl<F> eclair::cmp::PartialEq<Self, R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    #[inline]
    fn eq(&self, rhs: &Self, compiler: &mut R1CS<F>) -> Boolean<F> {
        let _ = compiler;
        self.is_eq(rhs)
            .expect("Equality checking is not allowed to fail.")
    }
}

/// Conditionally select from `lhs` and `rhs` depending on the value of `bit`.
#[inline]
pub fn conditionally_select<F, T>(bit: &Boolean<F>, lhs: &T, rhs: &T) -> T
where
    F: PrimeField,
    T: CondSelectGadget<F>,
{
    CondSelectGadget::conditionally_select(bit, lhs, rhs)
        .expect("Conditionally selecting from two values is not allowed to fail.")
}

impl<F> ConditionalSelect<R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    #[inline]
    fn select(
        bit: &Boolean<F>,
        true_value: &Self,
        false_value: &Self,
        compiler: &mut R1CS<F>,
    ) -> Self {
        let _ = compiler;
        conditionally_select(bit, true_value, false_value)
    }
}

impl<F> ConditionalSwap<R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    #[inline]
    fn swap(bit: &Boolean<F>, lhs: &Self, rhs: &Self, compiler: &mut R1CS<F>) -> (Self, Self) {
        let _ = compiler;
        (
            conditionally_select(bit, rhs, lhs),
            conditionally_select(bit, lhs, rhs),
        )
    }
}

impl<F> Add<Self, R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self, compiler: &mut R1CS<F>) -> Self {
        let _ = compiler;
        self + rhs
    }
}

impl<F> Zero<R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    type Verification = Boolean<F>;

    #[inline]
    fn zero(compiler: &mut R1CS<F>) -> Self {
        let _ = compiler;
        FieldVar::zero()
    }

    #[inline]
    fn is_zero(&self, compiler: &mut R1CS<F>) -> Self::Verification {
        let _ = compiler;
        FieldVar::is_zero(self).expect("Comparison with zero is not allowed to fail.")
    }
}

/// Testing Suite
#[cfg(test)]
mod tests {
    use super::*;
    use core::iter::repeat_with;
    use manta_crypto::{
        arkworks::{bls12_381::Fr, ff::BigInteger},
        eclair::alloc::Allocate,
        rand::{OsRng, Rand},
    };

    /// Checks if `assert_within_range` passes when `should_pass` is `true` and fails when
    /// `should_pass` is `false`.
    #[inline]
    fn check_assert_within_range<F, const BITS: usize>(value: Fp<F>, should_pass: bool)
    where
        F: PrimeField,
    {
        let mut cs = R1CS::<F>::for_proofs();
        let variable = value.as_known::<Secret, FpVar<_>>(&mut cs);
        AssertWithinBitRange::<_, BITS>::assert_within_range(&mut cs, &variable);
        let satisfied = cs.is_satisfied();
        assert_eq!(
            should_pass, satisfied,
            "on value {:?}, expect satisfied = {}, but got {}",
            value, should_pass, satisfied
        );
    }

    /// Samples a field element with fewer than `BITS`-many bits using `rng`.
    #[inline]
    fn sample_smaller_than<R, F, const BITS: usize>(rng: &mut R) -> Fp<F>
    where
        R: RngCore + ?Sized,
        F: PrimeField,
    {
        Fp(F::from_repr(F::BigInt::from_bits_le(
            &repeat_with(|| rng.gen()).take(BITS).collect::<Vec<_>>(),
        ))
        .expect("BITS should be less than modulus bits of field."))
    }

    /// Samples a field element larger than `bound` using `rng`.
    #[inline]
    fn sample_larger_than<R, F>(bound: &Fp<F>, rng: &mut R) -> Fp<F>
    where
        R: RngCore + ?Sized,
        F: PrimeField,
    {
        let mut value = rng.gen();
        while &value <= bound {
            value = rng.gen();
        }
        value
    }

    /// Checks if [`assert_within_range`] works correctly for `BITS`-many bits with `ROUNDS`-many
    /// tests for less than the range and more than the range.
    #[inline]
    fn test_assert_within_range<R, F, const BITS: usize, const ROUNDS: usize>(rng: &mut R)
    where
        R: RngCore + ?Sized,
        F: PrimeField,
    {
        let bound = Fp(F::from(2u64).pow([BITS as u64]));
        check_assert_within_range::<_, BITS>(Fp(F::zero()), true);
        check_assert_within_range::<_, BITS>(Fp(bound.0 - F::one()), true);
        check_assert_within_range::<_, BITS>(bound, false);
        for _ in 0..ROUNDS {
            check_assert_within_range::<_, BITS>(sample_smaller_than::<_, F, BITS>(rng), true);
            check_assert_within_range::<_, BITS>(sample_larger_than(&bound, rng), false);
        }
    }

    /// Tests if `assert_within_range` works correctly for U8, U16, U32, U64, and U128.
    #[test]
    fn assert_within_range_is_correct() {
        let mut rng = OsRng;
        test_assert_within_range::<_, Fr, 8, 32>(&mut rng);
        test_assert_within_range::<_, Fr, 16, 32>(&mut rng);
        test_assert_within_range::<_, Fr, 32, 32>(&mut rng);
        test_assert_within_range::<_, Fr, 64, 32>(&mut rng);
        test_assert_within_range::<_, Fr, 128, 32>(&mut rng);
    }
}
