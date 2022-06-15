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
use ark_ff::{Field, FpParameters, PrimeField};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, select::CondSelectGadget};
use ark_relations::{
    ns, r1cs as ark_r1cs,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef},
};
use manta_crypto::{
    constraint::{
        self,
        measure::{Count, Measure},
        mode, Add, Assert, AssertEq, ConditionalSwap, Constant, Has, Public, Secret, Variable,
    },
    rand::{CryptoRng, RngCore, Sample},
};
use manta_util::{
    byte_count,
    codec::{Decode, DecodeError, Encode, Read, Write},
    SizeLimit,
};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize, Serializer};

pub use ark_r1cs::SynthesisError;
pub use ark_r1cs_std::{bits::boolean::Boolean, fields::fp::FpVar};

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

impl<F> Sample for Fp<F>
where
    F: Field,
{
    #[inline]
    fn sample<R>(_: (), rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Self(F::rand(rng))
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
    pub(crate) cs: ark_r1cs::ConstraintSystemRef<F>,
}

impl<F> R1CS<F>
where
    F: PrimeField,
{
    /// Constructs a new constraint system which is ready for unknown variables.
    #[inline]
    pub fn for_contexts() -> Self {
        // FIXME: This might not be the right setup for all proof systems.
        let cs = ark_r1cs::ConstraintSystem::new_ref();
        cs.set_optimization_goal(ark_r1cs::OptimizationGoal::Constraints);
        cs.set_mode(ark_r1cs::SynthesisMode::Setup);
        Self { cs }
    }

    /// Constructs a new constraint system which is ready for known variables.
    #[inline]
    pub fn for_proofs() -> Self {
        // FIXME: This might not be the right setup for all proof systems.
        let cs = ark_r1cs::ConstraintSystem::new_ref();
        cs.set_optimization_goal(ark_r1cs::OptimizationGoal::Constraints);
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
    fn assert(&mut self, b: Boolean<F>) {
        b.enforce_equal(&Boolean::TRUE)
            .expect("Enforcing equality is not allowed to fail.");
    }
}

impl<F> AssertEq for R1CS<F>
where
    F: PrimeField,
{
    // TODO: Implement these optimizations.
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

impl<F> constraint::PartialEq<Self, R1CS<F>> for Boolean<F>
where
    F: PrimeField,
{
    #[inline]
    fn eq(lhs: &Self, rhs: &Self, compiler: &mut R1CS<F>) -> Boolean<F> {
        let _ = compiler;
        lhs.is_eq(rhs)
            .expect("Equality checking is not allowed to fail.")
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

impl<F> constraint::PartialEq<Self, R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    #[inline]
    fn eq(lhs: &Self, rhs: &Self, compiler: &mut R1CS<F>) -> Boolean<F> {
        let _ = compiler;
        lhs.is_eq(rhs)
            .expect("Equality checking is not allowed to fail.")
    }
}

/// Conditionally select from `lhs` and `rhs` depending on the value of `bit`.
#[inline]
fn conditionally_select<F>(bit: &Boolean<F>, lhs: &FpVar<F>, rhs: &FpVar<F>) -> FpVar<F>
where
    F: PrimeField,
{
    FpVar::conditionally_select(bit, lhs, rhs)
        .expect("Conditionally selecting from two values is not allowed to fail.")
}

impl<F> ConditionalSwap<R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    #[inline]
    fn swap(bit: &Boolean<F>, lhs: &Self, rhs: &Self, compiler: &mut R1CS<F>) -> (Self, Self) {
        (
            Self::conditionally_select(bit, lhs, rhs),
            Self::conditionally_select(bit, rhs, lhs),
        )
    }
}

impl<F> Add<Self, R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    type Output = Self;

    #[inline]
    fn add(lhs: Self, rhs: Self, compiler: &mut R1CS<F>) -> Self {
        let _ = compiler;
        lhs + rhs
    }
}
