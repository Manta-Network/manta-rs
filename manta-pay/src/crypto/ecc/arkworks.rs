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

//! Arkworks Elliptic Curve Primitives

use crate::crypto::constraint::arkworks::{
    self, conditionally_select, empty, full, Boolean, Fp, FpVar, R1CS,
};
use alloc::vec::Vec;
use core::{borrow::Borrow, marker::PhantomData};
use manta_crypto::{
    algebra,
    algebra::FixedBaseScalarMul,
    arkworks::{
        algebra::{affine_point_as_bytes, modulus_is_smaller},
        ec::{AffineCurve, ProjectiveCurve},
        ff::{BigInteger, Field, PrimeField, Zero as _},
        r1cs_std::{groups::CurveVar, ToBitsGadget},
        relations::ns,
        serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError},
    },
    eclair::{
        self,
        alloc::{
            mode::{Public, Secret},
            Allocate, Allocator, Constant, Variable,
        },
        bool::{Bool, ConditionalSelect},
        cmp,
        num::Zero,
    },
    rand::{RngCore, Sample},
};
use manta_util::{codec, AsBytes};

#[cfg(feature = "serde")]
use {
    manta_crypto::arkworks::algebra::serialize_group_element,
    manta_util::serde::{Deserialize, Serialize},
};

/// Constraint Field Type
type ConstraintField<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;

/// Compiler Type
type Compiler<C> = R1CS<ConstraintField<C>>;

/// Scalar Field Element
pub type Scalar<C> = Fp<<C as ProjectiveCurve>::ScalarField>;

/// Lifts an embedded scalar to an outer scalar.
///
/// # Safety
///
/// This can only be used whenver the embedded scalar field is **smaller** than the outer scalar
/// field.
#[inline]
pub fn lift_embedded_scalar<C>(scalar: &Scalar<C>) -> Fp<ConstraintField<C>>
where
    C: ProjectiveCurve,
{
    assert!(
        modulus_is_smaller::<C::ScalarField, ConstraintField<C>>(),
        "The modulus of the embedded scalar field is larger than that of the constraint field."
    );
    Fp(ConstraintField::<C>::from_le_bytes_mod_order(
        &scalar.0.into_repr().to_bytes_le(),
    ))
}

/// Elliptic Curve Group Element
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
pub struct Group<C>(
    /// Affine Point Representation
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "serialize_group_element::<C, _>")
    )]
    pub(crate) C::Affine,
)
where
    C: ProjectiveCurve;

impl<C> codec::Decode for Group<C>
where
    C: ProjectiveCurve,
{
    type Error = SerializationError;

    #[inline]
    fn decode<R>(reader: R) -> Result<Self, codec::DecodeError<R::Error, Self::Error>>
    where
        R: codec::Read,
    {
        let mut reader = arkworks::codec::ArkReader::new(reader);
        match CanonicalDeserialize::deserialize(&mut reader) {
            Ok(value) => reader
                .finish()
                .map(move |_| Self(value))
                .map_err(codec::DecodeError::Read),
            Err(err) => Err(codec::DecodeError::Decode(err)),
        }
    }
}

impl<C> codec::Encode for Group<C>
where
    C: ProjectiveCurve,
{
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: codec::Write,
    {
        let mut writer = arkworks::codec::ArkWriter::new(writer);
        let _ = self.0.serialize(&mut writer);
        writer.finish().map(|_| ())
    }
}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl<C> scale_codec::Decode for Group<C>
where
    C: ProjectiveCurve,
{
    #[inline]
    fn decode<I>(input: &mut I) -> Result<Self, scale_codec::Error>
    where
        I: scale_codec::Input,
    {
        Ok(Self(
            CanonicalDeserialize::deserialize(arkworks::codec::ScaleCodecReader(input))
                .map_err(|_| "Deserialization Error")?,
        ))
    }
}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl<C> scale_codec::Encode for Group<C>
where
    C: ProjectiveCurve,
{
    #[inline]
    fn using_encoded<R, Encoder>(&self, f: Encoder) -> R
    where
        Encoder: FnOnce(&[u8]) -> R,
    {
        f(&affine_point_as_bytes::<C>(&self.0))
    }
}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl<C> scale_codec::EncodeLike for Group<C> where C: ProjectiveCurve {}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl<C> scale_codec::MaxEncodedLen for Group<C>
where
    C: ProjectiveCurve,
{
    #[inline]
    fn max_encoded_len() -> usize {
        // NOTE: In affine form, we have two base field elements to represent the point. The
        //       encoding uses a compressed representation, so we only need to include half as many
        //       bytes. We add space for an extra byte flag in case we need to keep track of
        //       "infinity".
        Fp::<C::BaseField>::max_encoded_len() + 1
    }
}

#[cfg(feature = "scale")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "scale")))]
impl<C> scale_info::TypeInfo for Group<C>
where
    C: ProjectiveCurve,
{
    type Identity = [u8];

    #[inline]
    fn type_info() -> scale_info::Type {
        Self::Identity::type_info()
    }
}

impl<C> AsBytes for Group<C>
where
    C: ProjectiveCurve,
{
    #[inline]
    fn as_bytes(&self) -> Vec<u8> {
        affine_point_as_bytes::<C>(&self.0)
    }
}

impl<C> algebra::Group for Group<C>
where
    C: ProjectiveCurve,
{
    #[inline]
    fn add(&self, rhs: &Self, _: &mut ()) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl<C> algebra::ScalarMul<Scalar<C>> for Group<C>
where
    C: ProjectiveCurve,
{
    type Output = Self;

    #[inline]
    fn scalar_mul(&self, scalar: &Scalar<C>, _: &mut ()) -> Self::Output {
        Self(self.0.mul(scalar.0.into_repr()).into())
    }
}

/// Discrete Logarithm Hardness
///
/// We assume that the DL problem is hard for all `arkworks` implementations of elliptic curves.
impl<C> algebra::security::DiscreteLogarithmHardness for Group<C> where C: ProjectiveCurve {}

/// Computational Diffie-Hellman Hardness
///
/// We assume that the CDH problem is hard for all `arkworks` implementations of elliptic curves.
impl<C> algebra::security::ComputationalDiffieHellmanHardness for Group<C> where C: ProjectiveCurve {}

impl<C> Sample for Group<C>
where
    C: ProjectiveCurve,
{
    #[inline]
    fn sample<R>(_: (), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self(C::rand(rng).into())
    }
}

impl<C> TryFrom<Vec<u8>> for Group<C>
where
    C: ProjectiveCurve,
{
    type Error = SerializationError;

    #[inline]
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        CanonicalDeserialize::deserialize(&mut bytes.as_slice()).map(Self)
    }
}

impl<C> ConditionalSelect for Group<C>
where
    C: ProjectiveCurve,
{
    #[inline]
    fn select(bit: &Bool<()>, true_value: &Self, false_value: &Self, compiler: &mut ()) -> Self {
        let _ = compiler;
        if *bit {
            *true_value
        } else {
            *false_value
        }
    }
}

impl<C> cmp::PartialEq<Self> for Group<C>
where
    C: ProjectiveCurve,
{
    #[inline]
    fn eq(&self, rhs: &Self, compiler: &mut ()) -> Bool<()> {
        let _ = compiler;
        self == rhs
    }
}

impl<C> Zero for Group<C>
where
    C: ProjectiveCurve,
{
    type Verification = bool;

    #[inline]
    fn zero(compiler: &mut ()) -> Self {
        let _ = compiler;
        Self(C::Affine::zero())
    }

    #[inline]
    fn is_zero(&self, compiler: &mut ()) -> Self::Verification {
        let _ = compiler;
        C::Affine::is_zero(&self.0)
    }
}

/// Elliptic Curve Scalar Element Variable
///
/// # Safety
///
/// This type can only be used whenever the embedded scalar field is **smaller** than the
/// outer scalar field.
pub struct ScalarVar<C, CV>(pub(crate) FpVar<ConstraintField<C>>, PhantomData<CV>)
where
    C: ProjectiveCurve,
    CV: CurveVar<C, ConstraintField<C>>;

impl<C, CV> ScalarVar<C, CV>
where
    C: ProjectiveCurve,
    CV: CurveVar<C, ConstraintField<C>>,
{
    /// Builds a new [`ScalarVar`] from a given `scalar`.
    #[inline]
    fn new(scalar: FpVar<ConstraintField<C>>) -> Self {
        Self(scalar, PhantomData)
    }
}

impl<C, CV> algebra::Group<Compiler<C>> for ScalarVar<C, CV>
where
    C: ProjectiveCurve,
    CV: CurveVar<C, ConstraintField<C>>,
{
    #[inline]
    fn add(&self, rhs: &Self, compiler: &mut Compiler<C>) -> Self {
        let _ = compiler;
        Self::new(&self.0 + &rhs.0)
    }
}

impl<C, CV> algebra::Ring<Compiler<C>> for ScalarVar<C, CV>
where
    C: ProjectiveCurve,
    CV: CurveVar<C, ConstraintField<C>>,
{
    #[inline]
    fn mul(&self, rhs: &Self, compiler: &mut Compiler<C>) -> Self {
        let _ = compiler;
        Self::new(&self.0 * &rhs.0)
    }
}

impl<C, CV> Constant<Compiler<C>> for ScalarVar<C, CV>
where
    C: ProjectiveCurve,
    CV: CurveVar<C, ConstraintField<C>>,
{
    type Type = Scalar<C>;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut Compiler<C>) -> Self {
        Self::new(lift_embedded_scalar::<C>(this).as_constant(compiler))
    }
}

impl<C, CV> Variable<Public, Compiler<C>> for ScalarVar<C, CV>
where
    C: ProjectiveCurve,
    CV: CurveVar<C, ConstraintField<C>>,
{
    type Type = Scalar<C>;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut Compiler<C>) -> Self {
        Self::new(lift_embedded_scalar::<C>(this).as_known::<Public, _>(compiler))
    }

    #[inline]
    fn new_unknown(compiler: &mut Compiler<C>) -> Self {
        Self::new(compiler.allocate_unknown::<Public, _>())
    }
}

impl<C, CV> Variable<Secret, Compiler<C>> for ScalarVar<C, CV>
where
    C: ProjectiveCurve,
    CV: CurveVar<C, ConstraintField<C>>,
{
    type Type = Scalar<C>;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut Compiler<C>) -> Self {
        Self::new(lift_embedded_scalar::<C>(this).as_known::<Secret, _>(compiler))
    }

    #[inline]
    fn new_unknown(compiler: &mut Compiler<C>) -> Self {
        Self::new(compiler.allocate_unknown::<Secret, _>())
    }
}

/// Elliptic Curve Group Element Variable
#[derive(derivative::Derivative)]
#[derivative(Clone)]
pub struct GroupVar<C, CV>(pub(crate) CV, PhantomData<C>)
where
    C: ProjectiveCurve,
    CV: CurveVar<C, ConstraintField<C>>;

impl<C, CV> GroupVar<C, CV>
where
    C: ProjectiveCurve,
    CV: CurveVar<C, ConstraintField<C>>,
{
    /// Builds a new [`GroupVar`] from a given `point`.
    #[inline]
    fn new(point: CV) -> Self {
        Self(point, PhantomData)
    }
}

impl<C, CV> algebra::Group<Compiler<C>> for GroupVar<C, CV>
where
    C: ProjectiveCurve,
    CV: CurveVar<C, ConstraintField<C>>,
{
    #[inline]
    fn add(&self, rhs: &Self, compiler: &mut Compiler<C>) -> Self {
        let _ = compiler;
        let mut result = self.0.clone();
        result += &rhs.0;
        Self::new(result)
    }

    #[inline]
    fn double_assign(&mut self, compiler: &mut Compiler<C>) -> &mut Self {
        let _ = compiler;
        self.0
            .double_in_place()
            .expect("Doubling is not allowed to fail.");
        self
    }
}

impl<C, CV> algebra::ScalarMul<ScalarVar<C, CV>, Compiler<C>> for GroupVar<C, CV>
where
    C: ProjectiveCurve,
    CV: CurveVar<C, ConstraintField<C>>,
{
    type Output = Self;

    #[inline]
    fn scalar_mul(&self, scalar: &ScalarVar<C, CV>, compiler: &mut Compiler<C>) -> Self::Output {
        let _ = compiler;
        Self::new(
            self.0
                .scalar_mul_le(
                    scalar
                        .0
                        .to_bits_le()
                        .expect("Bit decomposition is not allowed to fail.")
                        .iter(),
                )
                .expect("Scalar multiplication is not allowed to fail."),
        )
    }
}

/// Discrete Logarithm Hardness
///
/// We assume that the DL problem is hard for all `arkworks` implementations of elliptic curves.
impl<C, CV> algebra::security::DiscreteLogarithmHardness for GroupVar<C, CV>
where
    C: ProjectiveCurve,
    CV: CurveVar<C, ConstraintField<C>>,
{
}

/// Computational Diffie-Hellman Hardness
///
/// We assume that the CDH problem is hard for all `arkworks` implementations of elliptic curves.
impl<C, CV> algebra::security::ComputationalDiffieHellmanHardness for GroupVar<C, CV>
where
    C: ProjectiveCurve,
    CV: CurveVar<C, ConstraintField<C>>,
{
}

impl<C, CV> eclair::cmp::PartialEq<Self, Compiler<C>> for GroupVar<C, CV>
where
    C: ProjectiveCurve,
    CV: CurveVar<C, ConstraintField<C>>,
{
    #[inline]
    fn eq(&self, rhs: &Self, compiler: &mut Compiler<C>) -> Boolean<ConstraintField<C>> {
        let _ = compiler;
        self.0
            .is_eq(&rhs.0)
            .expect("Equality checking is not allowed to fail.")
    }
}

impl<C, CV> ConditionalSelect<Compiler<C>> for GroupVar<C, CV>
where
    C: ProjectiveCurve,
    CV: CurveVar<C, ConstraintField<C>>,
{
    #[inline]
    fn select(
        bit: &Bool<Compiler<C>>,
        true_value: &Self,
        false_value: &Self,
        compiler: &mut Compiler<C>,
    ) -> Self {
        let _ = compiler;
        Self::new(conditionally_select(bit, &true_value.0, &false_value.0))
    }
}

impl<C, CV> Zero<Compiler<C>> for GroupVar<C, CV>
where
    C: ProjectiveCurve,
    CV: CurveVar<C, ConstraintField<C>>,
{
    type Verification = Bool<Compiler<C>>;

    #[inline]
    fn zero(compiler: &mut Compiler<C>) -> Self {
        let _ = compiler;
        Self::new(CV::zero())
    }

    #[inline]
    fn is_zero(&self, compiler: &mut Compiler<C>) -> Self::Verification {
        let _ = compiler;
        self.0
            .is_zero()
            .expect("Comparison with zero is not allowed to fail.")
    }
}

impl<C, CV> Constant<Compiler<C>> for GroupVar<C, CV>
where
    C: ProjectiveCurve,
    CV: CurveVar<C, ConstraintField<C>>,
{
    type Type = Group<C>;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut Compiler<C>) -> Self {
        Self::new(
            CV::new_constant(ns!(compiler.cs, "embedded curve point constant"), this.0)
                .expect("Variable allocation is not allowed to fail."),
        )
    }
}

impl<C, CV> Variable<Public, Compiler<C>> for GroupVar<C, CV>
where
    C: ProjectiveCurve,
    CV: CurveVar<C, ConstraintField<C>>,
{
    type Type = Group<C>;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut Compiler<C>) -> Self {
        Self::new(
            CV::new_input(
                ns!(compiler.cs, "embedded curve point public input"),
                full(this.0),
            )
            .expect("Variable allocation is not allowed to fail."),
        )
    }

    #[inline]
    fn new_unknown(compiler: &mut Compiler<C>) -> Self {
        Self::new(
            CV::new_input(
                ns!(compiler.cs, "embedded curve point public input"),
                empty::<C>,
            )
            .expect("Variable allocation is not allowed to fail."),
        )
    }
}

impl<C, CV> Variable<Secret, Compiler<C>> for GroupVar<C, CV>
where
    C: ProjectiveCurve,
    CV: CurveVar<C, ConstraintField<C>>,
{
    type Type = Group<C>;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut Compiler<C>) -> Self {
        Self::new(
            CV::new_witness(
                ns!(compiler.cs, "embedded curve point secret witness"),
                full(this.0),
            )
            .expect("Variable allocation is not allowed to fail."),
        )
    }

    #[inline]
    fn new_unknown(compiler: &mut Compiler<C>) -> Self {
        Self::new(
            CV::new_witness(
                ns!(compiler.cs, "embedded curve point secret witness"),
                empty::<C>,
            )
            .expect("Variable allocation is not allowed to fail."),
        )
    }
}

impl<C, CV> FixedBaseScalarMul<ScalarVar<C, CV>, Compiler<C>> for GroupVar<C, CV>
where
    C: ProjectiveCurve,
    CV: CurveVar<C, ConstraintField<C>>,
{
    type Base = Group<C>;

    #[inline]
    fn fixed_base_scalar_mul<I>(
        precomputed_bases: I,
        scalar: &ScalarVar<C, CV>,
        compiler: &mut Compiler<C>,
    ) -> Self
    where
        I: IntoIterator,
        I::Item: Borrow<Self::Base>,
    {
        let _ = compiler;
        let mut result = CV::zero();
        let scalar_bits = scalar
            .0
            .to_bits_le()
            .expect("Bit decomposition is not allowed to fail.");
        for (bit, base) in scalar_bits.into_iter().zip(precomputed_bases.into_iter()) {
            result = bit
                .select(&(result.clone() + base.borrow().0.into()), &result)
                .expect("Conditional select is not allowed to fail. ");
        }
        Self::new(result)
    }
}

/// Testing Suite
#[cfg(test)]
mod test {
    use super::*;
    use crate::config::Bls12_381_Edwards;
    use manta_crypto::{
        algebra::{test::window_correctness, PrecomputedBaseTable, ScalarMul},
        arkworks::{algebra::scalar_bits, r1cs_std::groups::curves::twisted_edwards::AffineVar},
        constraint::measure::Measure,
        eclair::bool::AssertEq,
        rand::OsRng,
    };

    /// Checks if the fixed base multiplcation is correct.
    #[test]
    fn fixed_base_mul_is_correct() {
        let mut cs = Compiler::<Bls12_381_Edwards>::for_proofs();
        let scalar = Scalar::<Bls12_381_Edwards>::gen(&mut OsRng);
        let base = Group::<Bls12_381_Edwards>::sample((), &mut OsRng);
        const SCALAR_BITS: usize = scalar_bits::<Bls12_381_Edwards>();
        let precomputed_table = PrecomputedBaseTable::<_, SCALAR_BITS>::from_base(base, &mut ());
        let base_var =
            base.as_known::<Secret, GroupVar<Bls12_381_Edwards, AffineVar<_, _>>>(&mut cs);
        let scalar_var =
            scalar.as_known::<Secret, ScalarVar<Bls12_381_Edwards, AffineVar<_, _>>>(&mut cs);
        let ctr1 = cs.constraint_count();
        let expected = base_var.scalar_mul(&scalar_var, &mut cs);
        let ctr2 = cs.constraint_count();
        let actual = GroupVar::fixed_base_scalar_mul(precomputed_table, &scalar_var, &mut cs);
        let ctr3 = cs.constraint_count();
        cs.assert_eq(&expected, &actual);
        assert!(cs.is_satisfied());
        println!("variable base mul constraint: {:?}", ctr2 - ctr1);
        println!("fixed base mul constraint: {:?}", ctr3 - ctr2);
    }

    /// Checks if the windowed multiplication is correct in the native compiler.
    #[test]
    fn windowed_mul_is_correct() {
        window_correctness(
            4,
            &Scalar::<Bls12_381_Edwards>::gen(&mut OsRng),
            Group::<Bls12_381_Edwards>::gen(&mut OsRng),
            |scalar, _| scalar.0.into_repr().to_bits_be(),
            &mut (),
        );
    }
}
