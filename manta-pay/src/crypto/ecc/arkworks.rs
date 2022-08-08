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

use crate::crypto::constraint::arkworks::{self, empty, full, Boolean, Fp, FpVar, R1CS};
use alloc::vec::Vec;
use core::{iter::Extend, marker::PhantomData};
use manta_crypto::{
    algebra,
    arkworks::{
        algebra::{affine_point_as_bytes, modulus_is_smaller},
        ec::{AffineCurve, ProjectiveCurve},
        ff::{BigInteger, Field, PrimeField, ToConstraintField},
        r1cs_std::{groups::CurveVar, ToBitsGadget},
        relations::ns,
        serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError},
    },
    constraint::{Input, ProofSystem},
    eclair::{
        self,
        alloc::{
            mode::{Public, Secret},
            Allocate, Allocator, Constant, Variable,
        },
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
    pub C::Affine,
)
where
    C: ProjectiveCurve;

impl<C> ToConstraintField<ConstraintField<C>> for Group<C>
where
    C: ProjectiveCurve,
    C::Affine: ToConstraintField<ConstraintField<C>>,
{
    #[inline]
    fn to_field_elements(&self) -> Option<Vec<ConstraintField<C>>> {
        self.0.to_field_elements()
    }
}

impl<C, P> Input<P> for Group<C>
where
    C: ProjectiveCurve,
    C::Affine: ToConstraintField<ConstraintField<C>>,
    P: ProofSystem + ?Sized,
    P::Input: Extend<ConstraintField<C>>,
{
    #[inline]
    fn extend(&self, input: &mut P::Input) {
        if let Some(elements) = self.to_field_elements() {
            input.extend(elements);
        }
    }
}

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

impl<C> eclair::cmp::PartialEq<Self> for Group<C>
where
    C: ProjectiveCurve,
{
    #[inline]
    fn eq(&self, rhs: &Self, _: &mut ()) -> bool {
        PartialEq::eq(self, rhs)
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
    type Scalar = Scalar<C>;

    #[inline]
    fn add(&self, rhs: &Self, _: &mut ()) -> Self {
        Self(self.0 + rhs.0)
    }

    #[inline]
    fn mul(&self, scalar: &Self::Scalar, _: &mut ()) -> Self {
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

/// Elliptic Curve Scalar Element Variable
///
/// # Safety
///
/// This type can only be used whenever the embedded scalar field is **smaller** than the
/// outer scalar field.
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""))]
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
    pub fn new(scalar: FpVar<ConstraintField<C>>) -> Self {
        Self(scalar, PhantomData)
    }
}

impl<C, CV> algebra::Scalar<Compiler<C>> for ScalarVar<C, CV>
where
    C: ProjectiveCurve,
    CV: CurveVar<C, ConstraintField<C>>,
{
    #[inline]
    fn add(&self, rhs: &Self, compiler: &mut Compiler<C>) -> Self {
        let _ = compiler;
        Self::new(&self.0 + &rhs.0)
    }

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
    type Scalar = ScalarVar<C, CV>;

    #[inline]
    fn add(&self, rhs: &Self, compiler: &mut Compiler<C>) -> Self {
        let _ = compiler;
        let mut result = self.0.clone();
        result += &rhs.0;
        Self::new(result)
    }

    #[inline]
    fn mul(&self, scalar: &Self::Scalar, compiler: &mut Compiler<C>) -> Self {
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
