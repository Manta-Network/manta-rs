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
use ark_ff::{BigInteger, Field, FpParameters, PrimeField};
use ark_r1cs_std::ToBitsGadget;
use ark_relations::ns;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use core::marker::PhantomData;
use manta_crypto::{
    constraint::{Allocator, Constant, Equal, Public, Secret, ValueSource, Variable},
    ecc,
    key::kdf,
    rand::{CryptoRng, RngCore, Sample, Standard},
};
use manta_util::codec;

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize, Serializer};

pub use ark_ec::{AffineCurve, ProjectiveCurve};
pub use ark_r1cs_std::groups::CurveVar;
use manta_crypto::ecc::{PointAdd, PointDouble};

/// Constraint Field Type
type ConstraintField<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;

/// Compiler Type
type Compiler<C> = R1CS<ConstraintField<C>>;

/// Scalar Field Element
pub type Scalar<C> = Fp<<C as ProjectiveCurve>::ScalarField>;

/// Converts `scalar` to the bit representation of `O`.
#[inline]
pub fn convert_bits<T, O>(scalar: T) -> O::BigInt
where
    T: BigInteger,
    O: PrimeField,
{
    O::BigInt::from_bits_le(&scalar.to_bits_le())
}

/// Checks that the modulus of `A` is smaller than that of `B`.
#[inline]
pub fn modulus_is_smaller<A, B>() -> bool
where
    A: PrimeField,
    B: PrimeField,
{
    let modulus_a = A::Params::MODULUS;
    let modulus_b = B::Params::MODULUS;
    if modulus_a.num_bits() <= modulus_b.num_bits() {
        convert_bits::<_, B>(modulus_a) < modulus_b
    } else {
        modulus_a < convert_bits::<_, A>(modulus_b)
    }
}

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
        // NOTE: In affine form, we have two base field elements to represent the point. We add
        //       space for an extra byte flag in case we need to keep track of "infinity".
        2 * Fp::<C::BaseField>::max_encoded_len() + 1
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

impl<C> kdf::AsBytes for Group<C>
where
    C: ProjectiveCurve,
{
    #[inline]
    fn as_bytes(&self) -> Vec<u8> {
        affine_point_as_bytes::<C>(&self.0)
    }
}

impl<C> ecc::ScalarMul for Group<C>
where
    C: ProjectiveCurve,
{
    type Scalar = Scalar<C>;
    type Output = Self;

    #[inline]
    fn scalar_mul(&self, scalar: &Self::Scalar, _: &mut ()) -> Self::Output {
        Self(self.0.mul(scalar.0.into_repr()).into())
    }
}

impl<C> Sample for Group<C>
where
    C: ProjectiveCurve,
{
    #[inline]
    fn sample<R>(distribution: Standard, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let _ = distribution;
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

/// Converts `point` into its canonical byte-representation.
#[inline]
pub fn affine_point_as_bytes<C>(point: &C::Affine) -> Vec<u8>
where
    C: ProjectiveCurve,
{
    let mut buffer = Vec::new();
    point
        .serialize(&mut buffer)
        .expect("Serialization is not allowed to fail.");
    buffer
}

/// Uses `serializer` to serialize `point`.
#[cfg(feature = "serde")]
#[inline]
fn serialize_group_element<C, S>(point: &C::Affine, serializer: S) -> Result<S::Ok, S::Error>
where
    C: ProjectiveCurve,
    S: Serializer,
{
    serializer.serialize_bytes(&affine_point_as_bytes::<C>(point))
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
#[derive(Clone)]
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

impl<C, CV> ecc::ScalarMul<Compiler<C>> for GroupVar<C, CV>
where
    C: ProjectiveCurve,
    CV: CurveVar<C, ConstraintField<C>>,
{
    type Scalar = ScalarVar<C, CV>;
    type Output = Self;

    #[inline]
    fn scalar_mul(&self, scalar: &Self::Scalar, compiler: &mut Compiler<C>) -> Self::Output {
        let _ = compiler;
        Self(
            self.0
                .scalar_mul_le(
                    scalar
                        .0
                        .to_bits_le()
                        .expect("Bit decomposition is not allowed to fail.")
                        .iter(),
                )
                .expect("Scalar multiplication is not allowed to fail."),
            PhantomData,
        )
    }
}

macro_rules! impl_processed_scalar_mul {
    ($curve: ty) => {
        impl<CV>
            ecc::PreprocessedScalarMul<
                Compiler<$curve>,
                {
                    <<$curve as ProjectiveCurve>::ScalarField as PrimeField>::Params::MODULUS_BITS
                        as usize
                },
            > for GroupVar<$curve, CV>
        where
            CV: CurveVar<$curve, ConstraintField<$curve>>,
        {
            #[inline]
            fn preprocessed_scalar_mul(
                table: &[Self; {
                     <<$curve as ProjectiveCurve>::ScalarField as PrimeField>::Params::MODULUS_BITS
                         as usize
                 }],
                scalar: &Self::Scalar,
                compiler: &mut Compiler<$curve>,
            ) -> Self::Output {
                let _ = compiler;
                let mut result = CV::zero();
                let scalar_bits = scalar
                    .0
                    .to_bits_le()
                    .expect("Bit decomposition is not allowed to fail.");
                // TODO: Add `+` implementations, `conditional_add` to avoid unnecessary clones.
                for (bit, base) in scalar_bits.into_iter().zip(table.iter()) {
                    result = bit
                        .select(&(result.clone() + &base.0), &result)
                        .expect("Conditional select is not allowed to fail. ");
                }
                Self(result, PhantomData)
            }
        }
    };
}

impl_processed_scalar_mul!(ark_ed_on_bls12_381::EdwardsProjective);

impl<C, CV> Equal<Compiler<C>> for GroupVar<C, CV>
where
    C: ProjectiveCurve,
    CV: CurveVar<C, ConstraintField<C>>,
{
    #[inline]
    fn eq(lhs: &Self, rhs: &Self, compiler: &mut Compiler<C>) -> Boolean<ConstraintField<C>> {
        let _ = compiler;
        lhs.0
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

impl<C, CV> PointAdd<Compiler<C>> for GroupVar<C, CV>
where
    C: ProjectiveCurve,
    CV: CurveVar<C, ConstraintField<C>>,
{
    type Output = Self;

    fn add(&self, rhs: &Self, compiler: &mut Compiler<C>) -> Self::Output {
        let _ = compiler;
        let mut result = self.0.clone();
        result += &rhs.0;
        Self::new(result)
    }
}

impl<C, CV> PointDouble<Compiler<C>> for GroupVar<C, CV>
where
    C: ProjectiveCurve,
    CV: CurveVar<C, ConstraintField<C>>,
{
    type Output = Self;

    fn double(&self, compiler: &mut Compiler<C>) -> Self::Output {
        let _ = compiler;
        Self::new(self.0.double().expect("Doubling is not allowed to fail."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::ProjectiveCurve;
    use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective};
    use manta_crypto::{
        constraint::ConstraintSystem,
        ecc::{PreprocessedScalarMulTable, ScalarMul},
        rand::OsRng,
    };

    fn preprocessed_scalar_mul_test_template<C, CV, const N: usize>(rng: &mut OsRng)
    where
        C: ProjectiveCurve,
        CV: CurveVar<C, ConstraintField<C>>,
        GroupVar<C, CV>: ecc::PreprocessedScalarMul<
            Compiler<C>,
            N,
            Scalar = ScalarVar<C, CV>,
            Output = GroupVar<C, CV>,
        >,
    {
        const NUM_TRIALS: usize = 5;

        let mut cs = R1CS::for_known();

        for _ in 0..NUM_TRIALS {
            let base = Group::<C>::gen(rng);
            let base_var = <GroupVar<C, CV> as Variable<Secret, _>>::new_known(&base, &mut cs);

            let scalar = Scalar::<C>::gen(rng);
            let scalar_var = scalar.as_known::<Secret, ScalarVar<C, CV>>(&mut cs);

            let expected = ScalarMul::scalar_mul(&base_var, &scalar_var, &mut cs);

            let table = PreprocessedScalarMulTable::<_, N>::from_base(base_var, &mut cs);
            let actual = table.scalar_mul(&scalar_var, &mut cs);

            cs.assert_eq(&expected, &actual);
        }

        assert!(cs.cs.is_satisfied().unwrap());
    }

    #[test]
    fn preprocessed_scalar_mul_test() {
        macro_rules! test_on_curve {
            ($curve: ty, $var: ty, $rng: expr) => {
                preprocessed_scalar_mul_test_template::<
            $curve,
            $var,
            {
                <<$curve as ProjectiveCurve>::ScalarField as PrimeField>::Params::MODULUS_BITS as usize
            },
        >($rng)
            }
        }

        let mut rng = OsRng::default();
        test_on_curve!(EdwardsProjective, EdwardsVar, &mut rng);
    }
}
