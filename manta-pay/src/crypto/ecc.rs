// Copyright 2019-2021 Manta Network.
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

//! Elliptic Curve Primitives

/// Arkworks Backend
#[cfg(feature = "arkworks")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "arkworks")))]
pub mod arkworks {
    use crate::crypto::constraint::arkworks::{empty, full, Boolean, Fp, FpVar, R1CS};
    use alloc::vec::Vec;
    use ark_ff::{BigInteger, Field, FpParameters, PrimeField};
    use ark_r1cs_std::ToBitsGadget;
    use ark_relations::ns;
    use core::marker::PhantomData;
    use manta_crypto::{
        constraint::{Allocator, Constant, Equal, Public, Secret, ValueSource, Variable},
        ecc,
        key::kdf,
        rand::{CryptoRng, RngCore, Sample, Standard},
    };

    pub use ark_ec::ProjectiveCurve;
    pub use ark_r1cs_std::groups::CurveVar;

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

    /* TODO[remove]:
    /// Elliptic Curve Scalar Element
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct Scalar<C>(C::ScalarField)
    where
        C: ProjectiveCurve;

    impl<C> Sample for Scalar<C>
    where
        C: ProjectiveCurve,
    {
        #[inline]
        fn sample<R>(distribution: Standard, rng: &mut R) -> Self
        where
            R: CryptoRng + RngCore + ?Sized,
        {
            let _ = distribution;
            Self(C::ScalarField::rand(rng))
        }
    }
    */

    /// Elliptic Curve Group Element
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct Group<C>(pub(crate) C)
    where
        C: ProjectiveCurve;

    impl<C> kdf::AsBytes for Group<C>
    where
        C: ProjectiveCurve,
    {
        #[inline]
        fn as_bytes(&self) -> Vec<u8> {
            ark_ff::to_bytes!(&self.0).expect("Byte conversion does not fail.")
        }
    }

    impl<C> ecc::Group for Group<C>
    where
        C: ProjectiveCurve,
    {
        type Scalar = Scalar<C>;

        #[inline]
        fn add(&self, rhs: &Self, _: &mut ()) -> Self {
            Self(self.0 + rhs.0)
        }

        #[inline]
        fn scalar_mul(&self, scalar: &Self::Scalar, _: &mut ()) -> Self {
            Self(self.0.mul(scalar.0.into_repr()))
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
            Self(C::rand(rng))
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

    impl<C, CV> ecc::Group<Compiler<C>> for GroupVar<C, CV>
    where
        C: ProjectiveCurve,
        CV: CurveVar<C, ConstraintField<C>>,
    {
        type Scalar = ScalarVar<C, CV>;

        #[inline]
        fn add(&self, rhs: &Self, compiler: &mut Compiler<C>) -> Self {
            let _ = compiler;
            Self(self.0.clone() + &rhs.0, PhantomData)
        }

        #[inline]
        fn scalar_mul(&self, scalar: &Self::Scalar, compiler: &mut Compiler<C>) -> Self {
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
                .expect("Equality check is not allowed to fail.")
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
}
