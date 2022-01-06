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
    use crate::crypto::constraint::arkworks::{empty, full, Boolean, FpVar, R1CS};
    use alloc::vec::Vec;
    use ark_ec::ProjectiveCurve;
    use ark_ff::{Field, PrimeField};
    use ark_r1cs_std::{groups::CurveVar, ToBitsGadget};
    use ark_relations::ns;
    use core::marker::PhantomData;
    use manta_crypto::{
        constraint::{Constant, Equal, Public, Secret, Variable},
        ecc,
        key::kdf,
    };

    /// Constraint Field Type
    type ConstraintField<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;

    /// Compiler Type
    type Compiler<C> = R1CS<ConstraintField<C>>;

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
        type Scalar = C::ScalarField;

        #[inline]
        fn add(&self, rhs: &Self, _: &mut ()) -> Self {
            Self(self.0 + rhs.0)
        }

        #[inline]
        fn scalar_mul(&self, scalar: &Self::Scalar, _: &mut ()) -> Self {
            Self(self.0.mul(scalar.into_repr()))
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
        pub fn new(point: CV) -> Self {
            Self(point, PhantomData)
        }
    }

    impl<C, CV> ecc::Group<Compiler<C>> for GroupVar<C, CV>
    where
        C: ProjectiveCurve,
        CV: CurveVar<C, ConstraintField<C>>,
    {
        // FIXME: This should be a "subtype" of this field (whenever we have an actual injection).
        type Scalar = FpVar<ConstraintField<C>>;

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
