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

//! Elliptic Curve Diffie Hellman

use manta_crypto::key::KeyAgreementScheme;

/// Elliptic Curve Diffie Hellman Specification
pub trait Specification<COM = ()> {
    /// Group Type
    type Group;

    /// Scalar Type
    type Scalar;

    /// Multiplies `point` by `scalar`.
    fn scalar_mul(point: &Self::Group, scalar: &Self::Scalar, compiler: &mut COM) -> Self::Group;
}

/// Key Agreement Protocol
pub struct KeyAgreement<S, COM = ()>
where
    S: Specification<COM>,
{
    /// Base Generator
    pub generator: S::Group,
}

impl<S, COM> KeyAgreementScheme<COM> for KeyAgreement<S, COM>
where
    S: Specification<COM>,
{
    type SecretKey = S::Scalar;

    type PublicKey = S::Group;

    type SharedSecret = S::Group;

    #[inline]
    fn derive(&self, secret_key: &Self::SecretKey, compiler: &mut COM) -> Self::PublicKey {
        S::scalar_mul(&self.generator, secret_key, compiler)
    }

    #[inline]
    fn agree(
        &self,
        secret_key: &Self::SecretKey,
        public_key: &Self::PublicKey,
        compiler: &mut COM,
    ) -> Self::SharedSecret {
        S::scalar_mul(public_key, secret_key, compiler)
    }
}

/// Arkworks Backend
#[cfg(feature = "arkworks")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "arkworks")))]
pub mod arkworks {
    use crate::crypto::constraint::arkworks::R1CS;
    use ark_ec::ProjectiveCurve;
    use ark_ff::{Field, PrimeField};
    use ark_r1cs_std::{fields::fp::FpVar, groups::CurveVar, ToBitsGadget};
    use ark_relations::ns;
    use core::marker::PhantomData;
    use manta_crypto::constraint::{Allocation, Constant, Variable};

    /// Constraint Field Type
    type ConstraintField<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;

    /// Compiler Type
    type Compiler<C> = R1CS<ConstraintField<C>>;

    /// Specification
    pub struct Specification<C, CV>(PhantomData<(C, CV)>)
    where
        C: ProjectiveCurve,
        CV: CurveVar<C, ConstraintField<C>>;

    impl<C, CV> super::Specification for Specification<C, CV>
    where
        C: ProjectiveCurve,
        CV: CurveVar<C, ConstraintField<C>>,
    {
        type Group = C;

        type Scalar = C::ScalarField;

        #[inline]
        fn scalar_mul(
            point: &Self::Group,
            scalar: &Self::Scalar,
            compiler: &mut (),
        ) -> Self::Group {
            let _ = compiler;
            point.mul(scalar.into_repr())
        }
    }

    impl<C, CV> super::Specification<Compiler<C>> for Specification<C, CV>
    where
        C: ProjectiveCurve,
        CV: CurveVar<C, ConstraintField<C>>,
    {
        type Group = CV;

        type Scalar = FpVar<ConstraintField<C>>;

        #[inline]
        fn scalar_mul(
            point: &Self::Group,
            scalar: &Self::Scalar,
            compiler: &mut Compiler<C>,
        ) -> Self::Group {
            let _ = compiler;
            point
                .scalar_mul_le(
                    scalar
                        .to_bits_le()
                        .expect("Bit decomposition is not allowed to fail.")
                        .iter(),
                )
                .expect("Scalar multiplication is not allowed to fail.")
        }
    }

    impl<C, CV> Variable<Compiler<C>> for super::KeyAgreement<Specification<C, CV>, Compiler<C>>
    where
        C: ProjectiveCurve,
        CV: CurveVar<C, ConstraintField<C>>,
    {
        type Type = super::KeyAgreement<Specification<C, CV>, ()>;

        type Mode = Constant;

        #[inline]
        fn new(cs: &mut Compiler<C>, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
            match allocation {
                Allocation::Known(this, _) => Self {
                    generator: CV::new_constant(ns!(cs.cs, "group element"), this.generator)
                        .expect("Variable allocation is not allowed to fail."),
                },
                _ => unreachable!(),
            }
        }
    }
}
