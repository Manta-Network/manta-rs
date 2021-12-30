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

//! Pedersen Commitments

// TODO: Describe contract for `Specification`.

use core::{fmt::Debug, hash::Hash};
use manta_crypto::commitment::CommitmentScheme;

/// Pedersen Commitment Specification
pub trait Specification<COM = ()> {
    /// Group Type
    type Group;

    /// Scalar Field Type
    type Scalar;

    /// Adds two points of the group together.
    fn add(lhs: Self::Group, rhs: Self::Group, compiler: &mut COM) -> Self::Group;

    /// Multiplies the given `point` with a `scalar` value.
    fn scalar_mul(point: &Self::Group, scalar: &Self::Scalar, compiler: &mut COM) -> Self::Group;

    /// Computes the Pedersen Commitment with `parameters` over `trapdoor` and `input` in the given
    /// `compiler`.
    #[inline]
    fn commit<const ARITY: usize>(
        parameters: &Commitment<Self, COM, ARITY>,
        trapdoor: &Self::Scalar,
        input: &[Self::Scalar; ARITY],
        compiler: &mut COM,
    ) -> Self::Group {
        parameters.input_generators.iter().zip(input).fold(
            Self::scalar_mul(&parameters.trapdoor_generator, trapdoor, compiler),
            move |acc, (g, i)| {
                let point = Self::scalar_mul(g, i, compiler);
                Self::add(acc, point, compiler)
            },
        )
    }
}

/// Commitment Scheme
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "S::Group: Clone"),
    Copy(bound = "S::Group: Copy"),
    Debug(bound = "S::Group: Debug"),
    Eq(bound = "S::Group: Eq"),
    Hash(bound = "S::Group: Hash"),
    PartialEq(bound = "S::Group: PartialEq")
)]
pub struct Commitment<S, COM = (), const ARITY: usize = 1>
where
    S: Specification<COM> + ?Sized,
{
    /// Trapdoor Generator
    pub trapdoor_generator: S::Group,

    /// Input Generators
    pub input_generators: [S::Group; ARITY],
}

impl<S, COM, const ARITY: usize> CommitmentScheme<COM> for Commitment<S, COM, ARITY>
where
    S: Specification<COM>,
{
    type Trapdoor = S::Scalar;

    type Input = [S::Scalar; ARITY];

    type Output = S::Group;

    #[inline]
    fn commit(
        &self,
        trapdoor: &Self::Trapdoor,
        input: &Self::Input,
        compiler: &mut COM,
    ) -> Self::Output {
        S::commit(self, trapdoor, input, compiler)
    }
}

/// Pedersen Commitment Trapdoor Type
pub type Trapdoor<S, COM, const ARITY: usize> =
    <Commitment<S, COM, ARITY> as CommitmentScheme<COM>>::Trapdoor;

/// Pedersen Commitment Input Type
pub type Input<S, COM, const ARITY: usize> =
    <Commitment<S, COM, ARITY> as CommitmentScheme<COM>>::Input;

/// Pedersen Commitment Output Type
pub type Output<S, COM, const ARITY: usize> =
    <Commitment<S, COM, ARITY> as CommitmentScheme<COM>>::Output;

/// Arkworks Backend
#[cfg(feature = "arkworks")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "arkworks")))]
pub mod arkworks {
    use crate::crypto::constraint::arkworks::{FpVar, R1CS};
    use ark_ec::ProjectiveCurve;
    use ark_ff::{Field, PrimeField};
    use ark_r1cs_std::{groups::CurveVar, ToBitsGadget};
    use ark_relations::ns;
    use core::marker::PhantomData;
    use manta_crypto::constraint::{Allocation, Constant, Variable};
    use manta_util::fallible_array_map;

    /// Constraint Field Type
    type ConstraintField<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;

    /// Compiler Type
    type Compiler<C> = R1CS<ConstraintField<C>>;

    /// Pedersen Commitment Specification
    #[derive(derivative::Derivative)]
    #[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
        fn add(lhs: Self::Group, rhs: Self::Group, _: &mut ()) -> Self::Group {
            lhs + rhs
        }

        #[inline]
        fn scalar_mul(point: &Self::Group, scalar: &Self::Scalar, _: &mut ()) -> Self::Group {
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
        fn add(lhs: Self::Group, rhs: Self::Group, compiler: &mut Compiler<C>) -> Self::Group {
            let _ = compiler;
            lhs + rhs
        }

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

    impl<C, CV, const ARITY: usize> Variable<Compiler<C>>
        for super::Commitment<Specification<C, CV>, Compiler<C>, ARITY>
    where
        C: ProjectiveCurve,
        CV: CurveVar<C, ConstraintField<C>>,
    {
        type Type = super::Commitment<Specification<C, CV>, (), ARITY>;

        type Mode = Constant;

        #[inline]
        fn new(cs: &mut Compiler<C>, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
            match allocation {
                Allocation::Known(this, _) => Self {
                    trapdoor_generator: CV::new_constant(
                        ns!(cs.cs, "group element"),
                        this.trapdoor_generator,
                    )
                    .expect("Variable allocation is not allowed to fail."),
                    input_generators: fallible_array_map(this.input_generators, |g| {
                        CV::new_constant(ns!(cs.cs, "group element"), g)
                    })
                    .expect("Variable allocation is not allowed to fail."),
                },
                _ => unreachable!(),
            }
        }
    }
}
