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

use core::{fmt::Debug, hash::Hash, marker::PhantomData};
use manta_crypto::commitment::CommitmentScheme;

/// Pedersen Commitment Specification
pub trait Specification<J = ()> {
    /// Group Type
    type Group;

    /// Scalar Field Type
    type Scalar;

    /// Adds two points of the group together.
    fn add(compiler: &mut J, lhs: Self::Group, rhs: Self::Group) -> Self::Group;

    /// Multiplies the given `point` with a `scalar` value.
    fn scalar_mul(compiler: &mut J, point: &Self::Group, scalar: &Self::Scalar) -> Self::Group;

    /// Computes the Pedersen Commitment with `parameters` over `trapdoor` and `input` in the given
    /// `compiler`.
    #[inline]
    fn commit<const ARITY: usize>(
        compiler: &mut J,
        parameters: &Parameters<Self, J, ARITY>,
        trapdoor: &Self::Scalar,
        input: &[Self::Scalar; ARITY],
    ) -> Self::Group {
        parameters.input_generators.iter().zip(input).fold(
            Self::scalar_mul(compiler, &parameters.trapdoor_generator, trapdoor),
            move |acc, (g, i)| {
                let point = Self::scalar_mul(compiler, g, i);
                Self::add(compiler, acc, point)
            },
        )
    }
}

/// Commitment Parameters
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "S::Group: Clone"),
    Copy(bound = "S::Group: Copy"),
    Debug(bound = "S::Group: Debug"),
    Eq(bound = "S::Group: Eq"),
    Hash(bound = "S::Group: Hash"),
    PartialEq(bound = "S::Group: PartialEq")
)]
pub struct Parameters<S, J = (), const ARITY: usize = 1>
where
    S: Specification<J> + ?Sized,
{
    /// Trapdoor Generator
    pub trapdoor_generator: S::Group,

    /// Input Generators
    pub input_generators: [S::Group; ARITY],
}

/// Commitment Scheme
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Commitment<S, J = (), const ARITY: usize = 1>(PhantomData<(J, S)>)
where
    S: Specification<J>;

impl<S, J, const ARITY: usize> CommitmentScheme<J> for Commitment<S, J, ARITY>
where
    S: Specification<J>,
{
    type Parameters = Parameters<S, J, ARITY>;

    type Trapdoor = S::Scalar;

    type Input = [S::Scalar; ARITY];

    type Output = S::Group;

    #[inline]
    fn commit(
        compiler: &mut J,
        parameters: &Self::Parameters,
        trapdoor: &Self::Trapdoor,
        input: &Self::Input,
    ) -> Self::Output {
        S::commit(compiler, parameters, trapdoor, input)
    }
}

/// Pedersen Commitment Trapdoor Type
pub type Trapdoor<S, J, const ARITY: usize> =
    <Commitment<S, J, ARITY> as CommitmentScheme<J>>::Trapdoor;

/// Pedersen Commitment Input Type
pub type Input<S, J, const ARITY: usize> = <Commitment<S, J, ARITY> as CommitmentScheme<J>>::Input;

/// Pedersen Commitment Output Type
pub type Output<S, J, const ARITY: usize> =
    <Commitment<S, J, ARITY> as CommitmentScheme<J>>::Output;

/// Arkworks Backend
#[cfg(feature = "arkworks")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "arkworks")))]
pub mod arkworks {
    use super::*;
    use ark_ec::ProjectiveCurve;
    use ark_ff::PrimeField;

    /// Pedersen Commitment Specification
    #[derive(derivative::Derivative)]
    #[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct Specification<C>(PhantomData<C>)
    where
        C: ProjectiveCurve;

    impl<C> super::Specification for Specification<C>
    where
        C: ProjectiveCurve,
    {
        type Group = C;

        type Scalar = C::ScalarField;

        #[inline]
        fn add(_: &mut (), lhs: Self::Group, rhs: Self::Group) -> Self::Group {
            lhs + rhs
        }

        #[inline]
        fn scalar_mul(_: &mut (), point: &Self::Group, scalar: &Self::Scalar) -> Self::Group {
            point.mul(scalar.into_repr())
        }
    }
}
