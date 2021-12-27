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

// TODO: Describe contract for `Group`.

use core::marker::PhantomData;
use manta_crypto::commitment::CommitmentScheme;

/// Pedersen Group
pub trait Group {
    /// Scalar Field Type
    type Scalar;

    /// Adds two points of the group together.
    fn add(lhs: Self, rhs: Self) -> Self;

    /// Multiplies the given `point` with a `scalar` value.
    fn scalar_mul(point: &Self, scalar: &Self::Scalar) -> Self;
}

/// Commitment Paramters
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Parameters<G, const ARITY: usize = 1>
where
    G: Group,
{
    /// Trapdoor Generator
    pub trapdoor_generator: G,

    /// Input Generators
    pub input_generators: [G; ARITY],
}

/// Commitment Scheme
pub struct Commitment<G, const ARITY: usize = 1>(PhantomData<G>)
where
    G: Group;

impl<G, const ARITY: usize> CommitmentScheme for Commitment<G, ARITY>
where
    G: Group,
{
    type Parameters = Parameters<G, ARITY>;

    type Trapdoor = G::Scalar;

    type Input = [G::Scalar; ARITY];

    type Output = G;

    #[inline]
    fn commit(
        parameters: &Self::Parameters,
        trapdoor: &Self::Trapdoor,
        input: &Self::Input,
    ) -> Self::Output {
        parameters.input_generators.iter().zip(input).fold(
            G::scalar_mul(&parameters.trapdoor_generator, trapdoor),
            move |acc, (g, i)| G::add(acc, G::scalar_mul(g, i)),
        )
    }
}

/// Constraint System Gadgets
pub mod constraint {}

/// Arkworks Backend
#[cfg(feature = "arkworks")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "arkworks")))]
pub mod arkworks {
    use ark_ec::ProjectiveCurve;
    use ark_ff::PrimeField;

    /// Pedersen Group Wrapper for a [`ProjectiveCurve`]
    pub struct Group<C>(C)
    where
        C: ProjectiveCurve;

    impl<C> super::Group for Group<C>
    where
        C: ProjectiveCurve,
    {
        type Scalar = C::ScalarField;

        #[inline]
        fn add(lhs: Self, rhs: Self) -> Self {
            Self(lhs.0 + rhs.0)
        }

        #[inline]
        fn scalar_mul(point: &Self, scalar: &Self::Scalar) -> Self {
            Self(point.0.mul(scalar.into_repr()))
        }
    }
}
