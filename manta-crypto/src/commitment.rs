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

//! Commitment Schemes

use core::{fmt::Debug, hash::Hash};

/// Commitment Scheme
pub trait CommitmentScheme {
    /// Parameters Type
    type Parameters;

    /// Trapdoor Type
    type Trapdoor;

    /// Input Type
    type Input;

    /// Output Type
    type Output;

    /// Commits to the `input` value using `parameters` and randomness `trapdoor`.
    fn commit(
        parameters: &Self::Parameters,
        trapdoor: &Self::Trapdoor,
        input: &Self::Input,
    ) -> Self::Output;

    /// Starts a new [`Builder`] for extended commitments.
    #[inline]
    fn start<'c>(
        parameters: &'c Self::Parameters,
        trapdoor: &'c Self::Trapdoor,
    ) -> Builder<'c, Self>
    where
        Self::Input: Default,
    {
        Builder::new(parameters, trapdoor)
    }
}

/// Commitment Extended Input
pub trait Input<T>
where
    T: ?Sized,
{
    /// Extends `self` with input data `next`.
    fn extend(&mut self, next: &T);
}

/// Commitment Builder
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "C::Input: Clone"),
    Copy(bound = "C::Input: Copy"),
    Debug(bound = "C::Parameters: Debug, C::Trapdoor: Debug, C::Input: Debug"),
    Eq(bound = "C::Parameters: Eq, C::Trapdoor: Eq, C::Input: Eq"),
    Hash(bound = "C::Parameters: Hash, C::Trapdoor: Hash, C::Input: Hash"),
    PartialEq(bound = "C::Parameters: PartialEq, C::Trapdoor: PartialEq, C::Input: PartialEq")
)]
pub struct Builder<'c, C>
where
    C: CommitmentScheme + ?Sized,
    C::Input: Default,
{
    /// Commitment Parameters
    parameters: &'c C::Parameters,

    /// Commitment Trapdoor
    trapdoor: &'c C::Trapdoor,

    /// Commitment Input Accumulator
    input: C::Input,
}

impl<'c, C> Builder<'c, C>
where
    C: CommitmentScheme + ?Sized,
    C::Input: Default,
{
    /// Returns a new [`Builder`] with fixed `parameters` and `trapdoor`.
    #[inline]
    pub fn new(parameters: &'c C::Parameters, trapdoor: &'c C::Trapdoor) -> Self {
        Self {
            parameters,
            trapdoor,
            input: Default::default(),
        }
    }

    /// Updates the builder with the `next` input.
    #[inline]
    pub fn update<T>(mut self, next: &T) -> Self
    where
        T: ?Sized,
        C::Input: Input<T>,
    {
        self.input.extend(next);
        self
    }

    /// Updates the builder with each item in `iter`.
    #[inline]
    pub fn update_all<'t, T, I>(mut self, iter: I) -> Self
    where
        T: 't + ?Sized,
        I: IntoIterator<Item = &'t T>,
        C::Input: Input<T>,
    {
        for next in iter {
            self.input.extend(next);
        }
        self
    }

    /// Commits to the input stored in the builder.
    #[inline]
    pub fn commit(self) -> C::Output {
        C::commit(self.parameters, self.trapdoor, &self.input)
    }
}

/// Constraint System Gadgets
pub mod constraint {
    use super::Input;
    use crate::constraint::Variable;

    /// Commitment Scheme Gadget
    pub trait CommitmentScheme<C>
    where
        C: super::CommitmentScheme,
    {
        /// Parameters Type
        type Parameters: Variable<Self, Type = C::Parameters>;

        /// Input Type
        type Input: Variable<Self, Type = C::Input>;

        /// Trapdoor Type
        type Trapdoor: Variable<Self, Type = C::Trapdoor>;

        /// Output Type
        type Output: Variable<Self, Type = C::Output>;

        /// Commits to the `input` value using `parameters` and randomness `trapdoor`.
        fn commit(
            &mut self,
            parameters: &Self::Parameters,
            trapdoor: &Self::Trapdoor,
            input: &Self::Input,
        ) -> Self::Output;

        /// Starts a new [`Builder`] for extended commitments.
        #[inline]
        fn start<'c>(
            parameters: &'c Self::Parameters,
            trapdoor: &'c Self::Trapdoor,
        ) -> Builder<'c, C, Self>
        where
            Self::Input: Default,
        {
            Builder::new(parameters, trapdoor)
        }
    }

    /// Commitment Builder
    pub struct Builder<'c, B, C>
    where
        B: super::CommitmentScheme,
        C: CommitmentScheme<B> + ?Sized,
        C::Input: Default,
    {
        /// Commitment Parameters
        parameters: &'c C::Parameters,

        /// Commitment Trapdoor
        trapdoor: &'c C::Trapdoor,

        /// Commitment Input Accumulator
        input: C::Input,
    }

    impl<'c, B, C> Builder<'c, B, C>
    where
        B: super::CommitmentScheme,
        C: CommitmentScheme<B> + ?Sized,
        C::Input: Default,
    {
        /// Returns a new [`Builder`] with fixed `parameters` and `trapdoor`.
        #[inline]
        pub fn new(parameters: &'c C::Parameters, trapdoor: &'c C::Trapdoor) -> Self {
            Self {
                parameters,
                trapdoor,
                input: Default::default(),
            }
        }

        /// Updates the builder with the `next` input.
        #[inline]
        pub fn update<T>(mut self, next: &T) -> Self
        where
            T: ?Sized,
            C::Input: Input<T>,
        {
            self.input.extend(next);
            self
        }

        /// Updates the builder with each item in `iter`.
        #[inline]
        pub fn update_all<'t, T, I>(mut self, iter: I) -> Self
        where
            T: 't + ?Sized,
            I: IntoIterator<Item = &'t T>,
            C::Input: Input<T>,
        {
            for next in iter {
                self.input.extend(next);
            }
            self
        }

        /// Commits to the input stored in the builder.
        #[inline]
        pub fn commit(self, cs: &mut C) -> C::Output {
            cs.commit(self.parameters, self.trapdoor, &self.input)
        }
    }
}
