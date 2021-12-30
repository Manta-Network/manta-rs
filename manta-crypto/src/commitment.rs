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
pub trait CommitmentScheme<COM = ()> {
    /// Trapdoor Type
    type Trapdoor;

    /// Input Type
    type Input;

    /// Output Type
    type Output;

    /// Commits to the `input` value using randomness `trapdoor`.
    fn commit(
        &self,
        trapdoor: &Self::Trapdoor,
        input: &Self::Input,
        compiler: &mut COM,
    ) -> Self::Output;

    /// Starts a new [`Builder`] for extended commitments.
    #[inline]
    fn start<'c>(&'c self, trapdoor: &'c Self::Trapdoor) -> Builder<'c, Self, COM>
    where
        Self::Input: Default,
    {
        Builder::new(self, trapdoor)
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
    Debug(bound = "C: Debug, C::Trapdoor: Debug, C::Input: Debug"),
    Eq(bound = "C: Eq, C::Trapdoor: Eq, C::Input: Eq"),
    Hash(bound = "C: Hash, C::Trapdoor: Hash, C::Input: Hash"),
    PartialEq(bound = "C: PartialEq, C::Trapdoor: PartialEq, C::Input: PartialEq")
)]
pub struct Builder<'c, C, COM = ()>
where
    C: CommitmentScheme<COM> + ?Sized,
    C::Input: Default,
{
    /// Commitment Scheme
    commitment_scheme: &'c C,

    /// Commitment Trapdoor
    trapdoor: &'c C::Trapdoor,

    /// Commitment Input Accumulator
    input: C::Input,
}

impl<'c, C, COM> Builder<'c, C, COM>
where
    C: CommitmentScheme<COM> + ?Sized,
    C::Input: Default,
{
    /// Returns a new [`Builder`] with fixed `commitment_scheme` and `trapdoor`.
    #[inline]
    pub fn new(commitment_scheme: &'c C, trapdoor: &'c C::Trapdoor) -> Self {
        Self {
            commitment_scheme,
            trapdoor,
            input: Default::default(),
        }
    }

    /// Updates the builder with the `next` input.
    #[inline]
    #[must_use]
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
    #[must_use]
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
    pub fn commit_with_compiler(self, compiler: &mut COM) -> C::Output {
        self.commitment_scheme
            .commit(self.trapdoor, &self.input, compiler)
    }
}

impl<'c, C> Builder<'c, C>
where
    C: CommitmentScheme + ?Sized,
    C::Input: Default,
{
    /// Commits to the input stored in the builder.
    #[inline]
    pub fn commit(self) -> C::Output {
        self.commit_with_compiler(&mut ())
    }
}
