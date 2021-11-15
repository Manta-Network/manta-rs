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

// FIXME: Change this so that commiting one value is the default, and commiting a "concatenation"
//        of values is the special case.

use core::{fmt::Debug, hash::Hash};
use manta_util::{Concat, ConcatAccumulator};

/// Commitment Scheme
pub trait CommitmentScheme {
    /// Commitment Input Type
    type Input: Default;

    /// Commitment Trapdoor Parameter Type
    type Trapdoor;

    /// Commitment Output Type
    type Output;

    /// Returns a new [`Builder`] to build up a commitment.
    #[inline]
    fn start(&self) -> Builder<Self> {
        Builder::new(self)
    }

    /// Commits the `input` with the given `trapdoor` parameter.
    fn commit(&self, input: Self::Input, trapdoor: &Self::Trapdoor) -> Self::Output;

    /// Commits the single `input` value with the given `trapdoor` parameter.
    #[inline]
    fn commit_one<T>(&self, input: &T, trapdoor: &Self::Trapdoor) -> Self::Output
    where
        T: ?Sized,
        Self: Input<T>,
    {
        self.start().update(input).commit(trapdoor)
    }
}

/// Commitment Input
pub trait Input<T>: CommitmentScheme
where
    T: ?Sized,
{
    /// Extends the `input` with the `next` element.
    fn extend(input: &mut Self::Input, next: &T);
}

impl<C, T> Input<T> for C
where
    C: CommitmentScheme + ?Sized,
    C::Input: ConcatAccumulator<T::Item>,
    T: Concat + ?Sized,
{
    #[inline]
    fn extend(input: &mut Self::Input, next: &T) {
        next.concat(input);
    }
}

/// Commitment Builder
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "C::Input: Clone"),
    Copy(bound = "C::Input: Copy"),
    Debug(bound = "C: Debug, C::Input: Debug"),
    Eq(bound = "C: Eq, C::Input: Eq"),
    Hash(bound = "C: Hash, C::Input: Hash"),
    PartialEq(bound = "C: PartialEq, C::Input: PartialEq")
)]
pub struct Builder<'c, C>
where
    C: CommitmentScheme + ?Sized,
{
    /// Commitment Scheme
    commitment_scheme: &'c C,

    /// Commitment Input
    input: C::Input,
}

impl<'c, C> Builder<'c, C>
where
    C: CommitmentScheme + ?Sized,
{
    /// Returns a new [`Builder`] for this `commitment_scheme`.
    #[inline]
    pub fn new(commitment_scheme: &'c C) -> Self {
        Self {
            commitment_scheme,
            input: Default::default(),
        }
    }

    /// Updates the builder with the `next` input.
    #[inline]
    pub fn update<T>(mut self, next: &T) -> Self
    where
        T: ?Sized,
        C: Input<T>,
    {
        C::extend(&mut self.input, next);
        self
    }

    /// Commits to the input stored in the builder with the given `trapdoor`.
    #[inline]
    pub fn commit(self, trapdoor: &C::Trapdoor) -> C::Output {
        self.commitment_scheme.commit(self.input, trapdoor)
    }
}

/// Testing Framework
#[cfg(feature = "test")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "test")))]
pub mod test {
    use super::*;
    use core::fmt::Debug;

    /// Asserts that the given commitment `output` is equal to commiting `input` with `trapdoor`
    /// using the `commitment_scheme`.
    #[inline]
    pub fn assert_commitment_matches<T, C>(
        commitment_scheme: &C,
        input: &T,
        trapdoor: &C::Trapdoor,
        output: &C::Output,
    ) where
        T: ?Sized,
        C: CommitmentScheme + Input<T> + ?Sized,
        C::Output: Debug + PartialEq,
    {
        assert_eq!(&commitment_scheme.commit_one(input, trapdoor), output);
    }
}
