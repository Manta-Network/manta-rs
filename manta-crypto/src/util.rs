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

//! Utilities

use core::{fmt::Debug, hash::Hash};

/// Extended Input
pub trait Input<T>
where
    T: ?Sized,
{
    /// Extends `self` with input data `next`.
    fn extend(&mut self, next: &T);
}

/// Extended Input Builder
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "I: Clone"),
    Copy(bound = "I: Copy"),
    Debug(bound = "F: Debug, I: Debug, Args: Debug"),
    Eq(bound = "F: Eq, I: Eq, Args: Eq"),
    Hash(bound = "F: Hash, I: Hash, Args: Hash"),
    PartialEq(bound = "F: PartialEq, I: PartialEq, Args: PartialEq")
)]
pub struct Builder<'f, F, I, Args = ()>
where
    F: ?Sized,
    Args: ?Sized,
{
    /// Base Construction
    pub(crate) base: &'f F,

    /// Stored Arguments
    pub(crate) args: &'f Args,

    /// Input Data
    pub(crate) input: I,
}

impl<'f, F, I, Args> Builder<'f, F, I, Args>
where
    F: ?Sized,
    Args: ?Sized,
{
    /// Returns a new [`Builder`] for the given `base`.
    #[inline]
    pub(crate) fn new(base: &'f F, args: &'f Args) -> Self
    where
        I: Default,
    {
        Self {
            base,
            args,
            input: Default::default(),
        }
    }

    /// Updates the builder with the `next` input.
    #[inline]
    #[must_use]
    pub fn update<T>(mut self, next: &T) -> Self
    where
        T: ?Sized,
        I: Input<T>,
    {
        self.input.extend(next);
        self
    }

    /// Updates the builder with each item in `iter`.
    #[inline]
    #[must_use]
    pub fn update_all<'t, T, Iter>(mut self, iter: Iter) -> Self
    where
        T: 't + ?Sized,
        Iter: IntoIterator<Item = &'t T>,
        I: Input<T>,
    {
        for next in iter {
            self.input.extend(next);
        }
        self
    }
}
