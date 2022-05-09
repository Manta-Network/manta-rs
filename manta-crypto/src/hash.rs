// Copyright 2019-2022 Manta Network.
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

//! Hash Functions

use crate::constraint::Native;

/// Unary Hash Function
pub trait UnaryHashFunction<COM = ()> {
    /// Input Type
    type Input: ?Sized;

    /// Output Type
    type Output;

    /// Computes the hash over `input` in the given `compiler`.
    fn hash_in(&self, input: &Self::Input, compiler: &mut COM) -> Self::Output;

    /// Computes the hash over `input`.
    #[inline]
    fn hash(&self, input: &Self::Input) -> Self::Output
    where
        COM: Native,
    {
        self.hash_in(input, &mut COM::compiler())
    }
}

impl<H, COM> UnaryHashFunction<COM> for &H
where
    H: UnaryHashFunction<COM>,
{
    type Input = H::Input;
    type Output = H::Output;

    #[inline]
    fn hash_in(&self, input: &Self::Input, compiler: &mut COM) -> Self::Output {
        (*self).hash_in(input, compiler)
    }

    #[inline]
    fn hash(&self, input: &Self::Input) -> Self::Output
    where
        COM: Native,
    {
        (*self).hash(input)
    }
}

/// Binary Hash Function
pub trait BinaryHashFunction<COM = ()> {
    /// Left Input Type
    type Left: ?Sized;

    /// Right Input Type
    type Right: ?Sized;

    /// Output Type
    type Output;

    /// Computes the hash over `lhs` and `rhs` in the given `compiler`.
    fn hash_in(&self, lhs: &Self::Left, rhs: &Self::Right, compiler: &mut COM) -> Self::Output;

    /// Computes the hash over `lhs` and `rhs`.
    #[inline]
    fn hash(&self, lhs: &Self::Left, rhs: &Self::Right) -> Self::Output
    where
        COM: Native,
    {
        self.hash_in(lhs, rhs, &mut COM::compiler())
    }
}

/// Array Hash Function
pub trait ArrayHashFunction<COM, const ARITY: usize> {
    /// Input Type
    type Input: ?Sized;

    /// Output Type
    type Output;

    /// Computes the hash over `input` in the given `compiler`.
    fn hash_in(&self, input: [&Self::Input; ARITY], compiler: &mut COM) -> Self::Output;

    /// Computes the hash over `input`.
    #[inline]
    fn hash(&self, input: [&Self::Input; ARITY]) -> Self::Output
    where
        COM: Native,
    {
        self.hash_in(input, &mut COM::compiler())
    }
}

/// Array Hashing Utilities
pub mod array {
    use super::*;
    use core::marker::PhantomData;

    #[cfg(feature = "serde")]
    use manta_util::serde::{Deserialize, Serialize};

    /// Converts `hasher` from an [`ArrayHashFunction`] into a [`UnaryHashFunction`].
    #[inline]
    pub fn as_unary<H, COM>(hasher: H) -> AsUnary<H, COM>
    where
        H: ArrayHashFunction<COM, 1>,
    {
        AsUnary::new(hasher)
    }

    /// Unary Hash Function Converter
    #[cfg_attr(
        feature = "serde",
        derive(Deserialize, Serialize),
        serde(crate = "manta_util::serde", deny_unknown_fields)
    )]
    #[derive(derivative::Derivative)]
    #[derivative(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct AsUnary<H, COM = ()>
    where
        H: ArrayHashFunction<COM, 1>,
    {
        /// Array Hasher
        hasher: H,

        /// Type Parameter Marker
        __: PhantomData<COM>,
    }

    impl<H, COM> AsUnary<H, COM>
    where
        H: ArrayHashFunction<COM, 1>,
    {
        /// Builds a new [`UnaryHashFunction`] implementation out of an [`ArrayHashFunction`]
        /// implementation `hasher`.
        #[inline]
        pub fn new(hasher: H) -> Self {
            Self {
                hasher,
                __: PhantomData,
            }
        }
    }

    impl<H, COM> UnaryHashFunction<COM> for AsUnary<H, COM>
    where
        H: ArrayHashFunction<COM, 1>,
    {
        type Input = H::Input;
        type Output = H::Output;

        #[inline]
        fn hash_in(&self, input: &Self::Input, compiler: &mut COM) -> Self::Output {
            self.hasher.hash_in([input], compiler)
        }

        #[inline]
        fn hash(&self, input: &Self::Input) -> Self::Output
        where
            COM: Native,
        {
            self.hasher.hash([input])
        }
    }
}
