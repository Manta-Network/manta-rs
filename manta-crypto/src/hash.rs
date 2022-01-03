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

//! Hash Functions

pub use crate::util::{Builder, Input};

/// Hash Function
pub trait HashFunction<COM = ()> {
    /// Input Type
    type Input: ?Sized;

    /// Output Type
    type Output;

    /// Performs a hash over `input` in the given `compiler`.
    fn hash(&self, input: &Self::Input, compiler: &mut COM) -> Self::Output;

    /// Starts a new [`Builder`] for extended hashes.
    #[inline]
    fn start(&self) -> Builder<Self, Self::Input>
    where
        Self::Input: Default,
    {
        Builder::new(self, &())
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

    /// Performs a hash over `lhs` and `rhs` in the given `compiler`.
    fn hash(&self, lhs: &Self::Left, rhs: &Self::Right, compiler: &mut COM) -> Self::Output;
}

impl<'h, H, I> Builder<'h, H, I> {
    /// Hashes the input stored in the builder against the given `compiler`.
    #[inline]
    pub fn hash_with_compiler<COM>(self, compiler: &mut COM) -> H::Output
    where
        H: HashFunction<COM, Input = I>,
    {
        self.base.hash(&self.input, compiler)
    }

    /// Hashes the input stored in the builder.
    #[inline]
    pub fn hash(self) -> H::Output
    where
        H: HashFunction<Input = I>,
    {
        self.hash_with_compiler(&mut ())
    }
}
