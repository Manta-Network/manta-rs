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

//! Algebraic Constructions

use crate::constraint::Native;

/// Field
pub trait Field<COM = ()>: Sized {
    /// Adds `rhs` to `self` inside of `compiler`.
    fn add_with(&self, rhs: &Self, compiler: &mut COM) -> Self;

    /// Adds `rhs` to `self`.
    #[inline]
    fn add(&self, rhs: &Self) -> Self
    where
        COM: Native,
    {
        self.add_with(rhs, &mut COM::compiler())
    }

    /// Multiplies `self` with `rhs` inside of `compiler`.
    fn mul_with(&self, rhs: &Self, compiler: &mut COM) -> Self;

    /// Multiplies `self` with `rhs`.
    #[inline]
    fn mul(&self, rhs: &Self) -> Self
    where
        COM: Native,
    {
        self.mul_with(rhs, &mut COM::compiler())
    }
}

/// Group
pub trait Group<COM = ()>: Sized {
    /// Scalar Field Type
    type Scalar: Field<COM>;

    /// Adds `rhs` to `self` returning another group point inside `compiler`.
    fn add_with(&self, rhs: &Self, compiler: &mut COM) -> Self;

    /// Adds `rhs` to `self` returning another group point.
    #[inline]
    fn add(&self, rhs: &Self) -> Self
    where
        COM: Native,
    {
        self.add_with(rhs, &mut COM::compiler())
    }

    /// Multiplies `self` by `scalar` returning another group point inside `compiler`.
    fn scalar_mul_with(&self, scalar: &Self::Scalar, compiler: &mut COM) -> Self;

    /// Multiplies `self` by `scalar` returning another group point.
    #[inline]
    fn scalar_mul(&self, scalar: &Self::Scalar) -> Self
    where
        COM: Native,
    {
        self.scalar_mul_with(scalar, &mut COM::compiler())
    }
}
