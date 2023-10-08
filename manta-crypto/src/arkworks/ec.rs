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

//! Arkworks Elliptic Curves Backend

#[doc(inline)]
pub use ark_ec::*;

/// Affine Curve Extension
pub trait AffineCurveExt: AffineCurve {
    /// Returns the `x` coordinate of `self`.
    fn x(&self) -> &Self::BaseField;

    /// Returns the `y` coordinate of `self`.
    fn y(&self) -> &Self::BaseField;

    /// Builds [`Self`] from `x` and `y`.
    fn from_xy_unchecked(x: Self::BaseField, y: Self::BaseField) -> Self;
}

impl<P> AffineCurveExt for short_weierstrass_jacobian::GroupAffine<P>
where
    P: SWModelParameters,
{
    #[inline]
    fn x(&self) -> &Self::BaseField {
        &self.x
    }

    #[inline]
    fn y(&self) -> &Self::BaseField {
        &self.y
    }

    #[inline]
    fn from_xy_unchecked(x: Self::BaseField, y: Self::BaseField) -> Self {
        Self::new(x, y, false)
    }
}

impl<P> AffineCurveExt for twisted_edwards_extended::GroupAffine<P>
where
    P: TEModelParameters,
{
    #[inline]
    fn x(&self) -> &Self::BaseField {
        &self.x
    }

    #[inline]
    fn y(&self) -> &Self::BaseField {
        &self.y
    }

    #[inline]
    fn from_xy_unchecked(x: Self::BaseField, y: Self::BaseField) -> Self {
        Self::new(x, y)
    }
}
