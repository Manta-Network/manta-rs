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

//! Elliptic Curve Cryptography

// TODO: Improve ECC abstractions over arkworks.

///
pub trait Coordinates<C, J = ()>
where
    C: Curve<J>,
{
}

/// Elliptic Curve
pub trait Curve<J = ()> {
    /// Base Field
    type BaseField;

    /// Scalar Field
    type ScalarField;
}

/// Embedded Elliptic Curve
pub trait EmbeddedCurve<C, J = ()>: Curve<J, BaseField = C::ScalarField>
where
    C: Curve<J>,
{
    ///
    fn lift_scalar(compiler: &mut J, scalar: Self::ScalarField) -> C::ScalarField;
}
