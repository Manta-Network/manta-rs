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

//! Conversion Utilities

use core::convert::Infallible;

/// The Never Type
///
/// This `type` will eventually be replaced by `!`, the primitive never type. See the ongoing
/// discussion for the [never_type #35121](https://github.com/rust-lang/rust/issues/35121) feature.
pub type Never = Infallible;

/// Promotes a [`Never`] value to another type.
#[inline]
pub fn never<T>(_: Never) -> T {
    unreachable!("This type never has any values, so this promotion is safe.")
}
