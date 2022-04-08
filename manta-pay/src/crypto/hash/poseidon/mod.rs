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

//! Poseidon Hash Function

use core::fmt::Debug;
use crate::crypto::hash::poseidon::constants::ParamField;

/// TODO doc
pub mod constants;
/// TODO doc
pub mod matrix;
#[cfg(feature = "arkworks")]
/// TODO doc
pub mod arkworks;

/// Specification for a Poseidon hash function.
pub trait Specification<const WIDTH: usize, COM = ()>{
    /// TODO doc
    type Field: Debug + Clone;
    /// TODO doc
    type ParameterField: ParamField;

    // TODO
}