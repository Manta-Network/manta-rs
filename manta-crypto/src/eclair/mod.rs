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

//! **_ECLAIR_**: Embedded Circuit Language And Intermediate Representation

use manta_util::{create_seal, seal};

pub mod alloc;
pub mod bool;
pub mod cmp;
pub mod execution;
pub mod measure;
pub mod ops;

/// Native Compiler Marker Trait
///
/// This `trait` is only implemented for `()`, the default native compiler.
pub trait Native: sealed::Sealed {
    /// Returns an instance of the native compiler.
    fn compiler() -> Self;
}

create_seal! {}
seal! { () }

impl Native for () {
    #[inline]
    fn compiler() -> Self {}
}

/// Compiler Type Introspection
pub trait Has<T> {
    /// Compiler Type
    ///
    /// This type represents the allocation of `T` into `Self` as a compiler. Whenever we need to
    /// define absractions that require the compiler to have access to some type internally, we can
    /// use this `trait` as a requirement of that abstraction.
    ///
    /// See the [`bool`](crate::eclair::bool) module for an example of how to use introspection.
    type Type;
}

/* FIXME: We cannot implement this yet.
impl<T> Has<T> for () {
    type Type = T;
}
*/
