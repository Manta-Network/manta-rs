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
pub mod num;
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

/// Non-Native Compiler Marker Trait
///
/// This `trait` is explicitly not implemented for `()`, the default native compiler. This marker
/// can be used to write explicitly different implementations for native and non-native compilers
/// where otherwise a generic implementation would have to exist.
///
/// # Limitations
///
/// This is an emulation of an unimplemented feature of rust called ["negative trait bounds"]. As it
/// currently stands, the compiler will make instances of [`NonNative`] outside of the ECLAIR crate
/// unusable as you'll run into [error 0119] which has the following notice:
///
/// ```text
/// note: upstream crates may add a new impl of trait `NonNative` for type `()` in future versions
/// ```
///
/// Even though this trait will never be implemented for `()`, there's no way the Rust compiler can
/// know this. As of right now, we can only use this `trait` internally to this crate.
///
/// ["negative trait bounds"]: https://doc.rust-lang.org/beta/unstable-book/language-features/negative-impls.html
/// [error 0119]: https://doc.rust-lang.org/error-index.html#E0119
pub trait NonNative {}

/// Compiler Type Introspection
pub trait Has<T> {
    /// Compiler Type
    ///
    /// This type represents the allocation of `T` into `Self` as a compiler. Whenever we need to
    /// define abstractions that require the compiler to have access to some type internally, we can
    /// use this `trait` as a requirement of that abstraction.
    ///
    /// See the [`bool`](crate::eclair::bool) module for an example of how to use introspection.
    type Type;
}

/// Introspection for the Native Compiler
///
/// The native compiler has access to all the types available to Rust and has access to them in
/// their native form so the allocated type [`Type`](Has::Type) is exactly the generic type `T`.
impl<T> Has<T> for () {
    type Type = T;
}

/// Compiler Introspected Type
pub type Type<COM, T> = <COM as Has<T>>::Type;
