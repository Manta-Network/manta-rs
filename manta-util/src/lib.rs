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

#![no_std]
#![cfg_attr(doc_cfg, feature(doc_cfg))]
#![forbid(rustdoc::broken_intra_doc_links)]
#![forbid(missing_docs)]

extern crate alloc;

mod array;
mod concat;
mod sealed;

pub mod iter;
pub mod num;

pub use array::*;
pub use concat::*;

/// Implements [`From`]`<$from>` for an enum `$to`, choosing the `$kind` variant.
// TODO: add `where` clauses
#[macro_export]
macro_rules! from_variant_impl {
    ($to:tt, $kind:ident, $from:tt) => {
        impl From<$from> for $to {
            #[inline]
            fn from(t: $from) -> Self {
                Self::$kind(t)
            }
        }
    };
}

/// Either Type
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Either<L, R> {
    /// Left Variant
    Left(L),

    /// Right Variant
    Right(R),
}
