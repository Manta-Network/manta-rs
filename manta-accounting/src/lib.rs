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

//! Accounting Primitives

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg), forbid(broken_intra_doc_links))]

extern crate alloc;
extern crate derive_more;

mod asset;
mod ledger;

pub mod account;
pub mod transfer;
pub mod wallet;

pub use account::prelude::*;
pub use asset::*;
pub use ledger::*;
