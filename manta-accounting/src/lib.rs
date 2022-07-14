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

//! Accounting Primitives
//!
//! This crate defines the abstractions required for the private transfer of assets and the keeping
//! of accounts related to private assets, including the definitions of an [asset], a [private
//! transfer protocol], and a [wallet protocol].
//!
//! [asset]: asset
//! [private transfer protocol]: transfer
//! [wallet protocol]: wallet

#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![cfg_attr(doc_cfg, feature(doc_cfg))]
#![forbid(rustdoc::broken_intra_doc_links)]
#![forbid(missing_docs)]

extern crate alloc;
extern crate derive_more;

pub mod asset;
pub mod key;
pub mod transfer;
pub mod wallet;

#[cfg(feature = "fs")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "fs")))]
pub mod fs;
