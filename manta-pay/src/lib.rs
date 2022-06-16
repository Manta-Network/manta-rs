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

//! Manta Pay Implementation

#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![cfg_attr(doc_cfg, feature(doc_cfg))]
#![forbid(rustdoc::broken_intra_doc_links)]
#![forbid(missing_docs)]

extern crate alloc;

pub mod crypto;
pub mod util;

#[cfg(feature = "groth16")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "groth16")))]
pub mod config;

#[cfg(feature = "bip32")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "bip32")))]
pub mod key;

#[cfg(all(feature = "groth16", feature = "test"))]
#[cfg_attr(doc_cfg, doc(cfg(all(feature = "groth16", feature = "test"))))]
pub mod parameters;

#[cfg(feature = "groth16")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "groth16")))]
pub mod signer;

#[cfg(all(feature = "groth16", feature = "simulation"))]
#[cfg_attr(doc_cfg, doc(cfg(all(feature = "groth16", feature = "simulation"))))]
pub mod simulation;

#[cfg(any(test, feature = "test"))]
#[cfg_attr(doc_cfg, doc(cfg(feature = "test")))]
pub mod test;
