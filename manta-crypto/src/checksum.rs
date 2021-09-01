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

//! Checksums

// TODO: move this out of this crate, this is for `pallet-manta-pay` when we check local parameters
// against stored ones. maybe this can go in `manta-pay`?

use ark_std::vec::Vec;
use blake2::{Blake2s, Digest};

/// Checksum Error Type
pub struct Error;

/// Checksum Trait
pub trait Checksum<const N: usize> {
	/// Computes the checksum of `self`.
	fn get_checksum(&self) -> Result<[u8; N], Error>;
}

impl Checksum<4> for Vec<u8> {
	fn get_checksum(&self) -> Result<[u8; 4], Error> {
		let mut hasher = Blake2s::new();
		hasher.update(&self);
		let digest = hasher.finalize();
		let mut int_res = [0; 32];
		int_res.copy_from_slice(digest.as_slice());
		let mut hasher_two = Blake2s::new();
		hasher_two.update(int_res);
		let final_digest = hasher_two.finalize();
		let mut res = [0; 4];
		res.copy_from_slice(&final_digest.as_slice()[0..4]);
		Ok(res)
	}
}
