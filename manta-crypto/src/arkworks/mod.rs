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

//! Arkworks Backend

pub use ark_ec as ec;
pub use ark_r1cs_std as r1cs_std;
pub use ark_relations as relations;

#[cfg(feature = "ark-bls12-381")]
pub use ark_bls12_381 as bls12_381;

#[cfg(feature = "ark-bn254")]
pub use ark_bn254 as bn254;

#[cfg(feature = "ark-ed-on-bls12-381")]
pub use ark_ed_on_bls12_381 as ed_on_bls12_381;

#[cfg(feature = "ark-ed-on-bn254")]
pub use ark_ed_on_bn254 as ed_on_bn254;

pub mod algebra;
pub mod constraint;
pub mod ff;
pub mod pairing;
pub mod rand;
pub mod ratio;
pub mod serialize;
