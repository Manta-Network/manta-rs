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

//! Generate round constants

use super::lfsr::GrainLFSR;
use crate::crypto::hash::poseidon::Specification;
use alloc::vec::Vec;

/// return round constants, and return the LFSR used to generate MDS matrix
pub fn generate_round_constants<S, COM>(
    prime_num_bits: u64,
    width: usize,
    r_f: usize,
    r_p: usize,
) -> (Vec<S::ParameterField>, GrainLFSR) 
where S: Specification<COM>
{
    let num_constants = (r_f + r_p) * width;
    let mut lfsr = GrainLFSR::new(prime_num_bits, width, r_f, r_p);
    (lfsr.get_field_elements_rejection_sampling::<S, COM>(num_constants), lfsr)
}