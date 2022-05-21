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

//! Round Constants Generation

use super::lfsr::GrainLFSR;
use crate::crypto::hash::poseidon::FieldGeneration;
use alloc::vec::Vec;

/// Generates round constants
pub fn generate_round_constants<F>(
    prime_num_bits: u64,
    width: usize,
    num_full_rounds: usize,
    num_partial_rounds: usize,
) -> Vec<F>
where
    F: FieldGeneration,
{
    let num_constants = (num_full_rounds + num_partial_rounds) * width;
    let mut lfsr = GrainLFSR::new(prime_num_bits, width, num_full_rounds, num_partial_rounds);
    lfsr.get_field_elements_rejection_sampling(num_constants)
}
