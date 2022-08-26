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

//! Trusted Setup Phase Two Parameters Preparation

use clap::Parser;
use manta_trusted_setup::ceremony::{config::g16_bls12_381::{Groth16BLS12381, prepare_phase_two_parameters}, util::load_from_file, message::MPCState};

/// CLI
#[derive(Debug, Parser)]
pub struct Arguments {
    /// Accumulator Path
    pub accumulator_path: String,
}

impl Arguments {
    /// Runs a server
    pub fn run(self) {
        prepare_phase_two_parameters(self.accumulator_path);
        load_from_file::<MPCState<Groth16BLS12381, 1>, _>(&"prepared_mint.data");
        load_from_file::<MPCState<Groth16BLS12381, 1>, _>(&"prepared_private_transfer.data");
        load_from_file::<MPCState<Groth16BLS12381, 1>, _>(&"prepared_reclaim.data");
    }
}

fn main() {
    Arguments::parse().run();
}
