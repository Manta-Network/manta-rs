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

use ark_bls12_381::Fr;
use clap::Parser;
use manta_crypto::arkworks::serialize::CanonicalDeserialize;
use manta_pay::{
    config::{FullParameters, Mint, PrivateTransfer, Reclaim},
    crypto::constraint::arkworks::R1CS,
    parameters::{load_transfer_parameters, load_utxo_accumulator_model},
};
use manta_trusted_setup::{
    ceremony::{
        config::g16_bls12_381::Groth16BLS12381,
        util::{load_from_file, log_to_file},
    },
    groth16::{kzg::Accumulator, mpc, mpc::initialize},
};
use std::{fs::File, io::Read, time::Instant};

type C = Groth16BLS12381;
type Config = manta_trusted_setup::groth16::config::Config;

/// Prepares phase one parameters ready to use in trusted setup for phase two parameters.
pub fn prepare_phase_two_parameters(accumulator_path: String) {
    let now = Instant::now();
    let mut buf = Vec::new();
    File::open(accumulator_path)
        .expect("Opening phase one parameter file should succeed.")
        .read_to_end(&mut buf)
        .expect("Reading phase one parameter should succeed.");
    let mut reader = &buf[..];
    let powers: Accumulator<Config> = CanonicalDeserialize::deserialize(&mut reader)
        .expect("Deserialize phase one parameter should succeed.");
    println!(
        "Loading & Deserializing Phase 1 parameters takes {:?}\n",
        now.elapsed()
    );
    let transfer_parameters = load_transfer_parameters();
    let utxo_accumulator_model = load_utxo_accumulator_model();
    prepare_parameters(
        powers.clone(),
        Mint::unknown_constraints(FullParameters::new(
            &transfer_parameters,
            &utxo_accumulator_model,
        )),
        "mint",
    );
    prepare_parameters(
        powers.clone(),
        PrivateTransfer::unknown_constraints(FullParameters::new(
            &transfer_parameters,
            &utxo_accumulator_model,
        )),
        "private_transfer",
    );
    prepare_parameters(
        powers,
        Reclaim::unknown_constraints(FullParameters::new(
            &transfer_parameters,
            &utxo_accumulator_model,
        )),
        "reclaim",
    );
}

/// Prepares phase one parameter `powers` for phase two parameters of circuit `cs` with `name`.
pub fn prepare_parameters(powers: Accumulator<Config>, cs: R1CS<Fr>, name: &str) {
    let now = Instant::now();
    let state = initialize::<Config, R1CS<Fr>>(powers, cs).expect("failed to initialize state");
    let challenge = <Config as mpc::ProvingKeyHasher<Config>>::hash(&state).into();
    log_to_file::<C, _>(&format!("prepared_{}.data", name), state, challenge);
    println!(
        "Preparing Phase 2 parameters for {} circuit takes {:?}\n",
        name,
        now.elapsed()
    );
}

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
        load_from_file::<C, _>(&"prepared_mint.data");
        load_from_file::<C, _>(&"prepared_private_transfer.data");
        load_from_file::<C, _>(&"prepared_reclaim.data");
    }
}

fn main() {
    Arguments::parse().run();
}
