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

//! Manta Pay Simulation

use clap::{error::ErrorKind, CommandFactory, Parser};
use manta_accounting::transfer::canonical::generate_context;
use manta_crypto::rand::{OsRng, Rand};
use manta_pay::{config::FullParametersRef, simulation::Simulation};

// cargo run --release --package manta-pay --all-features --bin simulation <number_of_actors> <number_of_steps> <number_of_asset_ids> <initial_balance>
// cargo run --release --package manta-pay --all-features --bin simulation 5 100000000 3 1000 > simulation_output_1

/// Runs the Manta Pay simulation.
pub fn main() {
    let simulation = Simulation::parse();
    let mut rng = OsRng;
    let parameters = rng.gen();
    let utxo_accumulator_model = rng.gen();
    let (proving_context, verifying_context) = generate_context(
        &(),
        FullParametersRef::new(&parameters, &utxo_accumulator_model),
        &mut rng,
    )
    .expect("Failed to generate contexts.");
    match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(6)
        .build()
    {
        Ok(runtime) => runtime.block_on(async {
            simulation
                .run(
                    &parameters,
                    &utxo_accumulator_model,
                    &proving_context,
                    verifying_context,
                    &mut rng,
                )
                .await
        }),
        Err(err) => Simulation::command()
            .error(
                ErrorKind::Io,
                format_args!("Unable to start `tokio` runtime: {err}"),
            )
            .exit(),
    }
}
