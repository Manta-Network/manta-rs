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
use manta_crypto::rand::OsRng;
use manta_pay::{parameters::load_parameters, simulation::Simulation};
use std::path::PathBuf;

/// Runs the Manta Pay simulation.
pub fn main() {
    let simulation = Simulation::parse();
    let mut rng = OsRng;
    let (proving_context, verifying_context, parameters, utxo_accumulator_model) =
        load_parameters(&PathBuf::from("/")) // TODO: What temporary directory can you specify here?
            .expect("Unable to load parameters");
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
