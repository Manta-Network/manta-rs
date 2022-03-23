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

// TODO: Add CLI interface and configuration for simulation parameters. See the old simulation code
//       `test/simulation/mod.rs` for more information.

use manta_accounting::transfer::canonical::generate_context;
use manta_crypto::rand::{OsRng, Rand};
use manta_pay::{
    config::FullParameters,
    simulation::{ledger::Ledger, Simulation},
};

/// Runs the Manta Pay simulation.
#[tokio::main]
pub async fn main() {
    let mut rng = OsRng;
    let parameters = rng.gen();
    let utxo_accumulator_model = rng.gen();

    let (proving_context, verifying_context) = generate_context(
        &(),
        FullParameters::new(&parameters, &utxo_accumulator_model),
        &mut rng,
    )
    .expect("Failed to generate contexts.");

    Simulation {
        actor_count: 10,
        actor_lifetime: 10,
        asset_id_count: 3,
        starting_balance: 1000000,
    }
    .run(
        &parameters,
        &utxo_accumulator_model,
        &proving_context,
        Ledger::new(utxo_accumulator_model.clone(), verifying_context),
        &mut rng,
    )
    .await
}
