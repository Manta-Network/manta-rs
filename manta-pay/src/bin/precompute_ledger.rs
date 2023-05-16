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

//! Precompute ledger

extern crate alloc;

use alloc::sync::Arc;
use manta_crypto::rand::{ChaCha20Rng, SeedableRng};
use manta_pay::{
    parameters::load_parameters,
    simulation::ledger::{safe_fill_ledger, unsafe_fill_ledger, Ledger},
};
use std::{
    env,
    fs::{self, OpenOptions},
    io::{self},
    path::PathBuf,
    str::FromStr,
};
use tokio::{runtime::Runtime, sync::RwLock};

/// Mode
#[derive(Debug)]
enum Mode {
    /// Safe mode
    Safe,

    /// Unsafe mode
    Unsafe,
}

impl FromStr for Mode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "UNSAFE" => Ok(Mode::Unsafe),
            "SAFE" => Ok(Mode::Safe),
            _ => Err(()),
        }
    }
}

/// Default number of coins
const NUMBER_OF_COINS: usize = 10000;

/// Default Mode
const DEFAULT_MODE: Mode = Mode::Unsafe;

/// Builds sample transactions on a ledger for testing purposes.
#[inline]
fn main() -> io::Result<()> {
    let target_dir = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or(env::current_dir()?);
    assert!(
        target_dir.is_dir() || !target_dir.exists(),
        "Specify a directory to place the generated files: {target_dir:?}.",
    );
    fs::create_dir_all(&target_dir)?;
    let number_of_coins = env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(NUMBER_OF_COINS);
    let mode = env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MODE);
    let target_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(target_dir.join("precomputed_ledger"))?;
    let directory = tempfile::tempdir().expect("Unable to generate temporary test directory.");
    println!("[INFO] Temporary Directory: {directory:?}");
    let mut rng = ChaCha20Rng::from_seed([0; 32]);
    let (proving_context, verifying_context, parameters, utxo_accumulator_model) =
        load_parameters(directory.path()).expect("Unable to load parameters.");
    let asset_id = 8.into();
    let ledger = Arc::new(RwLock::new(Ledger::new(
        utxo_accumulator_model.clone(),
        verifying_context,
        parameters.clone(),
    )));
    let runtime = Runtime::new().expect("Unable to start tokio runtime");
    match mode {
        Mode::Safe => runtime.block_on(safe_fill_ledger(
            number_of_coins,
            &ledger,
            &proving_context,
            &parameters,
            &utxo_accumulator_model,
            asset_id,
            &mut rng,
        )),
        Mode::Unsafe => runtime.block_on(unsafe_fill_ledger(
            number_of_coins,
            &ledger,
            &proving_context,
            &parameters,
            &utxo_accumulator_model,
            asset_id,
            &mut rng,
        )),
    };
    runtime.block_on(async { ledger.read().await.serialize_into(target_file) });
    directory.close()
}

// cargo run --release --package manta-pay --bin precompute_ledger --all-features -- <directory> <NUMBER_OF_COINS> <MODE>
// cargo run --release --package manta-pay --bin precompute_ledger --all-features -- manta-pay/src/test/data 100 unsafe
