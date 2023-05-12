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
use manta_crypto::{
    merkle_tree::{forest::TreeArrayMerkleForest, full::Full},
    rand::{ChaCha20Rng, CryptoRng, Rand, RngCore, SeedableRng},
};
use manta_pay::{
    config::{
        utxo::MerkleTreeConfiguration, AssetId, MultiProvingContext, Parameters,
        UtxoAccumulatorModel,
    },
    parameters::load_parameters,
    simulation::ledger::Ledger,
    test::payment::{
        unsafe_private_transfer::unsafe_no_prove_full as unsafe_private_transfer,
        unsafe_to_private::unsafe_no_prove_full as unsafe_to_private,
        unsafe_to_public::unsafe_no_prove_full as unsafe_to_public,
    },
};
use std::{
    env,
    fs::{self, OpenOptions},
    io::{self},
    path::PathBuf,
};
use tokio::{runtime::Runtime, sync::RwLock};

/// UTXO Accumulator for Building Test Circuits
pub type UtxoAccumulator =
    TreeArrayMerkleForest<MerkleTreeConfiguration, Full<MerkleTreeConfiguration>, 256>;

/// Number of coins
const NUMBER_OF_COINS: usize = 10000;

/// Builds sample transactions for testing.
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
    println!("{:?}", number_of_coins);
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
    runtime.block_on(fill_ledger_and_write(
        number_of_coins,
        &ledger,
        &proving_context,
        &parameters,
        &utxo_accumulator_model,
        asset_id,
        &mut rng,
    ));
    runtime.block_on(async { ledger.read().await.serialize_into(target_file) });
    directory.close()
}

// cargo run --release --package manta-pay --bin precompute_ledger --all-features -- <directory> <NUMBER_OF_COINS>
// cargo run --release --package manta-pay --bin precompute_ledger --all-features -- manta-pay/src/test/data 100

async fn fill_ledger_and_write<R>(
    number_of_coins: usize,
    ledger: &Arc<RwLock<Ledger>>,
    proving_context: &MultiProvingContext,
    parameters: &Parameters,
    utxo_accumulator_model: &UtxoAccumulatorModel,
    asset_id: AssetId,
    rng: &mut R,
) where
    R: RngCore + CryptoRng + ?Sized,
{
    for _ in 0..number_of_coins {
        match rng.gen_range(0..3) {
            0 => {
                let to_private = unsafe_to_private(
                    &proving_context.to_private,
                    parameters,
                    utxo_accumulator_model,
                    asset_id,
                    rng.gen(),
                    rng,
                );
                ledger
                    .write()
                    .await
                    .unsafe_push(rng.gen(), vec![to_private]);
            }
            1 => {
                let (private_transfer_input, private_transfer) = unsafe_private_transfer(
                    proving_context,
                    parameters,
                    utxo_accumulator_model,
                    asset_id,
                    [rng.gen::<_, u128>() / 2, rng.gen::<_, u128>() / 2],
                    rng,
                );
                ledger
                    .write()
                    .await
                    .unsafe_push(rng.gen(), private_transfer_input.into());
                ledger
                    .write()
                    .await
                    .unsafe_push(rng.gen(), vec![private_transfer]);
            }
            _ => {
                let account = rng.gen();
                let (to_public_input, to_public) = unsafe_to_public(
                    proving_context,
                    parameters,
                    utxo_accumulator_model,
                    asset_id,
                    [rng.gen::<_, u128>() / 2, rng.gen::<_, u128>() / 2],
                    account,
                    rng,
                );
                ledger
                    .write()
                    .await
                    .unsafe_push(rng.gen(), to_public_input.into());
                ledger.write().await.unsafe_push(account, vec![to_public]);
            }
        };
    }
}
