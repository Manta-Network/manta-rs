// Copyright 2019-2021 Manta Network.
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

//! Generate Parameters

// TODO: Specify target directory in `main`.
// TODO: Deduplicate the per-circuit proving context and verifying context serialization code.
// TODO: Print some statistics about the parameters and circuits and into a stats file as well.

use manta_accounting::transfer;
use manta_crypto::{
    constraint::ProofSystem as _,
    rand::{Rand, SeedableRng},
};
use manta_pay::config::{
    Config, FullParameters, Mint, Parameters, PrivateTransfer, ProofSystem, Reclaim,
};
use manta_util::codec::{Encode, IoWriter};
use rand_chacha::ChaCha20Rng;
use std::{
    env,
    fs::{self, OpenOptions},
    io,
    path::PathBuf,
};

/// Parameter Generation Seed
///
/// This is a nothing-up-my-sleve parameter generation number. Its just the numbers from `0` to `31`
/// as `u8` bytes.
///
/// # Warning
///
/// Right now, this seed is also used to generate to the proving and verifying keys for the ZKP
/// circuits. This is not safe, and a real system must use a Multi-Party-Computation to arrive at
/// the ZKP parameters.
pub const SEED: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

/// Generates the parameters using the [`SEED`] and saves them to the filesystem.
#[inline]
pub fn main() -> io::Result<()> {
    let target_dir = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or(env::current_dir()?);
    assert!(
        target_dir.is_dir() || !target_dir.exists(),
        "Specify a directory to place the generated files: {:?}.",
        target_dir,
    );
    fs::create_dir_all(&target_dir)?;

    let mut rng = ChaCha20Rng::from_seed(SEED);

    let parameters = rng.gen();
    let utxo_set_parameters: <Config as transfer::Configuration>::UtxoSetModel = rng.gen();

    let Parameters {
        key_agreement,
        utxo_commitment,
        void_number_hash,
    } = &parameters;

    let parameters_dir = target_dir.join("parameters");
    fs::create_dir_all(&parameters_dir)?;

    key_agreement
        .encode(IoWriter(
            OpenOptions::new()
                .create(true)
                .write(true)
                .open(parameters_dir.join("key-agreement.dat"))?,
        ))
        .unwrap();

    utxo_commitment
        .encode(IoWriter(
            OpenOptions::new()
                .create(true)
                .write(true)
                .open(parameters_dir.join("utxo-commitment-scheme.dat"))?,
        ))
        .unwrap();

    void_number_hash
        .encode(IoWriter(
            OpenOptions::new()
                .create(true)
                .write(true)
                .open(parameters_dir.join("void-number-hash-function.dat"))?,
        ))
        .unwrap();

    utxo_set_parameters
        .encode(IoWriter(
            OpenOptions::new()
                .create(true)
                .write(true)
                .open(parameters_dir.join("utxo-set-parameters.dat"))?,
        ))
        .unwrap();

    let full_parameters = FullParameters::new(&parameters, &utxo_set_parameters);

    let proving_context_dir = target_dir.join("proving");
    fs::create_dir_all(&proving_context_dir)?;

    let verifying_context_dir = target_dir.join("verifying");
    fs::create_dir_all(&verifying_context_dir)?;

    let cs = Mint::unknown_constraints(full_parameters);
    let (proving_context, verifying_context) =
        ProofSystem::generate_context(cs, &(), &mut rng).unwrap();
    proving_context
        .encode(IoWriter(
            OpenOptions::new()
                .create(true)
                .write(true)
                .open(proving_context_dir.join("mint.dat"))?,
        ))
        .unwrap();
    verifying_context
        .encode(IoWriter(
            OpenOptions::new()
                .create(true)
                .write(true)
                .open(verifying_context_dir.join("mint.dat"))?,
        ))
        .unwrap();

    let cs = PrivateTransfer::unknown_constraints(full_parameters);
    let (proving_context, verifying_context) =
        ProofSystem::generate_context(cs, &(), &mut rng).unwrap();
    proving_context
        .encode(IoWriter(
            OpenOptions::new()
                .create(true)
                .write(true)
                .open(proving_context_dir.join("private-transfer.dat"))?,
        ))
        .unwrap();
    verifying_context
        .encode(IoWriter(
            OpenOptions::new()
                .create(true)
                .write(true)
                .open(verifying_context_dir.join("private-transfer.dat"))?,
        ))
        .unwrap();

    let cs = Reclaim::unknown_constraints(full_parameters);
    let (proving_context, verifying_context) =
        ProofSystem::generate_context(cs, &(), &mut rng).unwrap();
    proving_context
        .encode(IoWriter(
            OpenOptions::new()
                .create(true)
                .write(true)
                .open(proving_context_dir.join("reclaim.dat"))?,
        ))
        .unwrap();
    verifying_context
        .encode(IoWriter(
            OpenOptions::new()
                .create(true)
                .write(true)
                .open(verifying_context_dir.join("reclaim.dat"))?,
        ))
        .unwrap();

    Ok(())
}
