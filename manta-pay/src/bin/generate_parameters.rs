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

//! Generate Parameters

// TODO: Deduplicate the per-circuit proving context and verifying context serialization code.
// TODO: Print some statistics about the parameters and circuits and into a stats file as well.

use manta_pay::{
    config::{utxo::v2::protocol::BaseParameters, Parameters},
    parameters,
};
use manta_util::codec::{Encode, IoWriter};
use std::{
    env,
    fs::{self, OpenOptions},
    io,
    path::PathBuf,
};

// cargo run --release --all-features --package manta-pay --bin generate_parameters /Users/thomascnorton/Documents/Manta/manta-rs/fresh_parameters

/// Generates the parameters using the [`SEED`](manta_pay::parameters::SEED) and saves them to the
/// filesystem.
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

    let (proving_context, verifying_context, parameters, utxo_accumulator_model) =
        parameters::generate().expect("Unable to generate parameters.");

    let Parameters {
        base:
            BaseParameters {
                group_generator,
                utxo_commitment_scheme,
                incoming_base_encryption_scheme,
                viewing_key_derivation_function,
                utxo_accumulator_item_hash,
                nullifier_commitment_scheme,
                outgoing_base_encryption_scheme,
            },
        address_partition_function,
        schnorr_hash_function,
    } = &parameters;

    let parameters_dir = target_dir.join("parameters");
    fs::create_dir_all(&parameters_dir)?;

    group_generator
        .encode(IoWriter(
            OpenOptions::new()
                .create(true)
                .write(true)
                .open(parameters_dir.join("group-generator.dat"))?,
        ))
        .unwrap();

    utxo_commitment_scheme
        .encode(IoWriter(
            OpenOptions::new()
                .create(true)
                .write(true)
                .open(parameters_dir.join("utxo-commitment-scheme.dat"))?,
        ))
        .unwrap();

    incoming_base_encryption_scheme
        .encode(IoWriter(OpenOptions::new().create(true).write(true).open(
            parameters_dir.join("incoming-base-encryption-scheme.dat"),
        )?))
        .unwrap();

    viewing_key_derivation_function
        .encode(IoWriter(OpenOptions::new().create(true).write(true).open(
            parameters_dir.join("viewing-key-derivation-function.dat"),
        )?))
        .unwrap();

    utxo_accumulator_item_hash
        .encode(IoWriter(
            OpenOptions::new()
                .create(true)
                .write(true)
                .open(parameters_dir.join("utxo-accumulator-item-hash.dat"))?,
        ))
        .unwrap();

    nullifier_commitment_scheme
        .encode(IoWriter(
            OpenOptions::new()
                .create(true)
                .write(true)
                .open(parameters_dir.join("nullifier-commitment-scheme.dat"))?,
        ))
        .unwrap();

    outgoing_base_encryption_scheme
        .encode(IoWriter(OpenOptions::new().create(true).write(true).open(
            parameters_dir.join("outgoing-base-encryption-scheme.dat"),
        )?))
        .unwrap();

    address_partition_function
        .encode(IoWriter(
            OpenOptions::new()
                .create(true)
                .write(true)
                .open(parameters_dir.join("address-partition-function.dat"))?,
        ))
        .unwrap();

    schnorr_hash_function
        .encode(IoWriter(
            OpenOptions::new()
                .create(true)
                .write(true)
                .open(parameters_dir.join("schnorr-hash-function.dat"))?,
        ))
        .unwrap();

    utxo_accumulator_model
        .encode(IoWriter(
            OpenOptions::new()
                .create(true)
                .write(true)
                .open(parameters_dir.join("utxo-accumulator-model.dat"))?,
        ))
        .unwrap();

    let proving_context_dir = target_dir.join("proving");
    fs::create_dir_all(&proving_context_dir)?;

    let verifying_context_dir = target_dir.join("verifying");
    fs::create_dir_all(&verifying_context_dir)?;

    proving_context
        .to_private
        .encode(IoWriter(
            OpenOptions::new()
                .create(true)
                .write(true)
                .open(proving_context_dir.join("to-private.lfs"))?,
        ))
        .unwrap();
    verifying_context
        .to_private
        .encode(IoWriter(
            OpenOptions::new()
                .create(true)
                .write(true)
                .open(verifying_context_dir.join("to-private.dat"))?,
        ))
        .unwrap();

    proving_context
        .private_transfer
        .encode(IoWriter(
            OpenOptions::new()
                .create(true)
                .write(true)
                .open(proving_context_dir.join("private-transfer.lfs"))?,
        ))
        .unwrap();
    verifying_context
        .private_transfer
        .encode(IoWriter(
            OpenOptions::new()
                .create(true)
                .write(true)
                .open(verifying_context_dir.join("private-transfer.dat"))?,
        ))
        .unwrap();

    proving_context
        .to_public
        .encode(IoWriter(
            OpenOptions::new()
                .create(true)
                .write(true)
                .open(proving_context_dir.join("to-public.lfs"))?,
        ))
        .unwrap();
    verifying_context
        .to_public
        .encode(IoWriter(
            OpenOptions::new()
                .create(true)
                .write(true)
                .open(verifying_context_dir.join("to-public.dat"))?,
        ))
        .unwrap();

    Ok(())
}
