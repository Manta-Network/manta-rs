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

//! Trusted Setup Ceremony Preparation
//! Given Phase 1 parameters and circuit descriptions, prepares files
//! needed for a server to act as ceremony coordinator.
//! NOTE: This saves an empty registry file. Registry updates are
//! triggered automatically by server.

use clap::Parser;
use manta_trusted_setup::groth16::ceremony::{
    config::ppot::{Config, Record, Registry},
    coordinator::prepare,
    CeremonyError,
};
use std::path::PathBuf;

// for local server test:
// cargo run --release --package manta-trusted-setup --all-features --bin groth16_phase2_prepare /Users/thomascnorton/Documents/Manta/trusted-setup/challenge_0072 /Users/thomascnorton/Documents/Manta/manta-rs/manta-trusted-setup/data
/// Preparer CLI
#[derive(Debug, Parser)]
pub struct Arguments {
    phase_one_param_path: PathBuf,

    recovery_directory: PathBuf,
}

impl Arguments {
    /// Prepares for phase 2 ceremony
    #[inline]
    pub fn run(self) -> Result<(), CeremonyError<Config>> {
        prepare::<Config, Registry, Record>(self.phase_one_param_path, self.recovery_directory);
        Ok(())
    }
}

fn main() {
    Arguments::parse()
        .run()
        .expect("Preparation error occurred");
}

/// The `prepare` method writes a `State`, which is just a wrapper
/// around a prover key. This deserializes, unwraps, reserializes.
#[test]
fn convert_state_to_pk() {
    use manta_crypto::arkworks::serialize::CanonicalSerialize;
    use manta_trusted_setup::{ceremony::util::deserialize_from_file, groth16::mpc::State};
    use std::{fs::OpenOptions, path::PathBuf};

    // let to_private_path = PathBuf::from(
    //     "/Users/thomascnorton/Documents/Manta/manta-rs/manta-trusted-setup/data/to_private_state_0",
    // );
    // let to_public_path = PathBuf::from(
    //     "/Users/thomascnorton/Documents/Manta/manta-rs/manta-trusted-setup/data/to_public_state_0",
    // );
    // let private_transfer_path = PathBuf::from("/Users/thomascnorton/Documents/Manta/manta-rs/manta-trusted-setup/data/private_transfer_state_0");

    let to_private_path = PathBuf::from(
        "/Users/thomascnorton/Desktop/server_data_test/to_private_state_11",
    );
    let to_public_path = PathBuf::from(
        "/Users/thomascnorton/Desktop/server_data_test/to_public_state_11",
    );
    let private_transfer_path = PathBuf::from("/Users/thomascnorton/Desktop/server_data_test/private_transfer_state_11");

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(
            to_private_path
                .parent()
                .expect("should have parent")
                .join("to_private_pk"),
        )
        .expect("unable to create file");
    let state: State<Config> =
        deserialize_from_file(to_private_path).expect("unable to load state");
    CanonicalSerialize::serialize_uncompressed(&state.0, &mut file).expect("Unable to serialize");

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(
            to_public_path
                .parent()
                .expect("should have parent")
                .join("to_public_pk"),
        )
        .expect("unable to create file");
    let state: State<Config> = deserialize_from_file(to_public_path).expect("unable to load state");
    CanonicalSerialize::serialize_uncompressed(&state.0, &mut file).expect("Unable to serialize");

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(
            private_transfer_path
                .parent()
                .expect("should have parent")
                .join("private_transfer_pk"),
        )
        .expect("unable to create file");
    let state: State<Config> =
        deserialize_from_file(private_transfer_path).expect("unable to load state");
    CanonicalSerialize::serialize_uncompressed(&state.0, &mut file).expect("Unable to serialize");
}
