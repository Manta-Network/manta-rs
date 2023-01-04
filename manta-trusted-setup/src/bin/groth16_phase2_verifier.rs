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

//! Trusted Setup Ceremony Verifier

use clap::Parser;
use core::fmt::Debug;
use manta_crypto::arkworks::serialize::CanonicalSerialize;
use manta_trusted_setup::{
    ceremony::util::deserialize_from_file,
    groth16::{
        ceremony::{
            config::ppot::Config, message::ContributeResponse, server::filename_format, Ceremony,
            CeremonyError, UnexpectedError,
        },
        mpc::{verify_transform, Proof, State},
    },
};
use manta_util::Array;
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

/// Verification CLI
#[derive(Debug, Parser)]
pub struct Arguments {
    /// Directory containing ceremony transcript
    path: String,

    /// Starting round for verification
    start: u64,
}

impl Arguments {
    /// Runs a server.
    #[inline]
    pub fn run(self) -> Result<(), CeremonyError<Config>> {
        let path = PathBuf::from(self.path);
        verify_ceremony(&path, self.start)?;
        contribution_hashes(&path);
        Ok(())
    }
}

fn main() {
    Arguments::parse().run().unwrap();
}

fn verify_ceremony<C>(path: &Path, start: u64) -> Result<(), CeremonyError<C>>
where
    C: Ceremony<Challenge = Array<u8, 64>>,
{
    // Need to read from files, so get circuit names
    let names: Vec<String> =
        deserialize_from_file(path.join(r"circuit_names")).expect("Circuit names file is missing.");
    println!("Will verify contributions to {names:?}");
    // Keep track of verification times
    let mut verification_times = Vec::<Duration>::new();

    // Check each circuit
    for name in names.clone() {
        println!("Checking contributions to circuit {}", name.clone());
        let mut challenge_output =
            File::create(path.join(format!("{}_computed_challenges", name.clone())))
                .expect("Unable to create output file");
        let mut round = start;
        let now = Instant::now();
        // Load starting round
        let mut state: State<C> = deserialize_from_file(filename_format(
            path,
            name.clone(),
            "state".to_string(),
            start,
        ))
        .map_err(|e| {
            CeremonyError::Unexpected(UnexpectedError::Serialization {
                message: format!("{e:?}"),
            })
        })?;
        let mut challenge: C::Challenge = deserialize_from_file(filename_format(
            path,
            name.clone(),
            "challenge".to_string(),
            start,
        ))
        .map_err(|e| {
            CeremonyError::Unexpected(UnexpectedError::Serialization {
                message: format!("{e:?}"),
            })
        })?;

        // Check until no more files are found
        loop {
            round += 1;
            let proof_result: Result<Proof<C>, _> = deserialize_from_file(filename_format(
                path,
                name.clone(),
                "proof".to_string(),
                round,
            ));
            let next_state_result: Result<State<C>, _> = deserialize_from_file(filename_format(
                path,
                name.clone(),
                "state".to_string(),
                round,
            ));
            match (proof_result, next_state_result) {
                (Ok(proof), Ok(next_state)) => {
                    if round % 50 == 0 {
                        println!("Verifying round {round}");
                    }
                    (challenge, state) = verify_transform(&challenge, &state, next_state, proof)
                        .map_err(|e| {
                            println!("Encountered error {e:?} in round {round}");
                            CeremonyError::BadRequest
                        })?;
                    writeln!(challenge_output, "{} round {round}", hex::encode(challenge))
                        .expect("Unable to write challenge hash to file");
                }
                _ => {
                    break;
                }
            }
        }

        verification_times.push(now.elapsed());
        println!(
            "Checked {} contributions to {name} in {:?}",
            round - 1,
            now.elapsed()
        );
    }
    println!("All checks successful.");
    for (name, time) in names.iter().zip(verification_times.iter()) {
        println!("Verified contributions to {name} in {time:?}");
    }
    Ok(())
}

/// Combines the challenge hashes from each individual circuit to form the overall
/// contribution hash that participants published as a commitment to their
/// contribution.
fn contribution_hashes(path: &Path) {
    let private_transfer_challenges = BufReader::new(
        File::open(path.join("private_transfer_computed_challenges")).expect("Unable to open file"),
    )
    .lines();
    let to_private_challenges = BufReader::new(
        File::open(path.join("to_private_computed_challenges")).expect("Unable to open file"),
    )
    .lines();
    let to_public_challenges = BufReader::new(
        File::open(path.join("to_public_computed_challenges")).expect("Unable to open file"),
    )
    .lines();
    let mut output =
        File::create(path.join("contribution_hashes.txt")).expect("Unable to create output file");

    for ((private_transfer, to_private), to_public) in private_transfer_challenges
        .zip(to_private_challenges)
        .zip(to_public_challenges)
    {
        match ((private_transfer, to_private), to_public) {
            ((Ok(private_transfer), Ok(to_private)), Ok(to_public)) => {
                // Hashes were written as "hash_as_hex round n"
                let private_transfer: Vec<&str> = private_transfer.split(' ').into_iter().collect();
                let to_private: Vec<&str> = to_private.split(' ').into_iter().collect();
                let to_public: Vec<&str> = to_public.split(' ').into_iter().collect();
                // Check that all hashes correspond to same contribution round:
                assert_eq!(to_private[2], to_public[2]);
                assert_eq!(to_private[2], private_transfer[2]);
                let index = to_private[2]
                    .parse::<u64>()
                    .expect("Unexpected value for round number");

                let contribution_response = ContributeResponse::<Config> {
                    index,
                    challenge: Vec::<Array<u8, 64>>::from([
                        Array::from_vec(hex::decode(to_private[0]).unwrap()),
                        Array::from_vec(hex::decode(to_public[0]).unwrap()),
                        Array::from_vec(hex::decode(private_transfer[0]).unwrap()),
                    ]),
                };
                let contribution_hash =
                    <Config as Ceremony>::contribution_hash(&contribution_response);
                writeln!(
                    output,
                    "{} round {}",
                    hex::encode(contribution_hash),
                    private_transfer[2]
                )
                .expect("Unable to write challenge hash to file");
            }
            _ => println!("Read error occurred"),
        }
    }
}

/// Can be used to compute contribution hashes if the challenge
/// hashes from individual circuits are already present in the specified directory.
/// Modify `path` as needed.
#[ignore] // NOTE: Adds `ignore` such that CI does NOT run this test while still allowing developers to test.
#[test]
fn compute_contribution_hashes() {
    // Modify this to correct path
    let path = PathBuf::from("/");
    contribution_hashes(&path);
}

/// If circuit_names file is missing, this is a way of generating a new one.
/// Change `path` as desired.
#[ignore]
#[test]
fn create_names_file() {
    use manta_trusted_setup::ceremony::util::serialize_into_file;
    use std::fs::OpenOptions;

    let path = PathBuf::from("/circuit_names");
    let names = Vec::from([
        "private_transfer".to_string(),
        "to_private".to_string(),
        "to_public".to_string(),
    ]);
    serialize_into_file(
        OpenOptions::new().write(true).truncate(true).create(true),
        &path,
        &names,
    )
    .expect("Unable to serialize names");
}

/// The `prepare` method writes a `State`, which is just a wrapper
/// around a prover key. This deserializes, unwraps, reserializes.
/// Modify the path as appropriate. 4382 refers to the total number
/// of ceremony contributions.
#[ignore]
#[test]
fn convert_state_to_keys() {
    use std::path::PathBuf;

    // Modify this to the appropriate path
    let directory_path = PathBuf::from("/");
    let to_private_path = directory_path.join("to_private_state_4382");
    let to_public_path = directory_path.join("to_public_state_4382");
    let private_transfer_path = directory_path.join("private_transfer_state_4382");

    extract_keys(&to_private_path, "to_private".to_string()).expect("Extraction error");
    extract_keys(&to_public_path, "to_public".to_string()).expect("Extraction error");
    extract_keys(&private_transfer_path, "private_transfer".to_string()).expect("Extraction error");
}

/// Extracts prover key and verifier key from state located at `path` and writes
/// them to a file according to the provided `name`. The new files are located
/// in the same directory as `path`.
pub fn extract_keys(path: &Path, name: String) -> Result<(), UnexpectedError> {
    let mut pk_file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(
            path.parent()
                .expect("Path has no parent")
                .join(format!("{name}_pk")),
        )
        .map_err(|_| UnexpectedError::Serialization {
            message: "Unable to create file at desired location.".to_string(),
        })?;
    let mut vk_file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(
            path.parent()
                .expect("Path has no parent")
                .join(format!("{name}_vk")),
        )
        .map_err(|_| UnexpectedError::Serialization {
            message: "Unable to create file at desired location.".to_string(),
        })?;
    let state: State<Config> =
        deserialize_from_file(path).map_err(|_| UnexpectedError::Serialization {
            message: "Unable to deserialize state at provided path".to_string(),
        })?;
    CanonicalSerialize::serialize_uncompressed(&state.0, &mut pk_file).map_err(|_| {
        UnexpectedError::Serialization {
            message: "Unable to serialize prover key.".to_string(),
        }
    })?;
    CanonicalSerialize::serialize_uncompressed(&state.0.vk, &mut vk_file).map_err(|_| {
        UnexpectedError::Serialization {
            message: "Unable to serialize prover key.".to_string(),
        }
    })?;
    Ok(())
}
