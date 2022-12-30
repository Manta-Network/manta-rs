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
use core::{cmp::PartialEq, fmt::Debug};
use manta_trusted_setup::{
    ceremony::util::deserialize_from_file,
    groth16::{
        ceremony::{
            config::ppot::Config, server::filename_format, Ceremony, CeremonyError, UnexpectedError,
        },
        mpc::{verify_transform, Proof, State},
    },
};
use manta_util::serde::{de::DeserializeOwned, Serialize};
use std::{
    fs::File,
    io::Write,
    path::PathBuf,
    time::{Duration, Instant},
};

// cargo run --release --package manta-trusted-setup --all-features --bin groth16_phase2_verifier -- /Users/thomascnorton/Documents/Manta/ceremony_archive_2022_12_29

/// Server CLI
#[derive(Debug, Parser)]
pub struct Arguments {
    path: String,
}

impl Arguments {
    /// Runs a server.
    #[inline]
    pub fn run(self) -> Result<(), CeremonyError<Config>> {
        let path = PathBuf::from(self.path);
        verify_ceremony(path)
    }
}

fn main() {
    Arguments::parse().run().unwrap();
}

fn verify_ceremony<C>(path: PathBuf) -> Result<(), CeremonyError<C>>
where
    C: Ceremony,
    C::Challenge: DeserializeOwned + PartialEq + Clone + Serialize + Debug + AsRef<[u8]>,
{
    // Need to read from files, so get circuit names
    let names: Vec<String> =
        deserialize_from_file(path.join(r"circuit_names")).expect("Cannot open circuit name file.");
    println!("Will verify contributions to {names:?}");
    // Keep track of verification times
    let mut verification_times = Vec::<Duration>::new();
    // Need to know how many rounds to verify
    let rounds: u64 = deserialize_from_file(path.join(r"round_number")).map_err(|e| {
        CeremonyError::Unexpected(UnexpectedError::Serialization {
            message: format!("{e:?}"),
        })
    })?;
    println!("Checking a ceremony with {rounds:?} contributions");

    // Check each circuit
    for name in names.clone() {
        println!("Checking contributions to circuit {}", name.clone());

        let now = Instant::now();
        // Start by loading the defaults (TODO: This ought to generate them itself from a circuit description)
        let mut state: State<C> =
            deserialize_from_file(filename_format(&path, name.clone(), "state".to_string(), 0))
                .map_err(|e| {
                    CeremonyError::Unexpected(UnexpectedError::Serialization {
                        message: format!("{e:?}"),
                    })
                })?;
        let mut challenge: C::Challenge = deserialize_from_file(filename_format(
            &path,
            name.clone(),
            "challenge".to_string(),
            0,
        ))
        .map_err(|e| {
            CeremonyError::Unexpected(UnexpectedError::Serialization {
                message: format!("{e:?}"),
            })
        })?;

        let mut challenge_output =
            File::create(path.join(format!("{:?}_computed_challenges", name.clone())))
                .expect("Unable to create output file");
        for i in 1..(rounds + 1) {
            let proof: Proof<C> =
                deserialize_from_file(filename_format(&path, name.clone(), "proof".to_string(), i))
                    .map_err(|e| {
                        CeremonyError::Unexpected(UnexpectedError::Serialization {
                            message: format!("{e:?}"),
                        })
                    })?;
            let next_state: State<C> =
                deserialize_from_file(filename_format(&path, name.clone(), "state".to_string(), i))
                    .map_err(|e| {
                        CeremonyError::Unexpected(UnexpectedError::Serialization {
                            message: format!("{e:?}"),
                        })
                    })?;

            // Just a small sanity check to make sure the client really does transform the keys
            if state.0.delta_g1 == next_state.0.delta_g1 {
                println!("Warning: Trivial contribution occurred in round {i}");
            }
            (challenge, state) =
                verify_transform(&challenge, &state, next_state, proof).map_err(|e| {
                    println!("Encountered error {e:?}");
                    CeremonyError::BadRequest
                })?;

            writeln!(challenge_output, "{:?}", hex::encode(challenge.clone()))
                .expect("Unable to write challenge hash to file");
            // Check that this matches the purported challenge in ceremony transcript
            let asserted_challenge: C::Challenge = deserialize_from_file(filename_format(
                &path,
                name.clone(),
                "challenge".to_string(),
                i,
            ))
            .map_err(|e| {
                CeremonyError::Unexpected(UnexpectedError::Serialization {
                    message: format!("{e:?}"),
                })
            })?;
            if challenge != asserted_challenge {
                println!("Warning: Inconsistent challenge hashes.\nComputed challenge is {challenge:?}\nArchived Challenge is {asserted_challenge:?}");
            }
            if i % 100 == 0 {
                println!("Have checked {i} contributions successfully");
            }
        }
        writeln!(
            challenge_output,
            "Verified {rounds} contributions to {name} in {:?}",
            now.elapsed()
        )
        .expect("Unable to write to file");
        verification_times.push(now.elapsed());
        println!("Checked all contributions in {:?}", now.elapsed());
        // Write challenges to file
    }
    println!("All checks successful.");
    for (name, time) in names.iter().zip(verification_times.iter()) {
        println!("Verified {rounds} contributions to {name} in {time:?}");
    }
    Ok(())
}

#[test]
fn create_names_file() {
    use manta_trusted_setup::ceremony::util::serialize_into_file;
    use std::fs::OpenOptions;
    let path = PathBuf::from(
        "/Users/thomascnorton/Documents/Manta/manta-rs/manta-trusted-setup/data/circuit_names",
    );
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

#[test]
fn create_rounds_file() {
    use manta_trusted_setup::ceremony::util::serialize_into_file;
    use std::fs::OpenOptions;
    let path = PathBuf::from(
        "/Users/thomascnorton/Documents/Manta/manta-rs/manta-trusted-setup/data/round_number",
    );
    let rounds = 2u64;
    serialize_into_file(
        OpenOptions::new().write(true).truncate(true).create(true),
        &path,
        &rounds,
    )
    .expect("Unable to serialize rounds");
}

#[test]
fn contribution_hashes() {
    use manta_trusted_setup::groth16::ceremony::message::ContributeResponse;
    use manta_util::Array;
    use std::io::{BufRead, BufReader};

    let path = PathBuf::from("/Users/thomascnorton/Documents/Manta/ceremony_hashes_22_12_29");

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

    for (i, ((private_transfer, to_private), to_public)) in private_transfer_challenges
        .zip(to_private_challenges)
        .zip(to_public_challenges)
        .enumerate()
    {
        match ((private_transfer, to_private), to_public) {
            ((Ok(private_transfer), Ok(to_private)), Ok(to_public)) => {
                let contribution_response = ContributeResponse::<Config> {
                    index: (i + 1) as u64,
                    challenge: Vec::<Array<u8, 64>>::from([
                        Array::from_vec(hex::decode(&to_private[1..129]).unwrap()),
                        Array::from_vec(hex::decode(&to_public[1..129]).unwrap()),
                        Array::from_vec(hex::decode(&private_transfer[1..129]).unwrap()),
                    ]),
                };
                let contribution_hash =
                    <Config as Ceremony>::contribution_hash(&contribution_response);
                println!(
                    "Computed the contribution hash {:?}",
                    hex::encode(contribution_hash)
                );
            }
            _ => println!("Read error occurred"),
        }
    }
}
