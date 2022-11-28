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

//! Trusted Setup Ceremony Server

use clap::Parser;
use manta_trusted_setup::{
    ceremony::util::deserialize_from_file,
    groth16::{
        ceremony::{
            config::ppot::Config, server::filename_format, Ceremony, CeremonyError, UnexpectedError,
        },
        mpc::{verify_transform, Proof, State},
    },
};
use manta_util::serde::de::DeserializeOwned;
use std::{path::PathBuf, time::Instant};

// cargo run --release --package manta-trusted-setup --all-features --bin ceremony_verifier -- /Users/thomascnorton/Documents/Manta/manta-rs/manta-trusted-setup/data

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
    Arguments::parse().run().expect("");
}

fn verify_ceremony<C>(path: PathBuf) -> Result<(), CeremonyError<C>>
where
    C: Ceremony,
    C::Challenge: DeserializeOwned,
{
    // Need to read from files, so get circuit names
    let names: Vec<String> =
        deserialize_from_file(path.join(r"circuit_names")).expect("Cannot open circuit name file.");
    // Need to know how many rounds to verify
    let rounds: u64 = deserialize_from_file(path.join(r"round_number")).map_err(|e| {
        CeremonyError::Unexpected(UnexpectedError::Serialization {
            message: format!("{e:?}"),
        })
    })?;
    println!("Checking a ceremony with {rounds:?} contributions");

    // Check each circuit
    for name in names {
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
            (challenge, state) = verify_transform(&challenge, &state, next_state, proof)
                .map_err(|_| CeremonyError::BadRequest)?;
        }
        println!("Checked all contributions in {:?}", now.elapsed());
    }
    println!("All checks successful.");
    Ok(())
}
