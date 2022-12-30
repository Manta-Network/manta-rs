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
use manta_trusted_setup::{
    ceremony::util::deserialize_from_file,
    groth16::ceremony::{
        config::ppot::Config, message::ContributeResponse, server::filename_format, Ceremony,
        CeremonyError,
    },
};
use manta_util::Array;
use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

// cargo run --release --package manta-trusted-setup --all-features --bin contribution_hash_calculator -- /Users/thomascnorton/Documents/Manta/ceremony_hashes_22_12_29
// cargo run --release --package manta-trusted-setup --all-features --bin contribution_hash_calculator -- /Users/thomascnorton/Desktop/server_data_test

/// The names used by the ceremony coordinator server
const _NAMES: [&str; 3] = ["to_private", "to_public", "private_transfer"];

/// Given path to challenge files, returns
/// all challenges as owned `Vec`. Assumes
/// coordinator server used above [`NAMES`].
fn _read_challenges_from_verify_output(path: &Path) -> Vec<[Array<u8, 64>; 3]> {
    let to_private_reader = BufReader::new(
        File::open(path.join("to_private_computed_challenges")).expect("Unable to open file"),
    )
    .lines();
    let to_public_reader = BufReader::new(
        File::open(path.join("to_public_computed_challenges")).expect("Unable to open file"),
    )
    .lines();
    let private_transfer_reader = BufReader::new(
        File::open(path.join("private_transfer_computed_challenges")).expect("Unable to open file"),
    )
    .lines();
    // Collect these:
    let mut result = Vec::new();
    for ((a, b), c) in to_private_reader
        .zip(to_public_reader)
        .zip(private_transfer_reader)
    {
        match ((a, b), c) {
            ((Ok(a), Ok(b)), Ok(c)) => {
                let challenges = [
                    Array::from_vec(hex::decode(&a[1..129]).unwrap()),
                    Array::from_vec(hex::decode(&b[1..129]).unwrap()),
                    Array::from_vec(hex::decode(&c[1..129]).unwrap()),
                ];
                result.push(challenges);
            }
            _ => println!("Read error"),
        }
    }
    result
}

/// Given path to challenge files, returns all challenges as owned `Vec`.
/// Assumes coordinator server used above [`NAMES`] and that all rounds
/// are present.
fn read_challenges_from_ceremony_archive(path: &Path) -> Vec<[Array<u8, 64>; 3]> {
    let rounds: u64 = deserialize_from_file(path.join(r"round_number")).unwrap();
    let mut result = Vec::new();
    for i in 1..rounds {
        let challenges = [
            deserialize_from_file(filename_format(
                path,
                "to_private".to_string(),
                "challenge".to_string(),
                i,
            ))
            .expect("Unable to deserialize challenge hash"),
            deserialize_from_file(filename_format(
                path,
                "to_public".to_string(),
                "challenge".to_string(),
                i,
            ))
            .expect("Unable to deserialize challenge hash"),
            deserialize_from_file(filename_format(
                path,
                "private_transfer".to_string(),
                "challenge".to_string(),
                i,
            ))
            .expect("Unable to deserialize challenge hash"),
        ];
        result.push(challenges);
    }
    result
}

/// Converts a vector of challenge hashes from individual circuits into
/// an overall contribution hash (i.e. those announced by participants on Twitter).
/// Assumes vector starts at given round.
fn consolidate_hashes(hashes: Vec<[Array<u8, 64>; 3]>, starting_round: u64) -> Vec<String> {
    let mut index = starting_round;
    hashes
        .iter()
        .map(|hashes| {
            let contribution_response = ContributeResponse::<Config> {
                index,
                challenge: Vec::<Array<u8, 64>>::from(&hashes[..]),
            };
            index += 1;
            hex::encode(<Config as Ceremony>::contribution_hash(
                &contribution_response,
            ))
        })
        .collect()
}

/// Writes a list of contributions to an output file in directory
/// specified by `path`.
fn write_to_file(path: &Path, hashes: Vec<String>, starting_round: usize) {
    let mut output =
        File::create(path.join("ceremony_contribution_hashes")).expect("Unable to create file");
    for (i, hash) in hashes.iter().enumerate() {
        writeln!(output, "{hash} Contribution {} ", i + starting_round)
            .expect("Unable to write to file");
    }
}

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
        let challenge_hashes = consolidate_hashes(read_challenges_from_ceremony_archive(&path), 1);
        write_to_file(&path, challenge_hashes, 1);
        Ok(())
    }
}

fn main() {
    Arguments::parse().run().unwrap();
}
