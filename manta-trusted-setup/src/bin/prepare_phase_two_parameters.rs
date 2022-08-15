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

//! Trusted Setup Phase Two Parameters Preparation

use ark_bls12_381::Fr;
use manta_crypto::{
    arkworks::serialize::{CanonicalDeserialize, CanonicalSerialize},
    rand::{OsRng, Rand},
};
use manta_pay::{
    config::{FullParameters, Mint, PrivateTransfer, Reclaim},
    crypto::constraint::arkworks::R1CS,
};
use manta_trusted_setup::{
    ceremony::config::{g16_bls12_381::Groth16BLS12381, Challenge, State},
    groth16::{kzg::Accumulator, mpc, mpc::initialize},
};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
    time::Instant,
};

type C = Groth16BLS12381;
type Config = manta_trusted_setup::groth16::config::Config;

const ACCUMULATOR: &str = "dummy_phase_one_parameter.data";
const PREPARED: &str = "prepared_phase_two_parameter.data";

/// TO be updated
pub fn prepare_phase_two_parameters(accumulator_path: String, prepared_path: String) {
    let now = Instant::now();
    let mut file =
        File::open(accumulator_path).expect("Opening phase one parameter file should succeed.");
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .expect("Reading phase one parameter should succeed.");
    let mut reader = &buf[..];
    let powers: Accumulator<Config> = CanonicalDeserialize::deserialize(&mut reader)
        .expect("Deserialize phase one parameter should succeed.");
    println!(
        "Loading & Deserializing Phase 1 parameters takes {:?}\n",
        now.elapsed()
    );
    let mut rng = OsRng;
    let state0 = initialize::<Config, R1CS<Fr>>(
        powers.clone(),
        Mint::unknown_constraints(FullParameters::new(&rng.gen(), &rng.gen())), // TODO: Check constants in FullParameters
    )
    .expect("failed to initialize state");
    let state1 = initialize::<Config, R1CS<Fr>>(
        powers.clone(),
        PrivateTransfer::unknown_constraints(FullParameters::new(&rng.gen(), &rng.gen())), // TODO: Check constants in FullParameters
    )
    .expect("failed to initialize state");
    let state2 = initialize::<Config, R1CS<Fr>>(
        powers,
        Reclaim::unknown_constraints(FullParameters::new(&rng.gen(), &rng.gen())), // TODO: Check constants in FullParameters
    )
    .expect("failed to initialize state");
    let states = [state0, state1, state2];
    let challenges: [Challenge<C>; 3] = states
        .iter()
        .map(|state| <Config as mpc::ProvingKeyHasher<Config>>::hash(&state).into())
        .collect::<Vec<Challenge<C>>>()
        .try_into()
        .expect("Should produce an array of length 3.");
    log_to_file(prepared_path, states, challenges);
}

/// TODO
pub fn log_to_file<P>(path: P, states: [State<C>; 3], challenges: [Challenge<C>; 3])
where
    P: AsRef<Path>,
{
    let mut writer = Vec::new();
    let _ = states
        .into_iter()
        .map(|state| {
            state
                .serialize(&mut writer)
                .expect("Serializing states should succeed.");
        })
        .collect::<()>();
    let _ = challenges
        .into_iter()
        .map(|challenge| {
            challenge
                .serialize(&mut writer)
                .expect("Serializing challenges should succeed.");
        })
        .collect::<()>();
    let mut file = File::create(path).expect("Open file should succeed.");
    file.write_all(&writer)
        .expect("Write phase one parameters to disk should succeed.");
    file.flush().expect("Unable to flush file.");
}

/// TODO
pub fn load_from_file<P>(path: P) -> ([State<C>; 3], [Challenge<C>; 3])
where
    P: AsRef<Path>,
{
    let mut file = File::create(path).expect("Open file should succeed.");
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .expect("Reading data should succeed.");
    let mut reader = &buf[..];
    let state0 =
        CanonicalDeserialize::deserialize(&mut reader).expect("Deserialize should succeed.");
    let state1 =
        CanonicalDeserialize::deserialize(&mut reader).expect("Deserialize should succeed.");
    let state2 =
        CanonicalDeserialize::deserialize(&mut reader).expect("Deserialize should succeed.");
    let challenge0 =
        CanonicalDeserialize::deserialize(&mut reader).expect("Deserialize should succeed.");
    let challenge1 =
        CanonicalDeserialize::deserialize(&mut reader).expect("Deserialize should succeed.");
    let challenge2 =
        CanonicalDeserialize::deserialize(&mut reader).expect("Deserialize should succeed.");
    (
        [state0, state1, state2],
        [challenge0, challenge1, challenge2], // TODO: Make this more elegant.
    )
}

fn main() {
    prepare_phase_two_parameters(ACCUMULATOR.into(), PREPARED.into());
    load_from_file(PREPARED);
}

// cargo run --release --package manta-trusted-setup --bin prepare_phase_two_parameters
