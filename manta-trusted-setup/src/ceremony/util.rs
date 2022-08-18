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

//! Utilities

use crate::{
    ceremony::config::{g16_bls12_381::Groth16BLS12381, CeremonyConfig, Challenge, State},
    groth16::{
        config::Config,
        kzg::{Accumulator, Contribution},
        mpc,
        mpc::initialize,
    },
};
use ark_bls12_381::Fr;
use manta_crypto::{
    arkworks::serialize::{CanonicalDeserialize, CanonicalSerialize},
    rand::{OsRng, Sample},
};
use manta_pay::{
    config::{FullParameters, Mint, PrivateTransfer, Reclaim},
    crypto::constraint::arkworks::{codec::SerializationError, R1CS},
    parameters::{load_transfer_parameters, load_utxo_accumulator_model},
};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
    time::Instant,
};

/// Logs `data` to a disk file at `path`.
#[inline]
pub fn log_to_file<T, P>(path: &P, data: T)
where
    P: AsRef<Path>,
    T: CanonicalSerialize,
{
    let mut writer = Vec::new();
    data.serialize(&mut writer)
        .expect("Serializing states should succeed.");
    let mut file = File::create(path).expect("Open file should succeed.");
    file.write_all(&writer)
        .expect("Writing phase one parameters to disk should succeed.");
    file.flush().expect("Flushing file should succeed.");
}

/// Loads `data` from a disk file at `path`.
#[inline]
pub fn load_from_file<T, P>(path: P) -> T
where
    P: AsRef<Path>,
    T: CanonicalDeserialize,
{
    let mut file = File::open(path).expect("Opening file should succeed.");
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .expect("Reading data should succeed.");
    let mut reader = &buf[..];
    CanonicalDeserialize::deserialize(&mut reader).expect("Deserialize should succeed.")
}

/// Conducts a dummy phase one trusted setup.
#[inline]
pub fn dummy_phase_one_trusted_setup() -> Accumulator<Config> {
    let mut rng = OsRng;
    let accumulator = Accumulator::default();
    let challenge = [0; 64];
    let contribution = Contribution::gen(&mut rng);
    let proof = contribution
        .proof(&challenge, &mut rng)
        .expect("The contribution proof should have been generated correctly.");
    let mut next_accumulator = accumulator.clone();
    next_accumulator.update(&contribution);
    Accumulator::verify_transform(accumulator, next_accumulator, challenge, proof)
        .expect("Accumulator should have been generated correctly.")
}

/// MPC States
pub struct MPCState<C>
where
    C: CeremonyConfig,
{
    /// State
    pub state: State<C>,

    /// Challenge
    pub challenge: Challenge<C>,
}

impl<C> CanonicalSerialize for MPCState<C>
where
    C: CeremonyConfig,
    State<C>: CanonicalSerialize,
    Challenge<C>: CanonicalSerialize,
{
    #[inline]
    fn serialize<W>(&self, mut writer: W) -> Result<(), SerializationError>
    where
        W: ark_std::io::Write,
    {
        self.state
            .serialize(&mut writer)
            .expect("Serializing states should succeed.");
        self.challenge
            .serialize(&mut writer)
            .expect("Serializing challenges should succeed.");
        Ok(())
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        self.state.serialized_size() + self.challenge.serialized_size()
    }
}

impl<C> CanonicalDeserialize for MPCState<C>
where
    C: CeremonyConfig,
    State<C>: CanonicalDeserialize,
    Challenge<C>: CanonicalDeserialize,
{
    #[inline]
    fn deserialize<R>(mut reader: R) -> Result<Self, SerializationError>
    where
        R: ark_std::io::Read,
    {
        Ok(Self {
            state: CanonicalDeserialize::deserialize(&mut reader)
                .expect("Deserialize should succeed."),
            challenge: CanonicalDeserialize::deserialize(&mut reader)
                .expect("Deserialize should succeed."),
        })
    }
}

// /// Prepares phase one parameter `powers` for phase two parameters of circuit `cs` with `name`.
// pub fn prepare_parameters<C, S, T>(powers: Accumulator<T>, cs: S, name: &str)
// where
//     C: CeremonyConfig,
//     T: kzg::Configuration + mpc::ProvingKeyHasher<T>,
//     S: ConstraintSynthesizer<T::Scalar>,
//     State<C>: CanonicalDeserialize,
//     Challenge<C>: CanonicalDeserialize,
// {
//     let now = Instant::now();
//     let state = initialize::<T, S>(powers, cs).expect("Failed to initialize state");
//     let challenge = <T as mpc::ProvingKeyHasher<T>>::hash(&state);
//     let mpc_state = MPCState::<C> {
//         state,
//         challenge: challenge.into(),
//     };
//     // log_to_file(
//     //     &format!("prepared_{}.data", name),
//     //     MPCState::<C> {
//     //         state,
//     //         challenge: challenge.into(),
//     //     },
//     // );
//     println!(
//         "Preparing Phase 2 parameters for {} circuit takes {:?}\n",
//         name,
//         now.elapsed()
//     );
// } // TODO： Make it generic

/// Prepares phase one parameter `powers` for phase two parameters of circuit `cs` with `name`.
pub fn prepare_parameters(powers: Accumulator<Config>, cs: R1CS<Fr>, name: &str) {
    let now = Instant::now();
    let state = initialize::<Config, R1CS<Fr>>(powers, cs).expect("failed to initialize state");
    let challenge = <Config as mpc::ProvingKeyHasher<Config>>::hash(&state);
    let mpc_state: MPCState<Groth16BLS12381> = MPCState {
        state,
        challenge: challenge.into(),
    };
    log_to_file(&format!("prepared_{}.data", name), mpc_state);
    println!(
        "Preparing Phase 2 parameters for {} circuit takes {:?}\n",
        name,
        now.elapsed()
    );
}

/// Prepares phase one parameters ready to use in trusted setup for phase two parameters.
pub fn prepare_phase_two_parameters(accumulator_path: String) {
    let now = Instant::now();
    let powers = load_from_file::<Accumulator<_>, _>(accumulator_path);
    println!(
        "Loading & Deserializing Phase 1 parameters takes {:?}\n",
        now.elapsed()
    );
    let transfer_parameters = load_transfer_parameters();
    let utxo_accumulator_model = load_utxo_accumulator_model();
    prepare_parameters(
        powers.clone(),
        Mint::unknown_constraints(FullParameters::new(
            &transfer_parameters,
            &utxo_accumulator_model,
        )),
        "mint",
    );
    prepare_parameters(
        powers.clone(),
        PrivateTransfer::unknown_constraints(FullParameters::new(
            &transfer_parameters,
            &utxo_accumulator_model,
        )),
        "private_transfer",
    );
    prepare_parameters(
        powers,
        Reclaim::unknown_constraints(FullParameters::new(
            &transfer_parameters,
            &utxo_accumulator_model,
        )),
        "reclaim",
    );
}
