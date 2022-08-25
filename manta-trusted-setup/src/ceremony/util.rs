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

extern crate alloc;

use crate::{
    ceremony::{config::CeremonyConfig, message::MPCState},
    groth16::{
        kzg::{self, Accumulator, Size},
        mpc::{self, initialize, Groth16Phase2},
    },
    util::AsBytes,
};
use manta_crypto::arkworks::{
    pairing::Pairing, relations::r1cs::ConstraintSynthesizer, serialize::CanonicalSerialize,
};
use manta_util::{
    serde::{de::DeserializeOwned, Serialize},
    Array,
};
use std::{fmt::Debug, fs::File, io::Write, path::Path, time::Instant};

/// Logs `data` to a disk file at `path`.
#[inline]
pub fn log_to_file<T, P>(path: &P, data: &T)
where
    P: AsRef<Path>,
    T: Serialize,
{
    let mut file = File::create(path).expect("Open file should succeed.");
    serde_json::to_writer(&mut file, &data)
        .expect("Writing phase one parameters to disk should succeed.");
    file.flush().expect("Flushing file should succeed.");
}

/// Loads `data` from a disk file at `path`.
#[inline]
pub fn load_from_file<'de, T, P>(path: P) -> T
where
    P: AsRef<Path> + Debug,
    T: DeserializeOwned,
{
    let mut file = File::open(path).expect("Opening file should succeed.");
    serde_json::from_reader(&mut file).expect("Reading and deserializing data should succeed.")
}

/// Prepares phase one parameter `powers` for phase two parameters of circuit `cs` with `name`.
#[inline]
pub fn prepare_parameters<C, D, S>(powers: Accumulator<C>, cs: S, name: &str)
where
    C: Pairing + Size + kzg::Configuration + mpc::ProvingKeyHasher<C> + mpc::Configuration,
    S: ConstraintSynthesizer<C::Scalar>,
    D: CeremonyConfig<Setup = Groth16Phase2<C>>,
    <C as mpc::Configuration>::Challenge:
        From<<C as mpc::ProvingKeyHasher<C>>::Output> + CanonicalSerialize,
{
    let now = Instant::now();
    let state = initialize::<C, S>(powers, cs).expect("failed to initialize state");
    let challenge = <C as mpc::ProvingKeyHasher<C>>::hash(&state);
    let mpc_state: MPCState<D, 1> = MPCState {
        state: Array::from_unchecked([AsBytes::from_actual(state)]),
        challenge: Array::from_unchecked([AsBytes::from_actual(challenge.into())]),
    };
    log_to_file(&format!("prepared_{}.data", name), &mpc_state);
    println!(
        "Preparing Phase 2 parameters for {} circuit takes {:?}\n",
        name,
        now.elapsed()
    );
}
