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
    ceremony::{config::CeremonyConfig, state::MPCState},
    groth16::{
        kzg::{self, Accumulator, Contribution, Size},
        mpc::{self, initialize, Groth16Phase2},
    },
    util::{Deserializer, G1Type, G2Type, Serializer},
};
use alloc::string::String;
use ark_bls12_381::Fr;
use manta_crypto::{
    arkworks::{
        pairing::Pairing,
        relations::r1cs::ConstraintSynthesizer,
        serialize::{CanonicalDeserialize, CanonicalSerialize},
    },
    permutation::duplex::Setup,
    rand::{OsRng, Sample},
};
use manta_pay::{
    config::{FullParameters, Mint, PrivateTransfer, Reclaim},
    crypto::constraint::arkworks::R1CS,
    parameters::{load_transfer_parameters, load_utxo_accumulator_model},
};
use std::{
    fmt::Debug,
    fs::File,
    io::{Read, Write},
    path::Path,
    time::Instant,
};

/// Logs `data` to a disk file at `path`.
#[inline]
pub fn log_to_file<T, P>(path: &P, data: &T)
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
    P: AsRef<Path> + Debug,
    T: CanonicalDeserialize,
{
    let mut file = File::open(path).expect("Opening file should succeed.");
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .expect("Reading data should succeed.");
    let mut reader = &buf[..];
    CanonicalDeserialize::deserialize(&mut reader).expect("Deserialize should succeed.")
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
        state: [state],
        challenge: [challenge.into()],
    };
    log_to_file(&format!("prepared_{}.data", name), &mpc_state);
    println!(
        "Preparing Phase 2 parameters for {} circuit takes {:?}\n",
        name,
        now.elapsed()
    );
}

/// Has Contributed
pub trait HasContributed {
    /// Checks if the participant has contributed.
    fn has_contributed(&self) -> bool;

    /// Sets the participant as contributed.
    fn set_contributed(&mut self);
}
