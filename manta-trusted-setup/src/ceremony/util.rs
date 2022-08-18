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
    ceremony::{
        config::{g16_bls12_381::Groth16BLS12381, CeremonyConfig, Challenge, Proof, State},
        message::ServerSize,
        signature::{ed_dalek, SignatureScheme},
    },
    groth16::{
        config::Config,
        kzg::{Accumulator, Contribution},
        mpc,
        mpc::initialize,
    },
};
use alloc::string::String;
use ark_bls12_381::Fr;
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use colored::Colorize; // TODO: Try https://docs.rs/console/latest/console/
use manta_crypto::{
    arkworks::serialize::{CanonicalDeserialize, CanonicalSerialize},
    rand::{OsRng, Sample},
};
use manta_pay::{
    config::{FullParameters, Mint, PrivateTransfer, Reclaim},
    crypto::constraint::arkworks::{codec::SerializationError, R1CS},
    parameters::{load_transfer_parameters, load_utxo_accumulator_model},
};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Debug,
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
pub struct MPCState<C, const N: usize>
where
    C: CeremonyConfig,
{
    /// State
    pub state: [State<C>; N],

    /// Challenge
    pub challenge: [Challenge<C>; N],
}

impl<C, const N: usize> CanonicalSerialize for MPCState<C, N>
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

impl<C, const N: usize> CanonicalDeserialize for MPCState<C, N>
where
    C: CeremonyConfig,
    State<C>: CanonicalDeserialize + Debug,
    Challenge<C>: CanonicalDeserialize + Debug,
{
    #[inline]
    fn deserialize<R>(mut reader: R) -> Result<Self, SerializationError>
    where
        R: ark_std::io::Read,
    {
        let mut state = Vec::new();
        for _ in 0..N {
            state.push(
                CanonicalDeserialize::deserialize(&mut reader)
                    .expect("Deserialize should succeed."),
            );
        }
        let mut challenge = Vec::new();
        for _ in 0..N {
            challenge.push(
                CanonicalDeserialize::deserialize(&mut reader)
                    .expect("Deserialize should succeed."),
            );
        }
        Ok(Self {
            state: state
                .try_into()
                .expect("MPC State should contain N elements."),
            challenge: challenge
                .try_into()
                .expect("MPC State should contain N elements."),
        })
    }
}

/// Contribute States
pub struct ContributeState<C, const N: usize>
where
    C: CeremonyConfig,
{
    /// State
    pub state: [State<C>; N],

    /// Proof
    pub proof: [Proof<C>; N],
}

impl<C, const N: usize> CanonicalSerialize for ContributeState<C, N>
where
    C: CeremonyConfig,
    State<C>: CanonicalSerialize,
    Proof<C>: CanonicalSerialize,
{
    fn serialize<W>(&self, mut writer: W) -> Result<(), SerializationError>
    where
        W: ark_std::io::Write,
    {
        self.state
            .serialize(&mut writer)
            .expect("Serializing states should succeed.");
        self.proof
            .serialize(&mut writer)
            .expect("Serializing states should succeed.");
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        self.state.serialized_size() + self.proof.serialized_size()
    }
}

impl<C, const N: usize> CanonicalDeserialize for ContributeState<C, N>
where
    C: CeremonyConfig,
    State<C>: CanonicalDeserialize + Debug,
    Proof<C>: CanonicalDeserialize + Debug,
{
    fn deserialize<R>(mut reader: R) -> Result<Self, SerializationError>
    where
        R: ark_std::io::Read,
    {
        let mut state = Vec::new();
        for _ in 0..N {
            state.push(
                CanonicalDeserialize::deserialize(&mut reader)
                    .expect("Deserialize should succeed."),
            );
        }
        let mut proof = Vec::new();
        for _ in 0..N {
            proof.push(
                CanonicalDeserialize::deserialize(&mut reader)
                    .expect("Deserialize should succeed."),
            );
        }
        Ok(Self {
            state: state
                .try_into()
                .expect("Contribute State should contain N elements."),
            proof: proof
                .try_into()
                .expect("Contribute State should contain N elements."),
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
    let mpc_state: MPCState<Groth16BLS12381, 1> = MPCState {
        state: [state],
        challenge: [challenge.into()],
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

/// Registers a participant.
#[inline]
pub fn register(twitter_account: String, email: String) {
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    let seed = Seed::new(&mnemonic, "manta-trusted-setup");
    let seed_bytes = seed.as_bytes();
    assert!(ed25519_dalek::SECRET_KEY_LENGTH <= seed_bytes.len(), "Secret key length of ed25519 should be smaller than length of seed bytes from mnemonic phrases.");
    let sk = ed25519_dalek::SecretKey::from_bytes(&seed_bytes[0..ed25519_dalek::SECRET_KEY_LENGTH])
        .expect("`from_bytes` should succeed for SecretKey.");
    let pk = ed_dalek::PublicKey(ed25519_dalek::PublicKey::from(&sk).to_bytes());
    let sk = ed_dalek::PrivateKey(sk.to_bytes());
    println!(
        "Your {}: \nCopy the following text to \"Twitter\" Section in Google Sheet:\n {}\n",
        "Twitter Account".italic(),
        twitter_account.blue(),
    );
    println!(
        "Your {}: \nCopy the following text to \"Email\" Section in Google Sheet:\n {}\n",
        "Email".italic(),
        email.blue(),
    );
    println!(
        "Your {}: \nCopy the following text to \"Public Key\" Section in Google Sheet:\n {}\n",
        "Public Key".italic(),
        bs58::encode(bincode::serialize(&pk).expect("Serializing public key should succeed"))
            .into_string()
            .blue(),
    );
    println!(
        "Your {}: \nCopy the following text to \"Signature\" Section in Google Sheet: \n {}\n",
        "Signature".italic(),
        bs58::encode(
            bincode::serialize(
                &ed_dalek::Ed25519::sign(
                    format!(
                        "manta-trusted-setup-twitter:{}, manta-trusted-setup-email:{}",
                        twitter_account, email
                    ),
                    &0,
                    &pk,
                    &sk,
                )
                .expect("Signing should succeed"),
            )
            .expect("Serializing signature should succeed."),
        )
        .into_string()
        .blue()
    );
    println!(
        "Your {}: \nThe following text stores your secret for trusted setup. \
         Save the following text somewhere safe. \n DO NOT share this to anyone else! \
         Please discard this data after the trusted setup ceremony.\n {}",
        "Secret".italic(),
        mnemonic.phrase().red(),
    );
}

/// State Size
#[derive(Clone, Deserialize, Serialize)]
pub struct StateSize {
    /// Size of gamma_abc_g1 in verifying key
    pub gamma_abc_g1: usize,

    /// Size of a_query, b_g1_query, and b_g2_query which are equal
    pub a_b_g1_b_g2_query: usize,

    /// Size of h_query
    pub h_query: usize,

    /// Size of l_query
    pub l_query: usize,
}

/// Checks `states` has the same size as `size`.
pub fn check_state_size(states: &[State<Groth16BLS12381>; 3], size: &ServerSize) -> bool {
    (states[0].vk.gamma_abc_g1.len() == size.mint.gamma_abc_g1)
        || (states[0].a_query.len() == size.mint.a_b_g1_b_g2_query)
        || (states[0].b_g1_query.len() == size.mint.a_b_g1_b_g2_query)
        || (states[0].b_g2_query.len() == size.mint.a_b_g1_b_g2_query)
        || (states[0].h_query.len() == size.mint.h_query)
        || (states[0].l_query.len() == size.mint.l_query)
        || (states[1].vk.gamma_abc_g1.len() == size.private_transfer.gamma_abc_g1)
        || (states[1].a_query.len() == size.private_transfer.a_b_g1_b_g2_query)
        || (states[1].b_g1_query.len() == size.private_transfer.a_b_g1_b_g2_query)
        || (states[1].b_g2_query.len() == size.private_transfer.a_b_g1_b_g2_query)
        || (states[1].h_query.len() == size.private_transfer.h_query)
        || (states[1].l_query.len() == size.private_transfer.l_query)
        || (states[2].vk.gamma_abc_g1.len() == size.reclaim.gamma_abc_g1)
        || (states[2].a_query.len() == size.reclaim.a_b_g1_b_g2_query)
        || (states[2].b_g1_query.len() == size.reclaim.a_b_g1_b_g2_query)
        || (states[2].b_g2_query.len() == size.reclaim.a_b_g1_b_g2_query)
        || (states[2].h_query.len() == size.reclaim.h_query)
        || (states[2].l_query.len() == size.reclaim.l_query)
}

/// Testing Suite
#[cfg(test)]
mod test {
    use super::*;

    /// Tests if register is visually correct.
    #[test]
    fn register_is_visually_correct() {
        register(
            "Mantalorian".to_string(),
            "mantalorian@manta.network".to_string(),
        );
    }
}
