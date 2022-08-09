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

use ark_bls12_381::Fr;
use manta_crypto::{arkworks::pairing::Pairing, rand::Sample};
use manta_pay::crypto::constraint::arkworks::R1CS;
use manta_trusted_setup::{
    ceremony::{
        queue::{Identifier, Priority},
        server::{HasNonce, Server},
        signature::{
            ed_dalek,
            ed_dalek::{Ed25519, PublicKey},
            HasPublicKey,
        },
        CeremonyError,
    },
    groth16::{
        config::{dummy_circuit, Config},
        kzg::{Accumulator, Contribution},
        mpc,
        mpc::{initialize, Groth16Phase2},
    },
};
use rand_chacha::rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Participant
#[derive(Clone, Serialize, Deserialize)]
struct Participant {
    /// Public Key
    pub public_key: PublicKey,

    /// Identifier
    pub identifier: String,

    /// Priority
    pub priority: usize,

    /// Nonce
    pub nonce: u64,

    /// Boolean on whether this participant has contributed
    pub contributed: bool,
}

impl Priority for Participant {
    fn priority(&self) -> usize {
        self.priority
    }
}

impl Identifier for Participant {
    type Identifier = String;

    fn identifier(&self) -> Self::Identifier {
        self.identifier.clone() // TODO
    }
}

impl HasPublicKey for Participant {
    type PublicKey = ed_dalek::PublicKey;

    fn public_key(&self) -> Self::PublicKey {
        self.public_key
    }
}

impl HasNonce<Ed25519> for Participant {
    fn nonce(&self) -> u64 {
        self.nonce
    }

    fn update_nonce(&mut self, nonce: u64) -> Result<(), CeremonyError> {
        if self.nonce >= nonce {
            return Err(CeremonyError::InvalidNonce);
        }
        self.nonce = nonce;
        Ok(())
    }

    fn increase_nonce(&mut self) -> Result<(), CeremonyError> {
        self.nonce += 1;
        Ok(())
    }
}

type S = Server<Groth16Phase2<Config>, Participant, BTreeMap<String, Participant>, Ed25519, 2>;

///
pub struct PhaseOneParameters {
    phase_one_parameter_path: String,
}

impl PhaseOneParameters {
    fn load_from_args() -> Self {
        PhaseOneParameters {
            phase_one_parameter_path: clap::App::new("Trusted Setup Ceremony Server")
                .version("0.1.0")
                .author("Manta Network")
                .about("Trusted Setup Ceremony Server")
                .arg(
                    clap::Arg::new("accumulator_path")
                        .short('a')
                        .long("accumulator_path")
                        .help("Path to the accumulator")
                        .takes_value(true)
                        .required(true),
                )
                .get_matches()
                .value_of("accumulator_path")
                .expect("parameter accumulator_path is required")
                .to_string(),
        }
    }
}

fn synthesize_constraints(// phase_one_parameters: &PhaseOneParameters,
) -> R1CS<<Config as Pairing>::Scalar> {
    let mut cs = R1CS::for_contexts();
    dummy_circuit(&mut cs); // TO be changed
    cs
}

// TODO: To be replaced with production circuit.
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

// TO be updated
async fn init_server(options: &PhaseOneParameters) -> S {
    // let phase1_accumulator_bytes = async_std::fs::read(options.phase_one_parameter_path.as_str())
    //     .await
    //     .expect("failed to read accumulator file");
    // let powers = CanonicalDeserialize::deserialize(phase1_accumulator_bytes.as_slice()).unwrap();
    // let dummy_phase_one_parameter = fs::read("/home/boyuan/manta/code/manta-rs/manta-trusted-setup/dummy_phase_one_parameter.data").await.unwrap();
    // let powers =
    //     CanonicalDeserialize::deserialize(dummy_phase_one_parameter.as_slice()).unwrap();
    let _ = options;
    let powers = dummy_phase_one_trusted_setup(); // TODO: To be replaced with disk file
    let constraints = synthesize_constraints();
    let state =
        initialize::<Config, R1CS<Fr>>(powers, constraints).expect("failed to initialize state");
    let initial_challenge = <Config as mpc::ProvingKeyHasher<Config>>::hash(&state);
    let server = S::new(state, initial_challenge.into());

    // TODO: Only have temporary code here for testing.
    let dummy_public_key = PublicKey([
        104, 148, 44, 244, 61, 116, 39, 8, 68, 216, 6, 24, 232, 68, 239, 203, 198, 2, 138, 148,
        242, 73, 122, 3, 19, 236, 195, 133, 136, 137, 146, 108,
    ]);
    let dummy_participant = Participant {
        public_key: dummy_public_key,
        identifier: "happy".to_string(),
        priority: 0,
        nonce: 0,
        contributed: false,
    };
    server
        .coordinator
        .lock()
        .expect("Failed to lock coordinator")
        .register(dummy_participant)
        .expect("Register dummy participant should succeed.");
    server
}

#[async_std::main]
async fn main() -> tide::Result<()> {
    let options = PhaseOneParameters::load_from_args();
    let mut api = tide::Server::with_state(init_server(&options).await);
    api.at("/").get(|_| async { Ok("Hello, world!") });
    api.at("/register")
        .post(|r| Server::execute(r, Server::register_participant));
    api.at("/query")
        .post(|r| Server::execute(r, Server::get_state_and_challenge));
    api.at("/update")
        .post(|r| Server::execute(r, Server::update));
    api.listen("127.0.0.1:8080").await?;
    Ok(())
}

// cargo run --release --package manta-trusted-setup --bin groth16_phase2_server -- --accumulator_path xxx

// cs.constraint_count(): 17706
// Finished trusted setup phase one takes 286.423455189s

// Wrote phase one parameters to disk. Took 221.491831ms

// Initialize Phase 2 parameters takes 895.588149647s

// On client side, contribute Phase 2 parameters takes 10.574934047s
// On server side, verify transform for Phase 2 parameters takes 23.006557103s
// On client side, contribute Phase 2 parameters takes 11.101973456s
// On server side, verify transform for Phase 2 parameters takes 23.046081274s
// On client side, contribute Phase 2 parameters takes 10.418395032s
// On server side, verify transform for Phase 2 parameters takes 23.041631704s
// On client side, contribute Phase 2 parameters takes 10.510215602s
// On server side, verify transform for Phase 2 parameters takes 22.873919112s
// On client side, contribute Phase 2 parameters takes 10.300151345s
// On server side, verify transform for Phase 2 parameters takes 22.742186574s
// Given 5 contributions, verify transform all for Phase 2 parameters takes 22.963527386s
