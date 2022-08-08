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

use manta_crypto::arkworks::{pairing::Pairing, serialize::CanonicalDeserialize};
use manta_pay::crypto::constraint::arkworks::R1CS;
use manta_trusted_setup::{
    ceremony::{
        queue::{Identifier, Priority},
        server::{HasNonce, Server},
        signature::{
            ed_dalek,
            ed_dalek::{Ed25519, PublicKey},
            HasPublicKey, SignatureScheme,
        },
        CeremonyError,
    },
    groth16::{
        config::Config,
        kzg::Accumulator,
        mpc,
        mpc::{initialize, Groth16Phase2},
    },
};
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

type S = Server<Groth16Phase2<Config>, Participant, BTreeMap<PublicKey, Participant>, Ed25519, 2>;

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

fn synthesize_constraints(
    phase_one_parameters: &PhaseOneParameters,
) -> R1CS<<Config as Pairing>::Scalar> {
    let _ = phase_one_parameters;
    todo!()
}

// async fn init_server(options: &PhaseOneParameters) -> S {
//     let phase1_accumulator_bytes = async_std::fs::read(options.accumulator_path.as_str())
//         .await
//         .expect("failed to read accumulator file");
//     let powers = Accumulator::<Config>::deserialize(&phase1_accumulator_bytes[..])
//         .expect("failed to deserialize accumulator");
//     let constraints = synthesize_constraints(options);
//     let state = initialize(powers, constraints).expect("failed to initialize state");
//     let initial_challenge = <Config as mpc::ProvingKeyHasher<Config>>::hash(&state);
//     S::new(state, initial_challenge.into())
// }

#[async_std::main]
async fn main() -> tide::Result<()> {
    let options = PhaseOneParameters::load_from_args();
    // let mut api = tide::Server::with_state(init_server(&options).await);

    // api.at("/register")
    //     .post(|r| Server::execute(r, Server::register_participant));
    // api.at("/query")
    //     .post(|r| Server::execute(r, Server::get_state_and_challenge));
    // api.at("/update")
    //     .post(|r| Server::execute(r, Server::update));
    // api.listen("127.0.0.1:8080").await?;
    Ok(())
}
