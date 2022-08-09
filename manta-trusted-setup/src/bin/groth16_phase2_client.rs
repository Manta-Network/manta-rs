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

//! Trusted Setup Ceremony Client

extern crate alloc;

use alloc::string::String;
use blake2::Blake2b512;
use clap::{Error, Parser, Subcommand};
use dialoguer::{theme::ColorfulTheme, Input};
use ed25519_dalek::Keypair;
use manta_crypto::arkworks::{pairing::Pairing, serialize::CanonicalDeserialize};
use manta_pay::crypto::constraint::arkworks::R1CS;
use manta_trusted_setup::{
    ceremony::{
        client::Client,
        message::{ContributeResponse, QueryMPCStateResponse},
        queue::{Identifier, Priority},
        server::{HasNonce, Server},
        signature::{
            ed_dalek::{self, Ed25519, PrivateKey, PublicKey},
            HasPublicKey, SignatureScheme,
        },
        CeremonyError,
    },
    groth16::{
        config::Config,
        kzg::{Accumulator, Configuration},
        mpc,
        mpc::{initialize, Groth16Phase2},
    },
    mpc::Contribute,
    util::BlakeHasher,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, thread, time::Duration};

///
pub type Result<T = (), E = Error> = core::result::Result<T, E>;

/// Command
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Register for the Trusted Setup Ceremony
    Register,

    /// Runs the Trusted Setup Ceremony as a Contributor
    Contribute,
}

/// Trusted Setup Contributor
#[derive(Debug, Parser)]
pub struct Arguments {
    /// Command
    #[clap(subcommand)]
    pub command: Command,
}

impl Arguments {
    ///
    #[inline]
    pub fn run(self) -> Result {
        match self.command {
            Command::Register => register().map_err(|_| todo!()),
            Command::Contribute => {
                match tokio::runtime::Builder::new_multi_thread() // TODO
                    .worker_threads(4)
                    .enable_io()
                    .enable_time()
                    .build()
                {
                    Ok(runtime) => runtime
                        .block_on(async { contribute().await })
                        .map_err(|_| todo!()),
                    Err(err) => {
                        let _ = err;
                        todo!()
                    }
                }
            }
        }
    }
}

/// Sample random seed and generate public key, printing both to stdout. Then, takes twitter account
/// from stdin (dialoguer crate) and generates payload for registration form.
#[inline]
pub fn register() -> Result<(), ()> {
    // Generate seed
    let seed = ();

    // Print seed
    println!("SEED: {:?}", seed);

    // Generate sk,pk from seed
    let (sk, pk) = ((), ());

    // Read in twitter account name
    let twitter: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Your twitter account")
        .interact_text()
        .expect("");

    // Sign message with `sk` (the message has to include the twitter account).
    let signature = ();

    // Print out pk
    println!("Public Key: {:?}", pk);

    // Print out signature
    println!("Signature: {:?}", signature);

    Ok(()) // TODO: This goes into google form
}

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

type C = Client<Ed25519, Participant>;

fn init_participant() -> Participant {
    // TODO: Only have temporary code here for testing.
    let public_key = PublicKey([
        104, 148, 44, 244, 61, 116, 39, 8, 68, 216, 6, 24, 232, 68, 239, 203, 198, 2, 138, 148,
        242, 73, 122, 3, 19, 236, 195, 133, 136, 137, 146, 108,
    ]);
    Participant {
        public_key,
        identifier: "happy".to_string(),
        priority: 0,
        nonce: 0,
        contributed: false,
    }
}

use ed25519_dalek::Signature;

fn init_key_pair<S>(seed: String) -> (S::PrivateKey, S::PublicKey)
where
    S: SignatureScheme<PrivateKey = ed_dalek::PrivateKey, PublicKey = ed_dalek::PublicKey>,
{
    // TODO. Hardcode a seed for temporary testing.
    // let keypair: Keypair = Keypair::generate(&mut seed);
    let private_key = PrivateKey([
        149, 167, 173, 208, 224, 206, 37, 70, 87, 169, 157, 198, 120, 32, 151, 88, 25, 10, 12, 215,
        80, 124, 187, 129, 183, 96, 103, 11, 191, 255, 33, 105,
    ]);
    let public_key = PublicKey([
        104, 148, 44, 244, 61, 116, 39, 8, 68, 216, 6, 24, 232, 68, 239, 203, 198, 2, 138, 148,
        242, 73, 122, 3, 19, 236, 195, 133, 136, 137, 146, 108,
    ]);
    (private_key, public_key)
}

/// Run `reqwest` contribution client, takes seed as input.
#[inline]
pub async fn contribute() -> Result<(), ()> {
    // Note: seed is the same as the one used during registration.
    // TODO: In every message, return the nonce of the specific user.
    let seed: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Seed")
        .validate_with(move |input: &String| -> Result<(), &str> {
            // Check that it is a valid seed phrase and return `Err("error message")` if not
            // todo!()
            Ok(()) // TODO
        })
        .interact_text()
        .expect("");

    // Generate sk, pk from seed
    let key_pair = init_key_pair::<Ed25519>(seed); // TODO

    // Run ceremony client
    let participant = init_participant();
    let mut trusted_setup_client = C::new(participant, key_pair);

    let network_client = reqwest::Client::new();

    loop {
        // TODO: Handle nonce
        let query_mpc_state_request = trusted_setup_client.query_mpc_state();
        let query_mpc_state_response = network_client
            .post("http://localhost:8080/query") // TODO: Change HTTP path
            .json(&query_mpc_state_request)
            .send()
            .await
            .unwrap();
        // let parsed_query_mpc_state_response = match query_mpc_state_response.status() {
        //     reqwest::StatusCode::OK => {
        //         query_mpc_state_response.json::<QueryMPCStateResponse<Groth16Phase2<Config>>>().await.unwrap();
        //     }
        //     other => {
        //         panic!("Uh No! Something unexpected happend: {:?}", other);
        //     }
        // };
        let parsed_query_mpc_state_response = query_mpc_state_response
            .json::<QueryMPCStateResponse<Groth16Phase2<Config>>>()
            .await
            .unwrap(); // TODO: Error handling here if response status is bad.
        let (state, challenge) = match parsed_query_mpc_state_response {
            QueryMPCStateResponse::Mpc(state, challenge) => {
                (state.to_actual(), challenge.to_actual())
            }
            QueryMPCStateResponse::QueuePosition(t) => {
                println!("Your current position is {}.", t);
                thread::sleep(Duration::from_millis(300000));
                continue;
            }
            QueryMPCStateResponse::NotRegistered => {
                println!("You have not registered.");
                return Ok(());
            }
            QueryMPCStateResponse::HaveContributed => {
                println!("You have contributed.");
                return Ok(());
            }
        };
        let h = Config::generate_hasher();
        // <Config as mpc::Configuration>::Hasher;
        let contribute_request =
            trusted_setup_client.contribute::<Groth16Phase2<Config>>(&h, &challenge, state);
        let contribute_response = network_client
            .post("http://localhost:8080/update") // TODO: Change HTTP path
            .json(&contribute_request)
            .send()
            .await
            .unwrap();
        let parsed_contribute_response = contribute_response
            .json::<ContributeResponse>()
            .await
            .unwrap(); // TODO: Error handling here if response status is bad.
                       // TODO: Need to handle the case if contribute failed due to network reason or other reasons.
        println!("Contribute succeed: {:?}", parsed_contribute_response);
        break;
    }
    Ok(())
}

fn main() {
    Arguments::parse().run(); // TODO: When should we stop?
}
