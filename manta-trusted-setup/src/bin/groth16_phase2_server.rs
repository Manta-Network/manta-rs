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

use clap::{Parser, Subcommand};
use manta_crypto::rand::{OsRng, Rand};
use manta_trusted_setup::ceremony::{
    config::{
        g16_bls12_381::{Groth16BLS12381, Participant, UserPriority},
        CeremonyConfig, ParticipantIdentifier,
    },
    message::ServerSize,
    registry::Registry,
    server::Server,
    signature::{ed_dalek, SignatureScheme},
    util::{load_from_file, MPCState, StateSize},
};
use std::{collections::BTreeMap, fs::File, path::Path, process::exit};
use tracing::error;

type C = Groth16BLS12381;
type S = Server<C, 2>;

/// Command
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Creates a new server.
    Create {
        registry_path: String,
        recovery_dir_path: String,
    },

    /// Recovers a server from disk.
    Recover {
        recovery_path: String,
        recovery_dir_path: String,
    },
}

/// Server CLI
#[derive(Debug, Parser)]
pub struct Arguments {
    /// Server Command
    #[clap(subcommand)]
    pub command: Command,
}

impl Arguments {
    /// Runs a server.
    #[inline]
    pub async fn run(self) {
        let server = match self.command {
            Command::Create {
                registry_path,
                recovery_dir_path,
            } => init_server(registry_path, recovery_dir_path),
            Command::Recover {
                recovery_path,
                recovery_dir_path,
            } => S::recover_from_file(recovery_path, recovery_dir_path),
        };
        println!("Network starts to run!");
        let mut api = tide::Server::with_state(server);
        api.at("/nonce").post(|r| S::execute(r, Server::get_nonce));
        api.at("/size").post(|r| S::execute(r, Server::get_state_size));
        api.at("/query").post(|r| S::execute(r, Server::query));
        api.at("/update").post(|r| S::execute(r, Server::update));
        api.listen("127.0.0.1:8080")
            .await
            .expect("Should create a listener."); // TODO: use TLS
    }
}

fn load_registry<P>(
    registry_path: P,
) -> Registry<ParticipantIdentifier<C>, <C as CeremonyConfig>::Participant>
where
    P: AsRef<Path>,
{
    let mut map = BTreeMap::new();
    for record in
        csv::Reader::from_reader(File::open(registry_path).expect("Registry file should exist."))
            .records()
    {
        let result = record.expect("Read csv should succeed.");
        let twitter = result[0].to_string();
        let email = result[1].to_string();
        let public_key = bincode::deserialize::<ed_dalek::PublicKey>(
            &bs58::decode(result[3].to_string())
                .into_vec()
                .expect("Decode public key should succeed."),
        )
        .expect("Deserialize public key should succeed.");
        ed_dalek::Ed25519::verify(
            format!(
                "manta-trusted-setup-twitter:{}, manta-trusted-setup-email:{}",
                twitter, email
            ),
            &0,
            &bincode::deserialize::<ed_dalek::Signature>(
                &bs58::decode(result[4].to_string())
                    .into_vec()
                    .expect("Decode signature should succeed."),
            )
            .expect("Deserialize signature should succeed."),
            &public_key,
        )
        .expect("Verifying signature should succeed.");
        let participant = Participant {
            twitter,
            priority: match result[2].to_string().parse::<u32>().unwrap() {
                1 => UserPriority::High,
                0 => UserPriority::Normal,
                _ => {
                    error!("Invalid priority: {:?}", result);
                    exit(1)
                }
            },
            public_key,
            nonce: OsRng.gen(),
            contributed: false,
        };
        map.insert(participant.public_key, participant);
    }
    Registry::new(map)
}

/// Initiates a server.
pub fn init_server(registry_path: String, recovery_dir_path: String) -> S {
    let registry = load_registry(registry_path);
    let mpc_state0 = load_from_file::<MPCState<Groth16BLS12381, 1>, _>(&"data/prepared_mint.data");
    let mpc_state1 =
        load_from_file::<MPCState<Groth16BLS12381, 1>, _>(&"data/prepared_private_transfer.data");
    let mpc_state2 =
        load_from_file::<MPCState<Groth16BLS12381, 1>, _>(&"data/prepared_reclaim.data");
    let size = ServerSize {
        mint: StateSize {
            gamma_abc_g1: mpc_state0.state[0].vk.gamma_abc_g1.len(),
            a_b_g1_b_g2_query: mpc_state0.state[0].a_query.len(),
            h_query: mpc_state0.state[0].h_query.len(),
            l_query: mpc_state0.state[0].l_query.len(),
        },
        private_transfer: StateSize {
            gamma_abc_g1: mpc_state1.state[0].vk.gamma_abc_g1.len(),
            a_b_g1_b_g2_query: mpc_state1.state[0].a_query.len(),
            h_query: mpc_state1.state[0].h_query.len(),
            l_query: mpc_state1.state[0].l_query.len(),
        },
        reclaim: StateSize {
            gamma_abc_g1: mpc_state2.state[0].vk.gamma_abc_g1.len(),
            a_b_g1_b_g2_query: mpc_state2.state[0].a_query.len(),
            h_query: mpc_state2.state[0].h_query.len(),
            l_query: mpc_state2.state[0].l_query.len(),
        },
    };
    S::new(
        [
            mpc_state0.state[0].clone(),
            mpc_state1.state[0].clone(),
            mpc_state2.state[0].clone(),
        ],
        [
            mpc_state0.challenge[0].clone(),
            mpc_state1.challenge[0].clone(),
            mpc_state2.challenge[0].clone(),
        ],
        registry,
        recovery_dir_path,
        size,
    )
}

#[async_std::main]
async fn main() -> tide::Result<()> {
    Arguments::parse().run().await;
    Ok(())
}
