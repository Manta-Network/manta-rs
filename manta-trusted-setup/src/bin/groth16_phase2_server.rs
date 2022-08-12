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
use manta_crypto::{
    arkworks::pairing::Pairing,
    rand::{OsRng, Rand, Sample},
};
use manta_pay::crypto::constraint::arkworks::R1CS;
use manta_trusted_setup::{
    ceremony::{
        config::{
            g16_bls12_381::{Groth16BLS12381, Participant, UserPriority},
            CeremonyConfig, ParticipantIdentifier,
        },
        registry::Registry,
        server::Server,
        signature::{ed_dalek, SignatureScheme},
    },
    groth16::{
        config::dummy_circuit,
        kzg::{Accumulator, Contribution},
        mpc,
        mpc::initialize,
    },
};
use std::{collections::BTreeMap, fs::File, path::Path, process::exit};
use tracing::error;

type C = Groth16BLS12381;
type Config = manta_trusted_setup::groth16::config::Config;
type S = Server<C, 2>;

/// Registry File Path
pub const REGISTRY: &str = "dummy_register.csv"; // TODO: Replace with real registry

/// Server Options
pub enum ServerOptions {
    /// Creates a new server.
    Create {
        accumulator_path: String,
        registry_path: String,
        recovery_dir_path: String,
    },
    /// Recovers a server from disk.
    Recover {
        recovery_path: String,
        recovery_dir_path: String,
    },
}

impl ServerOptions {
    pub fn load_from_args() -> Self {
        let matches = clap::App::new("Trusted Setup Ceremony Server")
            .version("0.1.0")
            .author("Manta Network")
            .about("Trusted Setup Ceremony Server")
            .arg(
                clap::Arg::new("mode")
                    .help("The mode for the server, can be either 'create' or 'recover'")
                    .takes_value(true)
                    .required(true),
            )
            .arg(
                clap::Arg::new("accumulator")
                    .short('a')
                    .long("accumulator")
                    .help("Path to the accumulator")
                    .takes_value(true)
                    .required_if_eq("mode", "create"),
            )
            .arg(
                clap::Arg::new("registry")
                    .short('r')
                    .long("registry")
                    .help("Path to the registry")
                    .takes_value(true)
                    .required_if_eq("mode", "create"),
            )
            .arg(
                clap::Arg::new("backup")
                    .short('b')
                    .long("backup")
                    .help("Path to the backup file")
                    .takes_value(true)
                    .required_if_eq("mode", "recover"),
            )
            .arg(
                clap::Arg::new("backup_dir")
                    .short('d')
                    .long("backup_dir")
                    .help("Path to the backup directory")
                    .takes_value(true)
                    .required(true),
            )
            .get_matches();

        let mode = matches.value_of("mode").unwrap();
        match mode {
            "create" => {
                let accumulator_path = matches.value_of("accumulator").unwrap().to_string();
                let registry_path = matches.value_of("registry").unwrap().to_string();
                let recovery_dir_path = matches.value_of("backup_dir").unwrap().to_string();
                ServerOptions::Create {
                    accumulator_path,
                    registry_path,
                    recovery_dir_path,
                }
            }
            "recover" => {
                let recovery_path = matches.value_of("backup").unwrap().to_string();
                let recovery_dir_path = matches.value_of("backup_dir").unwrap().to_string();
                ServerOptions::Recover {
                    recovery_path,
                    recovery_dir_path,
                }
            }
            _ => {
                panic!("Invalid mode: {}", mode); // TODO: better error message (like client)
            }
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
        let public_key = bincode::deserialize::<ed_dalek::PublicKey>(
            &bs58::decode(result[2].to_string())
                .into_vec()
                .expect("Decode public key should succeed."),
        )
        .expect("Deserialize public key should succeed.");
        ed_dalek::Ed25519::verify(
            format!("manta-trusted-setup-twitter:{}", twitter),
            &0,
            &bincode::deserialize::<ed_dalek::Signature>(
                &bs58::decode(result[3].to_string())
                    .into_vec()
                    .expect("Decode signature should succeed."),
            )
            .expect("Deserialize signature should succeed."),
            &public_key,
        )
        .expect("Verifying signature should succeed.");
        let participant = Participant {
            twitter,
            priority: match result[1].to_string().parse::<u32>().unwrap() {
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

// TO be updated
fn init_server(accumulator_path: String, registry_path: String, recovery_dir_path: String) -> S {
    let _ = accumulator_path; // TODO
    let powers = dummy_phase_one_trusted_setup(); // TODO: To be replaced with disk file
    let constraints = synthesize_constraints();
    let state =
        initialize::<Config, R1CS<Fr>>(powers, constraints).expect("failed to initialize state");
    let initial_challenge = <Config as mpc::ProvingKeyHasher<Config>>::hash(&state);
    let registry = load_registry(registry_path);
    S::new(state, initial_challenge.into(), registry, recovery_dir_path)
}

#[async_std::main]
async fn main() -> tide::Result<()> {
    tracing_subscriber::fmt().pretty().init();
    let options = ServerOptions::load_from_args();
    let server = match options {
        ServerOptions::Create {
            accumulator_path,
            registry_path,
            recovery_dir_path,
        } => init_server(accumulator_path, registry_path, recovery_dir_path),
        ServerOptions::Recover {
            recovery_path,
            recovery_dir_path,
        } => S::recover_from_file(recovery_path, recovery_dir_path),
    };
    let mut api = tide::Server::with_state(server);
    api.at("/enqueue")
        .post(|r| S::execute(r, Server::enqueue_participant));
    api.at("/query")
        .post(|r| S::execute(r, Server::get_state_and_challenge));
    api.at("/update").post(|r| S::execute(r, Server::update));
    api.at("/nonce").post(|r| S::execute(r, Server::get_nonce));
    api.listen("127.0.0.1:8080").await?; // TODO: use TLS
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
