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

use manta_crypto::{
    arkworks::serialize::CanonicalDeserialize,
    rand::{OsRng, Rand},
};
use manta_trusted_setup::{
    ceremony::{
        config::{
            g16_bls12_381::{Groth16BLS12381, Participant, UserPriority},
            CeremonyConfig, Challenge, ParticipantIdentifier, State,
        },
        registry::Registry,
        server::Server,
        signature::{ed_dalek, SignatureScheme},
    },
};
use std::{collections::BTreeMap, fs::File, io::Read, path::Path, process::exit, time::Instant};
use tracing::error;

type C = Groth16BLS12381;
type S = Server<C, 2>;

/// Server Options
pub enum ServerOptions {
    /// Creates a new server.
    Create {
        preprocessed_parameter_path: String,
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
                clap::Arg::new("parameters")
                    .short('p')
                    .long("preprocessed_parameters")
                    .help("Path to the preprocessed parameters")
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
                clap::Arg::new("recovery")
                    .short('b')
                    .long("recovery")
                    .help("Path to the recovery file")
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
                let preprocessed_parameter_path = matches.value_of("parameters").unwrap().to_string();
                let registry_path = matches.value_of("registry").unwrap().to_string();
                let recovery_dir_path = matches.value_of("backup_dir").unwrap().to_string();
                ServerOptions::Create {
                    preprocessed_parameter_path,
                    registry_path,
                    recovery_dir_path,
                }
            }
            "recover" => {
                let recovery_path = matches.value_of("recovery").unwrap().to_string();
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
            format!("manta-trusted-setup-twitter:{}, manta-trusted-setup-email:{}", twitter, email),
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

/// TODO
pub fn load_from_file<P>(path: P) -> ([State<C>; 3], [Challenge<C>; 3])
where
    P: AsRef<Path>,
{
    let now = Instant::now();
    let mut file = File::open(path).expect("Open file should succeed.");
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
    println!(
        "Deserializing Preprocessed Phase 2 parameters takes {:?}\n",
        now.elapsed()
    );
    (
        [state0, state1, state2],
        [challenge0, challenge1, challenge2], // TODO: Make this more elegant.
    )
}

/// Initiates a server.
pub fn init_server(
    preprocessed_parameter_path: String,
    registry_path: String,
    recovery_dir_path: String,
) -> S {
    let registry = load_registry(registry_path);
    let (states, challenges) = load_from_file(preprocessed_parameter_path);
    S::new(
        states,
        challenges,
        registry,
        recovery_dir_path,
    )
}

#[async_std::main]
async fn main() -> tide::Result<()> {
    tracing_subscriber::fmt().pretty().init();
    let options = ServerOptions::load_from_args();
    let server = match options {
        ServerOptions::Create {
            preprocessed_parameter_path,
            registry_path,
            recovery_dir_path,
        } => init_server(preprocessed_parameter_path, registry_path, recovery_dir_path),
        ServerOptions::Recover {
            recovery_path,
            recovery_dir_path,
        } => S::recover_from_file(recovery_path, recovery_dir_path),
    };
    println!("Network starts to run!");
    let mut api = tide::Server::with_state(server);
    api.at("/nonce").post(|r| S::execute(r, Server::get_nonce));
    api.at("/query")
        .post(|r| S::execute(r, Server::query));
    api.at("/update").post(|r| S::execute(r, Server::update));
    api.listen("127.0.0.1:8080").await?; // TODO: use TLS
    Ok(())
}
