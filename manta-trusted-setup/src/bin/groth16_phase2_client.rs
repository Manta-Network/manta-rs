// // Copyright 2019-2022 Manta Network.
// // This file is part of manta-rs.
// //
// // manta-rs is free software: you can redistribute it and/or modify
// // it under the terms of the GNU General Public License as published by
// // the Free Software Foundation, either version 3 of the License, or
// // (at your option) any later version.
// //
// // manta-rs is distributed in the hope that it will be useful,
// // but WITHOUT ANY WARRANTY; without even the implied warranty of
// // MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// // GNU General Public License for more details.
// //
// // You should have received a copy of the GNU General Public License
// // along with manta-rs.  If not, see <http://www.gnu.org/licenses/>.

// //! Trusted Setup Ceremony Client

// extern crate alloc;

// use alloc::string::String;
use clap::{Parser, Subcommand};
// use colored::Colorize;
// use core::fmt::{Display, Formatter};
// use dialoguer::{theme::ColorfulTheme, Input};
// use ed25519_dalek::SecretKey;
// use manta_crypto::rand::{OsRng, RngCore};
// use manta_trusted_setup::{
//     ceremony::{
//         client::Client,
//         message::{ContributeResponse, QueryMPCStateResponse},
//         queue::Priority,
//         server::HasNonce,
//         signature::{
//             ed_dalek::{self, Ed25519, PrivateKey, PublicKey},
//             HasPublicKey, SignatureScheme,
//         },
//         CeremonyError,
//     },
//     groth16::{ceremony::Participant, config::Config, mpc::Groth16Phase2},
// };
// use serde::{Deserialize, Serialize};
// use std::{thread, time::Duration};

use colored::Colorize;
use dialoguer::{theme::ColorfulTheme, Input};
use ed25519_dalek::SecretKey;
use manta_crypto::rand::{OsRng, RngCore};
use manta_trusted_setup::ceremony::{
    config::{g16_bls12_381::Groth16BLS12381, Nonce, PrivateKey, PublicKey},
    signature::{ed_dalek, SignatureScheme},
    CeremonyError,
};
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::{Display, Formatter};

type C = Groth16BLS12381;
type Config = manta_trusted_setup::groth16::config::Config;

const SERVER_ADDR: &str = "http://localhost:8080";

#[derive(Debug, Copy, Clone)]
enum Endpoint {
    Enqueue,
    Query,
    Update,
    Nonce,
}

impl From<Endpoint> for String {
    fn from(endpoint: Endpoint) -> String {
        let operation = match endpoint {
            Endpoint::Enqueue => "enqueue",
            Endpoint::Query => "query",
            Endpoint::Update => "update",
            Endpoint::Nonce => "nonce",
        };
        format!("{}/{}", SERVER_ADDR, operation)
    }
}

#[derive(Clone, Debug)]
enum Error {
    InvalidSecret,
    UnableToGenerateRequest(&'static str),
    MissingConfigFile,
    InvalidConfigFile,
    NotRegistered,
    UnexpectedError(String),
    NetworkError(String),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidSecret => {
                write!(f, "Your {} is invalid. Please try again", "secret".italic())
            }
            Error::UnableToGenerateRequest(msg) => {
                write!(f, "Unable to generate request: {}", msg)
            }
            Error::UnexpectedError(msg) => {
                write!(f, "Unexpected Error: {}", msg)
            }
            Error::MissingConfigFile => {
                write!(f, "Missing config file trusted_setup_config.toml")
            }
            Error::InvalidConfigFile => {
                write!(f, "Invalid config file trusted_setup_config.toml")
            }
            Error::NotRegistered => {
                write!(f, "You have not registered yet. ")
            }
            Error::NetworkError(msg) => {
                write!(f, "Network Error: {}", msg)
            }
        }
    }
}

fn handle_error<T>(result: Result<T, Error>) -> T {
    match result {
        Ok(x) => x,
        Err(e) => {
            println!("{}: {}", "error".red().bold(), e);
            std::process::exit(1);
        }
    }
}

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
    pub fn run(self) -> Result<(), Error> {
        match self.command {
            Command::Register => {
                todo!()
            }
            Command::Contribute => {
                match tokio::runtime::Builder::new_multi_thread() // TODO
                    .worker_threads(4)
                    .enable_io()
                    .enable_time()
                    .build()
                {
                    Ok(runtime) => runtime.block_on(async { todo!() }).map_err(|_| todo!()),
                    Err(err) => Err(Error::UnexpectedError(format!("{}", err))),
                }
            }
        }
    }
}

/// Sample random seed and generate public key, printing both to stdout.
#[inline]
pub fn register() {
    // Read in twitter account name
    let twitter_account: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Your twitter account")
        .interact_text()
        .expect("");

    // Generate sk,pk from entropy
    let mut rng = OsRng;
    let mut secret_key_bytes = [0u8; ed25519_dalek::SECRET_KEY_LENGTH];
    rng.fill_bytes(&mut secret_key_bytes);
    let sk = ed25519_dalek::SecretKey::from_bytes(&secret_key_bytes);
    let pk = ed_dalek::PublicKey(
        ed25519_dalek::PublicKey::from(
            &SecretKey::from_bytes(&secret_key_bytes).expect("`from_bytes` should succeed"),
        )
        .to_bytes(),
    );

    let pk_serialized = bincode::serialize(&pk).expect("Serializing public key should succeed");
    let pk_str = bs58::encode(pk_serialized).into_string();
    let keypair_serialized =
        bincode::serialize(&(pk, sk)).expect("Serializing keypair should succeed"); // TODO: Will the user be stupid and send the seed to google form?
    let keypair_str = bs58::encode(keypair_serialized).into_string();

    let signature = ed_dalek::Ed25519::sign(
        format!("manta-trusted-setup-twitter:{}", twitter_account),
        &0,
        &pk,
        &sk,
    )
    .expect("Signing should succeed");
    let signature_serialized =
        bincode::serialize(&signature).expect("Serializing signature should succeed.");
    let signature_str = bs58::encode(signature_serialized).into_string();

    println!(
        "Your {}: \nCopy the following text to \"Twitter\" Section in Google Form:\n {}\n\n\n\n",
        "Twitter Account".italic(),
        twitter_account.blue(),
    );

    println!(
        "Your {}: \nCopy the following text to \"Public Key\" Section in Google Form:\n {}\n\n\n\n",
        "Public Key".italic(),
        pk_str.blue(),
    );

    println!(
        "Your {}: \nCopy the following text to \"Signature\" Section in Google Form: \n {}\n\n\n\n",
        "Signature".italic(),
        signature_str.blue()
    );

    println!(
        "Your {}: \nThe following text stores your secret for trusted setup.\
         Save the following text somewhere safe. \n DO NOT share this to anyone else!\
          Please discard this data after the trusted setup ceremony.\n {}",
        "Secret".italic(),
        keypair_str.red(),
    );
}

type Client = manta_trusted_setup::ceremony::client::Client<C>;

/// Client Client Info from stdin
fn prompt_client_info() -> Result<(PrivateKey<C>, PublicKey<C>), Error> {
    println!(
        "Please enter your {} that you get when you registered yourself using this tool.",
        "Secret".italic()
    );
    let secret_str: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Your Secret")
        .interact_text()
        .expect("Please enter your secret received during `Register`.");
    let secret_bytes = bs58::decode(&secret_str)
        .into_vec()
        .map_err(|_| Error::InvalidSecret)?;

    bincode::deserialize(&secret_bytes).map_err(|_| Error::InvalidSecret)
}

async fn send_request<T, R>(
    network_client: &reqwest::Client,
    endpoint: Endpoint,
    request: T,
) -> Result<Result<R, CeremonyError<C>>, Error>
where
    T: Serialize,
    R: DeserializeOwned,
{
    network_client
        .post(String::from(endpoint))
        .json(&request)
        .send()
        .await
        .map_err(|e| Error::NetworkError(format!("{}", e)))?
        .json::<Result<R, CeremonyError<C>>>()
        .await
        .map_err(|e| Error::UnexpectedError(format!("{}", e)))
}

/// Get nonce from server
async fn get_nonce(
    identity: PublicKey<C>,
    network_client: &reqwest::Client,
) -> Result<Nonce<C>, Error> {
    let get_nonce_request = identity;
    let response =
        send_request::<_, Nonce<C>>(network_client, Endpoint::Nonce, get_nonce_request).await?;
    match response {
        Ok(nonce) => Ok(nonce),
        Err(CeremonyError::NotRegistered) => Err(Error::NotRegistered),
        Err(e) => Err(Error::UnexpectedError(format!("{:?}", e))),
    }
}

/// Run `reqwest` contribution client, takes seed as input.
#[inline]
pub async fn contribute() -> Result<(), Error> {
    // Note: seed is the same as the one used during registration.

    // Generate sk, pk from seed
    let network_client = reqwest::Client::new();
    let (sk, pk) = prompt_client_info()?;
    let nonce = get_nonce(pk, &network_client).await?;
    let mut trusted_setup_client = Client::new(pk, pk, nonce, sk);

    loop {
        let enqueue_request = trusted_setup_client
            .enqueue()
            .map_err(|_| Error::UnableToGenerateRequest("enqueue"))?;

        let enqueue_response =
            send_request::<_, ()>(&network_client, Endpoint::Enqueue, enqueue_request).await?;
        match enqueue_response {
            Err(CeremonyError::NotRegistered) => return Err(Error::NotRegistered),
            Err(CeremonyError::NonceNotInSync(nonce)) => {
                trusted_setup_client.set_nonce(nonce);
                continue;
            }
            Err(CeremonyError::BadRequest) => {
                return Err(Error::UnexpectedError(
                    "unexpected error when enqueueing".to_string(),
                ))
            }
            Ok(_) => {}
        }

        // // TODO: Handle nonce
        // let query_mpc_state_request = trusted_setup_client.query_mpc_state();
        // let query_mpc_state_response = network_client
        //     .post(Endpoint::Query.into())
        //     .json(&query_mpc_state_request)
        //     .send()
        //     .await
        //     .unwrap();
        // // let parsed_query_mpc_state_response = match query_mpc_state_response.status() {
        // //     reqwest::StatusCode::OK => {
        // //         query_mpc_state_response.json::<QueryMPCStateResponse<Groth16Phase2<Config>>>().await.unwrap();
        // //     }
        // //     other => {
        // //         panic!("Uh No! Something unexpected happend: {:?}", other);
        // //     }
        // // };
        // let parsed_query_mpc_state_response = query_mpc_state_response
        //     .json::<QueryMPCStateResponse<Groth16Phase2<Config>>>()
        //     .await
        //     .unwrap(); // TODO: Error handling here if response status is bad.
        // let (state, challenge) = match parsed_query_mpc_state_response {
        //     QueryMPCStateResponse::Mpc(state, challenge) => {
        //         (state.to_actual(), challenge.to_actual())
        //     }
        //     QueryMPCStateResponse::QueuePosition(t) => {
        //         println!("Your current position is {}.", t);
        //         thread::sleep(Duration::from_millis(300000));
        //         continue;
        //     }
        //     QueryMPCStateResponse::NotRegistered => {
        //         println!("You have not registered.");
        //         return Ok(());
        //     }
        //     QueryMPCStateResponse::HaveContributed => {
        //         println!("You have contributed.");
        //         return Ok(());
        //     }
        // };
        // let h = Config::generate_hasher();
        // // <Config as mpc::Configuration>::Hasher;
        // let contribute_request =
        //     trusted_setup_client.contribute::<Groth16Phase2<Config>>(&h, &challenge, state);
        // let contribute_response = network_client
        //     .post("http://localhost:8080/update") // TODO: Change HTTP path
        //     .json(&contribute_request)
        //     .send()
        //     .await
        //     .unwrap();
        // let parsed_contribute_response = contribute_response
        //     .json::<ContributeResponse>()
        //     .await
        //     .unwrap(); // TODO: Error handling here if response status is bad.
        //                // TODO: Need to handle the case if contribute failed due to network reason or other reasons.
        // println!("Contribute succeed: {:?}", parsed_contribute_response);
        // break;
    }
    Ok(())
}

fn main() {
    handle_error(Arguments::parse().run()); // TODO: When should we stop?
}

// cargo --bin xxx -- contribute
// cargo --bin xxx -- register
