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

extern crate alloc;

use alloc::string::String;
use clap::{Parser, Subcommand};
use colored::Colorize;
use core::{
    fmt::{Display, Formatter},
    time::Duration,
};
use dialoguer::{theme::ColorfulTheme, Input};
use manta_crypto::rand::{OsRng, RngCore};
use manta_trusted_setup::ceremony::{
    config::{g16_bls12_381::Groth16BLS12381, Nonce, PrivateKey, PublicKey},
    message::QueryMPCStateResponse,
    signature::{ed_dalek, SignatureScheme},
    CeremonyError,
};
use serde::{de::DeserializeOwned, Serialize};
use std::thread;

pub type C = Groth16BLS12381;
pub type Config = manta_trusted_setup::groth16::config::Config;
pub type Client = manta_trusted_setup::ceremony::client::Client<C>;

const SERVER_ADDR: &str = "http://localhost:8080";

#[derive(Debug, Copy, Clone)]
pub enum Endpoint {
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
pub enum Error {
    InvalidSecret,
    UnableToGenerateRequest(&'static str),
    NotRegistered,
    AlreadyContributed,
    UnexpectedError(String),
    NetworkError(String),
}

impl Display for Error {
    #[inline]
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
            Error::NotRegistered => {
                write!(f, "You have not registered yet. ")
            }
            Error::NetworkError(msg) => {
                write!(f, "Network Error: {}", msg)
            }
            Error::AlreadyContributed => {
                write!(f, "You have already contributed. ")
            }
        }
    }
}

/// Handles errors.
#[inline]
pub fn handle_error<T>(result: Result<T, Error>) -> T {
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

/// Command Line Arguments
#[derive(Debug, Parser)]
pub struct Arguments {
    /// Command
    #[clap(subcommand)]
    command: Command,
}

impl Arguments {
    /// Takes command line arguments and executes the corresponding operations.
    #[inline]
    pub fn run(self) -> Result<(), Error> {
        match self.command {
            Command::Register => {
                register();
                Ok(())
            }
            Command::Contribute => {
                match tokio::runtime::Builder::new_multi_thread() // TODO
                    .worker_threads(4)
                    .enable_io()
                    .enable_time()
                    .build()
                {
                    Ok(runtime) => runtime.block_on(async { contribute().await }),
                    Err(err) => Err(Error::UnexpectedError(format!("{}", err))),
                }
            }
        }
    }
}

/// Registers a participant.
#[inline]
pub fn register() {
    let twitter_account: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Your twitter account")
        .interact_text()
        .expect("");
    let mut secret_key_bytes = [0u8; ed25519_dalek::SECRET_KEY_LENGTH];
    OsRng.fill_bytes(&mut secret_key_bytes);
    let sk = ed25519_dalek::SecretKey::from_bytes(&secret_key_bytes)
        .expect("`from_bytes` should succeed for SecretKey.");
    let pk = ed_dalek::PublicKey(ed25519_dalek::PublicKey::from(&sk).to_bytes());
    let sk = ed_dalek::PrivateKey(sk.to_bytes());
    println!(
        "Your {}: \nCopy the following text to \"Twitter\" Section in Google Sheet:\n {}\n",
        "Twitter Account".italic(),
        twitter_account.blue(),
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
                    format!("manta-trusted-setup-twitter:{}", twitter_account),
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
        bs58::encode(bincode::serialize(&(pk, sk)).expect("Serializing keypair should succeed"))
            .into_string()
            .red(),
    );
}

/// Prompts the client information.
#[inline]
pub fn prompt_client_info() -> Result<(PublicKey<C>, PrivateKey<C>), Error> {
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

/// Sends requests thourgh network.
#[inline]
pub async fn send_request<T, R>(
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
        .map_err(|e| Error::NetworkError(format!("Network Error. {}", e)))?
        .json::<Result<R, CeremonyError<C>>>()
        .await
        .map_err(|e| Error::UnexpectedError(format!("JSON deserialization error: {}", e)))
}

/// Gets nonce from server.
#[inline]
pub async fn get_nonce(
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

/// Contributes to the server.
#[inline]
pub async fn contribute() -> Result<(), Error> {
    let network_client = reqwest::Client::new();
    let (pk, sk) = prompt_client_info()?;
    let nonce = get_nonce(pk, &network_client).await?;
    let mut trusted_setup_client = Client::new(pk, pk, nonce, sk);
    loop {
        match send_request::<_, ()>(
            &network_client,
            Endpoint::Enqueue,
            trusted_setup_client
                .enqueue()
                .map_err(|_| Error::UnableToGenerateRequest("enqueue"))?,
        )
        .await?
        {
            Err(CeremonyError::NotRegistered) => return Err(Error::NotRegistered),
            Err(CeremonyError::NonceNotInSync(nonce)) => {
                trusted_setup_client.set_nonce(nonce);
                continue;
            }
            Err(CeremonyError::BadRequest) => {
                return Err(Error::UnexpectedError(
                    "unexpected error when enqueueing since finding a bad request.".to_string(),
                ))
            }
            Err(CeremonyError::AlreadyContributed) => return Err(Error::AlreadyContributed),
            Ok(_) => {}
        }
        let (state, challenge) = match send_request::<_, QueryMPCStateResponse<C>>(
            &network_client,
            Endpoint::Query,
            trusted_setup_client
                .query_mpc_state()
                .map_err(|_| Error::UnableToGenerateRequest("query mpc state"))?,
        )
        .await?
        {
            Err(CeremonyError::NotRegistered) => return Err(Error::NotRegistered),
            Err(CeremonyError::NonceNotInSync(_)) => {
                return Err(Error::UnexpectedError(
                    "unexpected error when query mpc state. Nonce should have been synced."
                        .to_string(),
                ))
            }
            Err(CeremonyError::BadRequest) => {
                return Err(Error::UnexpectedError(
                    "unexpected error when query mpc state since finding a bad request."
                        .to_string(),
                ))
            }
            Err(CeremonyError::AlreadyContributed) => return Err(Error::AlreadyContributed),
            Ok(message) => match message {
                QueryMPCStateResponse::QueuePosition(position) => {
                    println!("Your current position is {}.", position);
                    thread::sleep(Duration::from_millis(10000));
                    continue;
                }
                QueryMPCStateResponse::Mpc(state, challenge) => (
                    state.to_actual().expect("`to_actual` should succeed."),
                    challenge.to_actual().expect("`to_actual` should succeed."),
                ),
            },
        };
        match send_request::<_, ()>(
            &network_client,
            Endpoint::Update,
            trusted_setup_client
                .contribute(&Config::generate_hasher(), &challenge, state)
                .map_err(|_| Error::UnableToGenerateRequest("contribute"))?,
        )
        .await?
        {
            Err(CeremonyError::NotRegistered) => {
                return Err(Error::UnexpectedError(
                    "unexpected error when contribute. Should have registered.".to_string(),
                ))
            }
            Err(CeremonyError::NonceNotInSync(_)) => {
                return Err(Error::UnexpectedError(
                    "unexpected error when contribute. Nonce should have been synced.".to_string(),
                ))
            }
            Err(CeremonyError::BadRequest) => {
                return Err(Error::UnexpectedError(
                    "unexpected error when contribute since finding a bad request.".to_string(),
                ))
            }
            Err(CeremonyError::AlreadyContributed) => return Err(Error::AlreadyContributed),
            Ok(_) => {
                println!("Contribute succeeded!");
                break;
            }
        }
    }
    Ok(())
}

fn main() {
    handle_error(Arguments::parse().run());
}
