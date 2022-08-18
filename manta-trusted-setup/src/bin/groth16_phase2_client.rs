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
use bip39::{Language, Mnemonic, Seed};
use clap::{Parser, Subcommand};
use colored::Colorize; // TODO: Try https://docs.rs/console/latest/console/
use core::fmt::{Display, Formatter};
use dialoguer::{theme::ColorfulTheme, Input};
use indicatif::ProgressBar;
use manta_trusted_setup::ceremony::{
    config::{g16_bls12_381::Groth16BLS12381, Nonce, PrivateKey, PublicKey},
    message::{QueryResponse, ServerSize, SizeRequest},
    signature::ed_dalek,
    util::{register, check_state_size},
    CeremonyError,
};
use serde::{de::DeserializeOwned, Serialize};

pub type C = Groth16BLS12381;
pub type Config = manta_trusted_setup::groth16::config::Config;
pub type Client = manta_trusted_setup::ceremony::client::Client<C>;

const SERVER_ADDR: &str = "http://localhost:8080";

#[derive(Debug, Copy, Clone)]
pub enum Endpoint {
    Query,
    Update,
    Nonce,
    Size,
}

impl From<Endpoint> for String {
    fn from(endpoint: Endpoint) -> String {
        let operation = match endpoint {
            Endpoint::Query => "query",
            Endpoint::Update => "update",
            Endpoint::Nonce => "nonce",
            Endpoint::Size => "size",
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
                let twitter_account = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Your twitter account")
                    .interact_text()
                    .expect("");
                let email = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Your email")
                    .interact_text()
                    .expect("");
                register(twitter_account, email);
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

/// Prompts the client information.
#[inline]
pub fn prompt_client_info() -> Result<(PublicKey<C>, PrivateKey<C>), Error> {
    println!(
        "Please enter your {} that you get when you registered yourself using this tool.",
        "Secret".italic()
    );
    let secret_str: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Your Secret")
        .validate_with(|input: &String| -> Result<(), &str> {
            if Mnemonic::validate(&input, Language::English).is_ok() {
                Ok(())
            } else {
                Err("This is not a valid secret.")
            }
        })
        .interact_text()
        .expect("Please enter your secret received during `Register`.");
    let mnemonic = Mnemonic::from_phrase(secret_str.as_str(), Language::English)
        .expect("Should produce a mnemonic from the secret.");
    let seed = Seed::new(&mnemonic, "manta-trusted-setup");
    let seed_bytes = seed.as_bytes();
    assert!(ed25519_dalek::SECRET_KEY_LENGTH <= seed_bytes.len(), "Secret key length of ed25519 should be smaller than length of seed bytes from mnemonic phrases.");
    let sk = ed25519_dalek::SecretKey::from_bytes(&seed_bytes[0..ed25519_dalek::SECRET_KEY_LENGTH])
        .expect("`from_bytes` should succeed for SecretKey.");
    let pk = ed_dalek::PublicKey(ed25519_dalek::PublicKey::from(&sk).to_bytes());
    let sk = ed_dalek::PrivateKey(sk.to_bytes());
    Ok((pk, sk))
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

/// Gets state size from server.
#[inline]
pub async fn get_state_size(network_client: &reqwest::Client) -> Result<ServerSize, Error> {
    let response =
        send_request::<_, ServerSize>(network_client, Endpoint::Nonce, SizeRequest).await?;
    match response {
        Ok(size) => Ok(size),
        Err(CeremonyError::NotRegistered) => Err(Error::NotRegistered),
        Err(e) => Err(Error::UnexpectedError(format!("{:?}", e))),
    }
}

/// Contributes to the server.
#[inline]
pub async fn contribute() -> Result<(), Error> {
    let network_client = reqwest::Client::new();
    let (pk, sk) = prompt_client_info()?;
    let size = get_state_size(&network_client).await?;
    let nonce = get_nonce(pk, &network_client).await?;
    let mut trusted_setup_client = Client::new(pk, pk, nonce, sk);
    loop {
        let mpc_state = match send_request::<_, QueryResponse<C>>(
            &network_client,
            Endpoint::Query,
            trusted_setup_client
                .query()
                .map_err(|_| Error::UnableToGenerateRequest("Queries the server state."))?,
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
                QueryResponse::QueuePosition(position) => {
                    println!("Your current position is {}.", position);
                    continue;
                }
                QueryResponse::Mpc(mpc_state) => {
                    let mpc_state = mpc_state.to_actual().map_err(|_| {
                        Error::UnexpectedError("Received mpc state cannot be parsed.".to_string())
                    })?;
                    if !check_state_size(&mpc_state.state, &size) {
                        return Err(Error::UnexpectedError(
                            "Received mpc state size is not correct."
                                .to_string(),
                        ))
                    }
                    mpc_state
                }
            },
        };
        println!("It's YOUR turn to contribute!");
        let bar = ProgressBar::new(5);
        match send_request::<_, ()>(
            &network_client,
            Endpoint::Update,
            trusted_setup_client
                .contribute(
                    &Config::generate_hasher(),
                    &mpc_state.challenge,
                    mpc_state.state,
                    &bar,
                )
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
                bar.inc(1);
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
