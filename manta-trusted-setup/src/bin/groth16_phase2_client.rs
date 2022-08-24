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
use clap::{Parser, Subcommand};
use console::{style, Term};
use dialoguer::{theme::ColorfulTheme, Input};
use manta_trusted_setup::ceremony::{
    client::{handle_error, prompt_client_info, register, Client, Endpoint, Error},
    config::{
        check_state_size, config::Config, g16_bls12_381::Groth16BLS12381, Nonce, PrivateKey,
        PublicKey,
    },
    message::{CeremonyError, QueryResponse},
    signature::ed_dalek,
    state::ServerSize,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{thread, time};

/// Welcome Message
pub const TITLE: &str = r"
 __  __             _          _______             _           _    _____      _               
|  \/  |           | |        |__   __|           | |         | |  / ____|    | |              
| \  / | __ _ _ __ | |_ __ _     | |_ __ _   _ ___| |_ ___  __| | | (___   ___| |_ _   _ _ __  
| |\/| |/ _` | '_ \| __/ _` |    | | '__| | | / __| __/ _ \/ _` |  \___ \ / _ | __| | | | '_ \ 
| |  | | (_| | | | | || (_| |    | | |  | |_| \__ | ||  __| (_| |  ____) |  __| |_| |_| | |_) |
|_|  |_|\__,_|_| |_|\__\__,_|    |_|_|   \__,_|___/\__\___|\__,_| |_____/ \___|\__|\__,_| .__/ 
                                                                                        | |    
                                                                                        |_|    
";

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
        println!("{}", TITLE);
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
                match tokio::runtime::Builder::new_multi_thread()
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
pub fn get_client_keys() -> Result<(PublicKey<Groth16BLS12381>, PrivateKey<Groth16BLS12381>), Error>
{
    let seed_bytes = prompt_client_info();
    assert!(ed25519_dalek::SECRET_KEY_LENGTH <= seed_bytes.len(), "Secret key length of ed25519 should be smaller than length of seed bytes from mnemonic phrases.");
    let sk = ed25519_dalek::SecretKey::from_bytes(&seed_bytes[0..ed25519_dalek::SECRET_KEY_LENGTH])
        .expect("`from_bytes` should succeed for SecretKey.");
    let pk = ed_dalek::PublicKey(ed25519_dalek::PublicKey::from(&sk).to_bytes().into());
    let sk = ed_dalek::PrivateKey(sk.to_bytes().into());
    Ok((pk, sk))
}

/// Sends requests thourgh network. TODO: something similar in manta-util
#[inline]
pub async fn send_request<T, R>(
    network_client: &reqwest::Client,
    endpoint: Endpoint,
    request: T,
) -> Result<Result<R, CeremonyError<Groth16BLS12381>>, Error>
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
        .json::<Result<R, CeremonyError<Groth16BLS12381>>>()
        .await
        .map_err(|e| Error::UnexpectedError(format!("JSON deserialization error: {}", e)))
}

/// Gets state size from server.
#[inline]
pub async fn get_start_meta_data(
    identity: PublicKey<Groth16BLS12381>,
    network_client: &reqwest::Client,
) -> Result<(ServerSize, Nonce<Groth16BLS12381>), Error> {
    let response = send_request::<_, (ServerSize, Nonce<Groth16BLS12381>)>(
        network_client,
        Endpoint::Start,
        identity,
    )
    .await?;
    match response {
        Ok((server_size, nonce)) => Ok((server_size, nonce)),
        Err(CeremonyError::NotRegistered) => Err(Error::NotRegistered),
        Err(e) => Err(Error::UnexpectedError(format!("{:?}", e))),
    }
}

/// Contributes to the server.
#[inline]
pub async fn contribute() -> Result<(), Error> {
    let network_client = reqwest::Client::new();
    let (pk, sk) = get_client_keys()?;
    println!(
        "{} Contacting Server for Meta Data...",
        style("[1/9]").bold().dim()
    );
    let term = Term::stdout();
    let (size, nonce) = get_start_meta_data(pk, &network_client).await?;
    let mut trusted_setup_client = Client::<Groth16BLS12381>::new(pk, pk, nonce, sk);
    println!("{} Waiting in Queue...", style("[2/9]").bold().dim(),);
    loop {
        let mpc_state = match send_request::<_, QueryResponse<Groth16BLS12381>>(
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
                    "Unexpected error when query mpc state. Nonce should have been synced."
                        .to_string(),
                ))
            }
            Err(CeremonyError::BadRequest) => {
                return Err(Error::UnexpectedError(
                    "Unexpected error when query mpc state since finding a bad request."
                        .to_string(),
                ))
            }
            Err(CeremonyError::AlreadyContributed) => return Err(Error::AlreadyContributed),
            Err(CeremonyError::NotYourTurn) => {
                return Err(Error::UnexpectedError(
                    "Unexpected error when query mpc state. Should not receive NotYourTurn message."
                        .to_string(),
                ));
            }
            Ok(message) => match message {
                QueryResponse::QueuePosition(position) => {
                    term.clear_last_lines(1)
                        .expect("Clear last lines should succeed.");
                    println!(
                        "{} Waiting in Queue... There are {} people ahead of you. Estimated Waiting Time: {} minutes.",
                        style("[2/9]").bold().dim(),
                        style(position).bold().red(),
                        style(5*position).bold().blue(),
                    );
                    thread::sleep(time::Duration::from_secs(10));
                    continue;
                }
                QueryResponse::Mpc(mpc_state) => {
                    term.clear_last_lines(1)
                        .expect("Clear last lines should succeed.");
                    println!("{} Waiting in Queue...", style("[2/9]").bold().dim(),);
                    println!(
                        "{} Downloading Ceremony States...",
                        style("[3/9]").bold().dim(),
                    );
                    // TODO: Add a progress bar here
                    let mpc_state = mpc_state.to_actual().map_err(|_| {
                        Error::UnexpectedError("Received mpc state cannot be parsed.".to_string())
                    })?;
                    if !check_state_size(&mpc_state.state, &size) {
                        return Err(Error::UnexpectedError(
                            "Received mpc state size is not correct.".to_string(),
                        ));
                    }
                    mpc_state
                }
            },
        };
        println!(
            "{} Starting contribution to 3 Circuits...",
            style("[4/9]").bold().dim(),
        );
        match send_request::<_, ()>(
            &network_client,
            Endpoint::Update,
            trusted_setup_client
                .contribute(
                    &Config::generate_hasher(),
                    &mpc_state.challenge,
                    mpc_state.state,
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
            Err(CeremonyError::NotYourTurn) => {
                println!(
                    "{} Lag behind server. Contacting Server again...",
                    style("[8/9]").bold().dim(),
                );
                continue;
            }
            Err(CeremonyError::AlreadyContributed) => return Err(Error::AlreadyContributed),
            Ok(_) => {
                term.clear_last_lines(1)
                    .expect("Clear last lines should succeed.");
                println!(
                    "{} Waiting for Confirmation from Server...",
                    style("[8/9]").bold().dim(),
                );
                println!(
                    "{} Congratulations! You have successfully contributed to Manta Trusted Setup Ceremony!...",
                    style("[9/9]").bold().dim(),
                );
                break;
            }
        }
    }
    Ok(())
}

fn main() {
    handle_error(Arguments::parse().run());
}
