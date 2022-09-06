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

//! Asynchronous client for trusted setup.

use crate::{
    ceremony::{
        config::{
            g16_bls12_381::Groth16BLS12381, CeremonyConfig, Challenge, Hasher, Nonce,
            ParticipantIdentifier, PrivateKey, Proof, PublicKey, State,
        },
        message::{
            CeremonyError, ContributeRequest, ContributeState, QueryRequest, QueryResponse,
            ServerSize, Signed,
        },
        participant::HasIdentifier,
        signature::{ed_dalek::Ed25519, sign},
        util::check_state_size,
    },
    mpc::{Contribute, Types},
    util::AsBytes,
};
use ark_groth16::ProvingKey;
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use colored::Colorize;
use console::{style, Term};
use core::fmt::{Debug, Display, Formatter};
use dialoguer::{theme::ColorfulTheme, Input};
use manta_crypto::{
    arkworks::{
        ec::PairingEngine,
        pairing::Pairing,
        serialize::{CanonicalDeserialize, CanonicalSerialize},
    },
    rand::OsRng,
    signature::{SigningKeyType, VerifyingKeyType},
};
use manta_util::{
    http::reqwest::KnownUrlClient,
    serde::{de::DeserializeOwned, Serialize},
    Array,
};
use std::{thread, time::Duration};

/// Client
pub struct Client<C, const CIRCUIT_COUNT: usize>
where
    C: CeremonyConfig,
{
    /// Identifier
    identifier: ParticipantIdentifier<C>,

    /// Current Nonce
    nonce: Nonce<C>,

    /// Private Key
    private_key: PrivateKey<C>,
}

impl<C, const CIRCUIT_COUNT: usize> Client<C, CIRCUIT_COUNT>
where
    C: CeremonyConfig,
{
    /// Builds a new [`Client`] with `participant` and `private_key`.
    #[inline]
    pub fn new(
        identifier: ParticipantIdentifier<C>,
        nonce: Nonce<C>,
        private_key: PrivateKey<C>,
    ) -> Self {
        Self {
            identifier,
            nonce,
            private_key,
        }
    }

    /// Queries the server state.
    #[inline]
    pub fn query(&mut self) -> Result<Signed<QueryRequest, C>, ()>
    where
        C::Participant: Clone,
    {
        Signed::new(
            QueryRequest,
            self.identifier.clone(),
            &mut self.nonce,
            &self.private_key,
        )
    }

    /// Contributes to the state on the server.
    #[inline]
    pub fn contribute(
        &mut self,
        hasher: &Hasher<C>,
        challenge: &Array<AsBytes<Challenge<C>>, CIRCUIT_COUNT>,
        mut state: Array<AsBytes<State<C>>, CIRCUIT_COUNT>,
    ) -> Result<Signed<ContributeRequest<C, CIRCUIT_COUNT>, C>, ()>
    where
        C::Participant: Clone,
        State<C>: CanonicalDeserialize + CanonicalSerialize,
        Proof<C>: CanonicalSerialize,
        Challenge<C>: CanonicalDeserialize,
    {
        let circuit_name = ["ToPrivate", "PrivateTransfer", "ToPublic"];
        let mut rng = OsRng;
        let mut proofs = Vec::new();
        for i in 0..CIRCUIT_COUNT {
            println!(
                "{} Contributing to {} Circuits...",
                style(format!("[{}/9]", i + 5)).bold().dim(),
                circuit_name[i],
            );
            let cur_challenge =
                AsBytes::to_actual(&challenge[i]).expect("To_actual should succeed.");
            let mut cur_state = AsBytes::to_actual(&state[i]).expect("To_actual should succeed.");
            let proof = AsBytes::from_actual(
                C::Setup::contribute(hasher, &cur_challenge, &mut cur_state, &mut rng).ok_or(())?,
            );
            proofs.push(proof);
            state[i] = AsBytes::from_actual(cur_state);
        }
        println!(
            "{} Waiting for Confirmation from Server... Estimated Waiting Time: {} minutes.",
            style("[8/9]").bold().dim(),
            style("3").bold().blue(),
        );
        Signed::new(
            ContributeRequest {
                contribute_state: ContributeState {
                    state,
                    proof: Array::from_unchecked(proofs),
                },
            },
            self.identifier.clone(),
            &mut self.nonce,
            &self.private_key,
        )
    }
}

/// Registers a participant.
#[inline]
pub fn register(twitter_account: String, email: String) {
    println!(
        "Your {}: \nCopy the following text to \"Twitter\" Section in Google Sheet:\n {}\n",
        "Twitter Account".italic(),
        twitter_account.blue(),
    );
    println!(
        "Your {}: \nCopy the following text to \"Email\" Section in Google Sheet:\n {}\n",
        "Email".italic(),
        email.blue(),
    );
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    let seed = Seed::new(&mnemonic, "manta-trusted-setup");
    let (sk, pk) = Ed25519::generate_keys(seed.as_bytes());
    println!(
        "Your {}: \nCopy the following text to \"Public Key\" Section in Google Sheet:\n {}\n",
        "Public Key".italic(),
        bs58::encode(pk).into_string().blue(),
    );
    let signature = sign::<_, Ed25519>(
        &format!(
            "manta-trusted-setup-twitter:{}, manta-trusted-setup-email:{}",
            twitter_account, email
        ),
        0,
        &sk,
    );
    println!(
        "Your {}: \nCopy the following text to \"Signature\" Section in Google Sheet: \n {}\n",
        "Signature".italic(),
        bs58::encode(signature).into_string().blue()
    );
    println!(
        "Your {}: \nThe following text stores your secret for trusted setup. \
         Save the following text somewhere safe. \n DO NOT share this to anyone else! \
         Please discard this data after the trusted setup ceremony.\n {}",
        "Secret".italic(),
        mnemonic.phrase().red(),
    );
}

/// Client Error
#[derive(Clone, Debug)]
pub enum Error {
    /// Invalid Secret
    InvalidSecret,

    /// Unable to Generate Request
    UnableToGenerateRequest(&'static str),

    /// Not Registered
    NotRegistered,

    /// User Already Contributed
    AlreadyContributed,

    /// Unexpected Error
    UnexpectedError(String),

    /// Network Error
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

/// Prompts the client information.
#[inline]
pub fn prompt_client_info() -> Vec<u8> {
    println!(
        "Please enter your {} that you get when you registered yourself using this tool.",
        "Secret".italic()
    );
    Seed::new(
        &Mnemonic::from_phrase(
            Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Your Secret")
                .validate_with(|input: &String| -> Result<(), &str> {
                    Mnemonic::validate(input, Language::English)
                        .map_err(|_| "This is not a valid secret.")
                })
                .interact_text()
                .expect("Please enter your secret received during `Register`.")
                .as_str(),
            Language::English,
        )
        .expect("Should produce a mnemonic from the secret."),
        "manta-trusted-setup",
    )
    .as_bytes()
    .to_vec()
}

/// Prompts the client information.
#[inline]
pub fn get_client_keys() -> Result<
    (
        <Ed25519 as SigningKeyType>::SigningKey,
        <Ed25519 as VerifyingKeyType>::VerifyingKey,
    ),
    Error,
> {
    let seed_bytes = prompt_client_info();
    Ok(Ed25519::generate_keys(&seed_bytes))
}

/// Gets state size from server.
#[inline]
pub async fn get_start_meta_data<C, const CIRCUIT_COUNT: usize>(
    identity: ParticipantIdentifier<C>,
    network_client: &KnownUrlClient,
) -> Result<(ServerSize<CIRCUIT_COUNT>, Nonce<C>), Error>
where
    C: CeremonyConfig,
    ParticipantIdentifier<C>: Serialize,
    Nonce<C>: DeserializeOwned + Debug,
{
    match network_client
        .post::<_, Result<(ServerSize<CIRCUIT_COUNT>, Nonce<C>), CeremonyError<C>>>(
            "start", &identity,
        )
        .await
        .map_err(|_| {
            return Error::NetworkError(
                "Should have received starting meta data from server".to_string(),
            );
        })? {
        Ok((server_size, nonce)) => Ok((server_size, nonce)),
        Err(CeremonyError::NotRegistered) => Err(Error::NotRegistered),
        Err(e) => Err(Error::UnexpectedError(format!("{:?}", e))),
    }
}

/// Contributes to the server.
#[inline]
pub async fn contribute<C, E, P, const CIRCUIT_COUNT: usize>() -> Result<(), Error>
where // TODO: Clean traits here
    C: CeremonyConfig<SignatureScheme = Ed25519>,
    C::Participant: HasIdentifier<Identifier = PublicKey<C>> + Clone,
    E: PairingEngine,
    P: Pairing<Pairing = E>,
    ParticipantIdentifier<C>: Serialize,
    Nonce<C>: DeserializeOwned + Debug,
    State<C>: CanonicalDeserialize,
    Challenge<C>: CanonicalDeserialize,
    Proof<C>: CanonicalSerialize,
    <C as CeremonyConfig>::Setup: Types<State = ProvingKey<E>>,
{
    let network_client = KnownUrlClient::new("http://localhost:8080").expect("Should succeed.");
    let (sk, pk) = get_client_keys()?;
    println!(
        "{} Contacting Server for Meta Data...",
        style("[1/9]").bold().dim()
    );
    let term = Term::stdout();
    let (size, nonce) = get_start_meta_data::<C, CIRCUIT_COUNT>(pk, &network_client).await?;
    let mut trusted_setup_client = Client::<C, CIRCUIT_COUNT>::new(pk, nonce, sk);
    println!("{} Waiting in Queue...", style("[2/9]").bold().dim(),);
    loop {
        let mpc_state = match network_client
            .post::<_, Result<QueryResponse<C, CIRCUIT_COUNT>, CeremonyError<C>>>(
                "query",
                &trusted_setup_client
                    .query()
                    .map_err(|_| Error::UnableToGenerateRequest("Queries the server state."))?,
            )
            .await
            .map_err(|_| {
                return Error::NetworkError(
                    "Should have received starting meta data from server".to_string(),
                );
            })? {
            Err(CeremonyError::Timeout) => {
                term.clear_last_lines(1)
                    .expect("Clear last lines should succeed.");
                println!(
                    "{} You have timed out. Waiting in Queue again...",
                    style("[2/9]").bold().dim(),
                );
                continue;
            }
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
                    thread::sleep(Duration::from_secs(10));
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
                    if !check_state_size::<P, CIRCUIT_COUNT>(&mpc_state.state, &size) {
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
        match network_client
            .post::<_, Result<(), CeremonyError<Groth16BLS12381>>>(
                "update",
                &trusted_setup_client
                    .contribute(
                        &Hasher::<C>::default(),
                        &mpc_state.challenge,
                        mpc_state.state,
                    )
                    .map_err(|_| Error::UnableToGenerateRequest("contribute"))?,
            )
            .await
            .map_err(|_| {
                return Error::NetworkError(
                    "Should have received starting meta data from server".to_string(),
                );
            })? {
            Err(CeremonyError::Timeout) => {
                term.clear_last_lines(1)
                    .expect("Clear last lines should succeed.");
                println!(
                    "{} You have timed out. Waiting in Queue again...",
                    style("[2/9]").bold().dim(),
                );
                continue;
            }
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

/// Testing Suite
#[cfg(test)]
mod test {
    use super::*;

    /// Tests if register is visually correct.
    #[test]
    fn register_is_visually_correct() {
        register(
            "Mantalorian".to_string(),
            "mantalorian@manta.network".to_string(),
        );
    }
}
