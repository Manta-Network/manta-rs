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
            CeremonyConfig, Challenge, Hasher, Nonce, ParticipantIdentifier, PrivateKey, Proof,
            PublicKey, State,
        },
        message::{ContributeRequest, ContributeState, QueryRequest, Signed},
        participant::{Participant, UserPriority},
        registry::Registry,
        signature::{ed_dalek::Ed25519, sign, verify, SignatureScheme},
    },
    mpc::Contribute,
    util::AsBytes,
};
use alloc::collections::BTreeMap;
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use colored::Colorize;
use console::style;
use core::fmt::{Debug, Display, Formatter};
use dialoguer::{theme::ColorfulTheme, Input};
use manta_crypto::{
    arkworks::serialize::{CanonicalDeserialize, CanonicalSerialize},
    rand::{OsRng, Rand},
};
use manta_util::Array;
use std::{fs::File, path::Path};

/// Client
pub struct Client<C, const CIRCUIT_COUNT: usize>
where
    C: CeremonyConfig,
{
    /// Public Key
    public_key: PublicKey<C>,

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
        public_key: PublicKey<C>,
        identifier: ParticipantIdentifier<C>,
        nonce: Nonce<C>,
        private_key: PrivateKey<C>,
    ) -> Self {
        Self {
            public_key,
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

/// TODO
#[derive(Clone, Debug)]
pub enum Error {
    ///
    InvalidSecret,

    ///
    UnableToGenerateRequest(&'static str),

    ///
    NotRegistered,

    ///
    AlreadyContributed,

    ///
    UnexpectedError(String),

    ///
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

/// Loads registry from a disk file at `registry`.
#[inline]
pub fn load_registry<C, P, S>(
    registry_file: P,
) -> Registry<S::VerifyingKey, <C as CeremonyConfig>::Participant>
where
    P: AsRef<Path>,
    C: CeremonyConfig<Participant = Participant<S>>,
    S: SignatureScheme<Vec<u8>, Nonce = u64, VerifyingKey = Array<u8, 32>>,
    S::VerifyingKey: Ord + CanonicalDeserialize + CanonicalSerialize,
{
    let mut map = BTreeMap::new();
    for record in
        csv::Reader::from_reader(File::open(registry_file).expect("Registry file should exist."))
            .records()
    {
        let result = record.expect("Read csv should succeed.");
        let twitter = result[0].to_string();
        let email = result[1].to_string();
        let public_key: Array<u8, 32> =
            Array::from_unchecked(bs58::decode(result[3].to_string()).into_vec().unwrap());
        let signature: Array<u8, 64> =
            Array::from_unchecked(bs58::decode(result[4].to_string()).into_vec().unwrap());
        verify::<_, Ed25519>(
            &format!(
                "manta-trusted-setup-twitter:{}, manta-trusted-setup-email:{}",
                twitter, email
            ),
            0,
            &public_key,
            &signature,
        )
        .expect("Verifying signature should succeed.");
        let participant = Participant {
            twitter,
            priority: match result[2].to_string().parse::<bool>().unwrap() {
                true => UserPriority::High,
                false => UserPriority::Normal,
            },
            public_key,
            nonce: OsRng.gen::<_, u16>() as u64,
            contributed: false,
        };
        map.insert(participant.public_key, participant);
    }
    Registry::new(map)
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
