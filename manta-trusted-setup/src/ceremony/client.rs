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
        message::{ContributeRequest, QueryRequest, Signed},
        signature::{ed_dalek, SignatureScheme},
        state::ContributeState,
    },
    mpc::Contribute,
    util::AsBytes,
};
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use colored::Colorize;
use core::fmt::{Debug, Display, Formatter};
use indicatif::ProgressBar;
use manta_crypto::{arkworks::serialize::CanonicalSerialize, rand::OsRng};

/// Client
pub struct Client<C>
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

impl<C> Client<C>
where
    C: CeremonyConfig,
{
    /// Builds a new [`Client`] with `participant` and `private_key`.
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
    pub fn query(&mut self) -> Result<Signed<QueryRequest, C>, ()>
    where
        C::Participant: Clone,
        <<C as CeremonyConfig>::SignatureScheme as SignatureScheme>::PublicKey: std::fmt::Debug, // TODO: Remove
    {
        Signed::new(
            QueryRequest,
            self.identifier.clone(),
            &mut self.nonce,
            &self.public_key,
            &self.private_key,
        )
    }

    /// Contributes to the state on the server.
    pub fn contribute(
        &mut self,
        hasher: &Hasher<C>,
        challenge: &[Challenge<C>; 3],
        mut state: [State<C>; 3],
        bar: &ProgressBar,
    ) -> Result<Signed<ContributeRequest<C, 3>, C>, ()>
    where
        C::Participant: Clone,
        State<C>: CanonicalSerialize,
        Proof<C>: CanonicalSerialize + Debug,
        <<C as CeremonyConfig>::SignatureScheme as SignatureScheme>::PublicKey: std::fmt::Debug,
    {
        let mut rng = OsRng;
        let mut proofs = Vec::new();
        for i in 0..3 {
            proofs.push(
                C::Setup::contribute(hasher, &challenge[i], &mut state[i], &mut rng).ok_or(())?,
            );
            bar.inc(1);
        }
        let message = ContributeRequest::<C, 3> {
            contribute_state: AsBytes::from_actual(ContributeState::<C, 3> {
                state,
                proof: proofs
                    .try_into()
                    .expect("Should have exactly three proofs."),
            }),
        };
        bar.inc(1);
        Signed::new(
            message,
            self.identifier.clone(),
            &mut self.nonce,
            &self.public_key,
            &self.private_key,
        )
    }

    /// Set Nonce for the client.
    pub fn set_nonce(&mut self, nonce: Nonce<C>) {
        self.nonce = nonce;
    }
}

/// Registers a participant.
#[inline]
pub fn register(twitter_account: String, email: String) {
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    let seed = Seed::new(&mnemonic, "manta-trusted-setup");
    let seed_bytes = seed.as_bytes();
    assert!(ed25519_dalek::SECRET_KEY_LENGTH <= seed_bytes.len(), "Secret key length of ed25519 should be smaller than length of seed bytes from mnemonic phrases.");
    let sk = ed25519_dalek::SecretKey::from_bytes(&seed_bytes[0..ed25519_dalek::SECRET_KEY_LENGTH])
        .expect("`from_bytes` should succeed for SecretKey.");
    let pk = ed_dalek::PublicKey(ed25519_dalek::PublicKey::from(&sk).to_bytes().into());
    let sk = ed_dalek::PrivateKey(sk.to_bytes().into());
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
    println!(
        "Your {}: \nCopy the following text to \"Public Key\" Section in Google Sheet:\n {}\n",
        "Public Key".italic(),
        bs58::encode(AsBytes::from_actual(pk).bytes)
            .into_string()
            .blue(),
    );
    println!(
        "Your {}: \nCopy the following text to \"Signature\" Section in Google Sheet: \n {}\n",
        "Signature".italic(),
        bs58::encode(
            AsBytes::from_actual(
                ed_dalek::Ed25519::sign(
                    format!(
                        "manta-trusted-setup-twitter:{}, manta-trusted-setup-email:{}",
                        twitter_account, email
                    ),
                    &0,
                    &pk,
                    &sk,
                )
                .expect("Signing should succeed")
            )
            .bytes
        )
        .into_string()
        .blue()
    );
    println!(
        "Your {}: \nThe following text stores your secret for trusted setup. \
         Save the following text somewhere safe. \n DO NOT share this to anyone else! \
         Please discard this data after the trusted setup ceremony.\n {}",
        "Secret".italic(),
        mnemonic.phrase().red(),
    );
}

/// Endpoint
#[derive(Debug, Copy, Clone)]
pub enum Endpoint {
    /// Query Server States
    Query,

    /// Update Server States
    Update,

    /// Start Meta Data
    Start,
}

const SERVER_ADDR: &str = "http://localhost:8080";

impl From<Endpoint> for String {
    fn from(endpoint: Endpoint) -> String {
        let operation = match endpoint {
            Endpoint::Query => "query",
            Endpoint::Update => "update",
            Endpoint::Start => "start",
        };
        format!("{}/{}", SERVER_ADDR, operation)
    }
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

    /// Tests if sign and verify are compatible with serialization.
    #[test]
    fn signature_and_serialization_is_compatible() {
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        let seed = Seed::new(&mnemonic, "manta-trusted-setup");
        let seed_bytes = seed.as_bytes();
        assert!(ed25519_dalek::SECRET_KEY_LENGTH <= seed_bytes.len(), "Secret key length of ed25519 should be smaller than length of seed bytes from mnemonic phrases.");
        let sk =
            ed25519_dalek::SecretKey::from_bytes(&seed_bytes[0..ed25519_dalek::SECRET_KEY_LENGTH])
                .expect("`from_bytes` should succeed for SecretKey.");
        let pk = ed_dalek::PublicKey(ed25519_dalek::PublicKey::from(&sk).to_bytes().into());
        let sk = ed_dalek::PrivateKey(sk.to_bytes().into());
        let twitter_account = "mantalorian";
        let email = "mantalorian@manta.network";
        let pk_string = bs58::encode(AsBytes::from_actual(pk).bytes).into_string();
        let signature_string = bs58::encode(
            AsBytes::from_actual(
                ed_dalek::Ed25519::sign(
                    format!(
                        "manta-trusted-setup-twitter:{}, manta-trusted-setup-email:{}",
                        twitter_account, email
                    ),
                    &0,
                    &pk,
                    &sk,
                )
                .expect("Signing should succeed"),
            )
            .bytes,
        )
        .into_string();

        let public_key: ed_dalek::PublicKey = AsBytes::new(
            bs58::decode(pk_string)
                .into_vec()
                .expect("Decode public key should succeed."),
        )
        .to_actual()
        .expect("Converting to a public key should succeed.");
        let signature: ed_dalek::Signature = AsBytes::new(
            bs58::decode(signature_string)
                .into_vec()
                .expect("Decode signature should succeed."),
        )
        .to_actual()
        .expect("Converting to a signature should succeed.");
        ed_dalek::Ed25519::verify(
            format!(
                "manta-trusted-setup-twitter:{}, manta-trusted-setup-email:{}",
                twitter_account, email
            ),
            &0,
            &signature,
            &public_key,
        )
        .expect("Verifying signature should succeed.");
    }
}
