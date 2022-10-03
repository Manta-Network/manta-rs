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

//! Groth16 Trusted Setup Ceremony Perpetual Powers of Tau Configuration

use crate::{
    ceremony::{
        participant,
        registry::csv,
        signature::{sign, verify, Nonce as _, RawMessage, SignatureScheme},
    },
    groth16::ceremony::{
        client::{self, Update},
        Ceremony, CeremonyError,
    },
};
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use colored::Colorize;
use console::{style, Term};
use core::fmt::Debug;
use dialoguer::{theme::ColorfulTheme, Input};
use manta_crypto::{
    dalek::ed25519::{self, generate_keypair, Ed25519, SECRET_KEY_LENGTH},
    rand::{ChaCha20Rng, OsRng, Rand, SeedableRng},
    signature::VerifyingKeyType,
};
use manta_util::serde::{de::DeserializeOwned, Deserialize, Serialize};

type Signature = Ed25519<RawMessage<u64>>;
type VerifyingKey = <Signature as VerifyingKeyType>::VerifyingKey;
type Nonce = <Signature as SignatureScheme>::Nonce;

/// Priority
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(
    bound(deserialize = "", serialize = ""),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
pub enum Priority {
    /// High Priority
    High,

    /// Normal Priority
    Normal,
}

impl From<Priority> for usize {
    #[inline]
    fn from(priority: Priority) -> Self {
        match priority {
            Priority::High => 0,
            Priority::Normal => 1,
        }
    }
}

/// Participant
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    bound(
        deserialize = r"
            VerifyingKey: Deserialize<'de>,
            Nonce: Deserialize<'de>,
        ",
        serialize = r"
            VerifyingKey: Serialize,
            Nonce: Serialize,
        "
    ),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
pub struct Participant {
    /// Twitter Account
    twitter: String,

    /// Priority
    priority: Priority,

    /// Verifying Key
    verifying_key: VerifyingKey,

    /// Nonce
    nonce: Nonce,

    /// Boolean on whether this participant has contributed
    contributed: bool,
}

impl Participant {
    /// Builds a new [`Participant`].
    #[inline]
    pub fn new(
        verifying_key: VerifyingKey,
        twitter: String,
        priority: Priority,
        nonce: Nonce,
        contributed: bool,
    ) -> Self {
        Self {
            verifying_key,
            twitter,
            priority,
            nonce,
            contributed,
        }
    }

    /// Gets `twitter`.
    #[inline]
    pub fn twitter(&self) -> &str {
        &self.twitter
    }
}

impl participant::Participant for Participant {
    type Identifier = VerifyingKey;
    type VerifyingKey = VerifyingKey;
    type Nonce = Nonce;

    #[inline]
    fn id(&self) -> &Self::Identifier {
        &self.verifying_key
    }

    #[inline]
    fn verifying_key(&self) -> &Self::VerifyingKey {
        &self.verifying_key
    }

    #[inline]
    fn has_contributed(&self) -> bool {
        self.contributed
    }

    #[inline]
    fn set_contributed(&mut self) {
        self.contributed = true
    }

    #[inline]
    fn nonce(&self) -> &Self::Nonce {
        &self.nonce
    }

    #[inline]
    fn increment_nonce(&mut self) {
        self.nonce.increment();
    }
}

impl participant::Priority for Participant {
    type Priority = Priority;

    #[inline]
    fn priority(&self) -> Self::Priority {
        self.priority
    }

    #[inline]
    fn reduce_priority(&mut self) {
        self.priority = Priority::Normal;
    }
}

/// Record
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(
    bound(deserialize = "", serialize = ""),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
pub struct Record {
    /// Twitter Account
    twitter: String,

    /// Email Account
    email: String,

    /// Priority Level
    priority: String,

    /// Verifying Key
    verifying_key: String,

    /// Signature
    signature: String,
}

impl csv::Record<VerifyingKey, Participant> for Record {
    type Error = String;

    #[inline]
    fn parse(self) -> Result<(VerifyingKey, Participant), Self::Error> {
        let verifying_key = ed25519::public_key_from_bytes(
            bs58::decode(self.verifying_key)
                .into_vec()
                .map_err(|_| "Cannot decode verifying key.".to_string())?
                .try_into()
                .map_err(|_| "Cannot decode to array.".to_string())?,
        );
        let signature: ed25519::Signature = ed25519::signature_from_bytes(
            bs58::decode(self.signature)
                .into_vec()
                .map_err(|_| "Cannot decode signature.".to_string())?
                .try_into()
                .map_err(|_| "Cannot decode to array.".to_string())?,
        );
        verify::<Signature, _>(
            &verifying_key,
            0,
            &format!(
                "manta-trusted-setup-twitter:{}, manta-trusted-setup-email:{}",
                self.twitter, self.email
            ),
            &signature,
        )
        .map_err(|_| "Cannot verify signature.".to_string())?;
        Ok((
            verifying_key,
            Participant::new(
                verifying_key,
                self.twitter,
                match self
                    .priority
                    .parse::<bool>()
                    .map_err(|_| "Cannot parse priority.".to_string())?
                {
                    true => Priority::High,
                    false => Priority::Normal,
                },
                OsRng.gen::<_, u16>() as u64,
                false,
            ),
        ))
    }
}

/// Generates an ed25519 keypair with `bytes` as seed.
#[inline]
pub fn generate_keys(bytes: &[u8]) -> Option<(ed25519::SecretKey, ed25519::PublicKey)> {
    if ed25519::SECRET_KEY_LENGTH > bytes.len() {
        return None;
    }
    let keypair = generate_keypair(&mut ChaCha20Rng::from_seed(
        bytes[0..SECRET_KEY_LENGTH].try_into().ok()?,
    ));
    Some((keypair.secret, keypair.public))
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
    let keypair = generate_keys(seed.as_bytes()).expect("Should generate a key pair.");
    println!(
        "Your {}: \nCopy the following text to \"Public Key\" Section in Google Sheet:\n {}\n",
        "Public Key".italic(),
        bs58::encode(keypair.1).into_string().blue(),
    );
    let signature = sign::<Ed25519<RawMessage<u64>>, _>(
        &keypair.0,
        Default::default(),
        &format!(
            "manta-trusted-setup-twitter:{}, manta-trusted-setup-email:{}",
            twitter_account, email
        ),
    )
    .expect("Signing message should succeed.");
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

/// Prompts the client information and get client keys.
#[inline]
pub fn get_client_keys() -> Option<(ed25519::SecretKey, ed25519::PublicKey)> {
    println!(
        "Please enter the {} you received when you registered yourself using this tool.",
        "Secret".italic()
    );
    let seed_bytes = Seed::new(
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
    .to_vec();
    generate_keys(&seed_bytes)
}

/// Contributes to the server.
#[inline]
pub async fn client_contribute<C>(
    signing_key: C::SigningKey,
    identifier: C::Identifier,
) -> Result<(), CeremonyError<C>>
where
    C: Ceremony,
    C::Challenge: DeserializeOwned,
    C::Identifier: Serialize,
    C::Nonce: Clone + Debug + DeserializeOwned + Serialize,
    C::Signature: Serialize,
{
    const LOCK_TIME: u64 = 5;
    let term = Term::stdout();
    client::contribute(
        signing_key,
        identifier,
        "http://localhost:8080",
        |state| match state {
            Update::Timeout => {
                let _ = term.clear_last_lines(1);
                println!("You have timed out. Waiting in queue again ...");
            },
            Update::Position(position) => {
                let _ = term.clear_last_lines(1);
                println!(
                    "Waiting in queue... There are {} people ahead of you. Estimated Waiting Time: {} minutes.",
                    style(position).bold().red(),
                    style(LOCK_TIME * position).bold().blue(),
                );
            },
        },
    )
    .await
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
