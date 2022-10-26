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

//! Generate a CSV file of credentials for a fake TS ceremony

use bip39::{Language, Mnemonic, MnemonicType, Seed};
use clap::Parser;
use csv::WriterBuilder;
use manta_crypto::dalek::ed25519::Ed25519;
use manta_trusted_setup::{
    ceremony::signature::{sign, RawMessage},
    groth16::ceremony::config::ppot::{extract_registry, generate_keys, Record},
};
use manta_util::serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs::OpenOptions, path::PathBuf};

/// Number of entries to generate
const LENGTH: usize = 2000;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(
    bound(deserialize = "", serialize = ""),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
/// Full credentials including password
struct Credentials {
    email: String,
    twitter: String,
    verifying_key: String,
    signature: String,
    mnemonic: String,
}

impl From<Credentials> for Record {
    fn from(value: Credentials) -> Self {
        Self::new(
            value.twitter,
            value.email,
            "false".to_string(),
            value.verifying_key,
            value.signature,
        )
    }
}

const HEADERS: [&str; 5] = ["email", "twitter", "verifying_key", "signature", "mnemonic"];

/// The [`ppot::register`] function, but with output `(verifying_key, signature, signing_key)`.
fn register(twitter: String, email: String) -> Credentials {
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    let seed = Seed::new(&mnemonic, "manta-trusted-setup");
    let keypair = generate_keys(seed.as_bytes()).expect("Should generate a key pair.");
    let signature = sign::<Ed25519<RawMessage<u64>>, _>(
        &keypair.0,
        Default::default(),
        &format!(
            "manta-trusted-setup-twitter:{}, manta-trusted-setup-email:{}",
            twitter, email
        ),
    )
    .expect("Signing message should succeed.");

    Credentials {
        email,
        twitter,
        verifying_key: bs58::encode(keypair.1).into_string(),
        signature: bs58::encode(signature).into_string(),
        mnemonic: mnemonic.phrase().to_string(),
    }
}

/// Server CLI
#[derive(Debug, Parser)]
pub struct Arguments {
    path: String,
}

impl Arguments {
    /// Runs a server.
    #[inline]
    pub fn run(self) {
        {
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(self.path.clone())
                .expect("Unable to create file at path");
            let mut writer = WriterBuilder::new().from_writer(&mut file);

            for i in 0..LENGTH {
                let credential = register(
                    format!("participant_{i}"),
                    format!("participant_{i}@email.com"),
                );
                writer.serialize(credential).expect("Serialization error");
            }
        }

        let file = OpenOptions::new()
            .read(true)
            .open(self.path.clone())
            .expect("Unable to open file at path");
        let priority_list = HashMap::new();
        let registry_path = PathBuf::from(self.path)
            .parent()
            .expect("Path should have parent")
            .join("registry.csv");
        let (successful, malformed) = extract_registry::<Credentials>(
            &file,
            registry_path,
            HEADERS.into(),
            HEADERS.into(),
            priority_list,
        )
        .expect("Registry processing failed.");
        println!(
            "Processed a total of {} registry entries. \
        {} were processed successfully. \
        {} were malformed entries.",
            successful + malformed,
            successful,
            malformed
        );
    }
}

fn main() {
    Arguments::parse().run();
}

// cargo run --release --all-features --bin generate_dummy_register /Users/thomascnorton/Documents/Manta/manta-rs/dummy_register.csv
