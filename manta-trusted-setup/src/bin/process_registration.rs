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

use clap::Parser;
use manta_trusted_setup::groth16::ceremony::{
    config::ppot::{extract_registry, Config, Record},
    CeremonyError,
};
use manta_util::serde::{Deserialize, Serialize};
use std::fs::File;

// run with
// cargo run --release --package manta-trusted-setup --all-features --bin process_registration -- process /Users/thomascnorton/Downloads/Trusted_Setup_Signups.csv /Users/thomascnorton/Documents/Manta/manta-rs/manta-trusted-setup/data/test_registry.csv
// or
// cargo run --release --package manta-trusted-setup --all-features --bin process_registration -- process /Users/thomascnorton/Downloads/Trusted_Setup_Signups.csv

/// These are the headers in the .csv automatically generated by the
/// registration form.
const EXPECTED_HEADERS: [&str; 14]= [
    "First up, what\'s your first name?", 
        "What is your email address? ", 
        "Okay {{field:c393dfe5f7faa4de}}, what your signature?", 
        "What\'s your public key, {{field:c393dfe5f7faa4de}}?", 
        "Finally, what\'s your Twitter Handle?  ", 
        "Alright {{field:c393dfe5f7faa4de}}, why is privacy important to you?", 
        "We want to reward participation with a POAP designed to commemorate this historical Web 3 achievement. If you would like to receive one please share your wallet address", 
        "score", 
        "Finally, what\'s your Twitter Handle?  ", 
        "What\'s your public key, {{field:c393dfe5f7faa4de}}?", 
        "What\'s your Discord ID, {{field:c393dfe5f7faa4de}}?", 
        "What is your motivation for participating in the Trusted Setup, {{field:c393dfe5f7faa4de}}?",
        "Submitted At", 
        "Token"
];

/// Short versions of the above headers to allow
/// rows of the .csv to be deserialized to [`RegistrationInfo`].
const SHORT_HEADERS: [&str; 14] = [
    "name",
    "email",
    "signature",
    "verifying_key_null",
    "twitter_null",
    "why_privacy",
    "wallet",
    "score",
    "twitter",
    "verifying_key",
    "discord",
    "motivation",
    "submission_time",
    "submission_token",
];

/// Server CLI
#[derive(Debug, Parser)]
pub struct Arguments {
    raw_registry_path: String,

    #[clap(default_value = "manta-trusted-setup/data/registry.csv")]
    registry_path: String,
}

impl Arguments {
    /// Runs a server.
    #[inline]
    pub async fn run(self) -> Result<(), CeremonyError<Config>> {
        let file =
            File::open(self.raw_registry_path).expect("Unable to open file raw registry file");
        extract_registry::<RegistrationInfo>(
            &file,
            self.registry_path.into(),
            EXPECTED_HEADERS.into(),
            SHORT_HEADERS.into(),
        )
        .expect("Registry processing failed.");
        Ok(())
    }
}

#[async_std::main]
async fn main() {
    Arguments::parse()
        .run()
        .await
        .expect("Server error occurred");
}

/// Registration info collected by our registration form.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(
    bound(deserialize = "", serialize = ""),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
pub struct RegistrationInfo {
    /// First name (may be empty)
    pub name: String,

    /// Email Account
    pub email: String,

    /// Signature
    pub signature: String,

    /// Verifying Key
    pub verifying_key: String,

    /// Twitter Account
    pub twitter: String,

    /// Why is privacy important (may be empty)
    pub why_privacy: String,

    /// Wallet address (may be empty)
    pub wallet: String,

    /// Score
    pub score: String,

    /// Named field that's always empty
    pub twitter_null: String,

    /// Named field that's always empty
    pub verifying_key_null: String,

    /// Discord ID (may be empty)
    pub discord: String,

    /// Motivation to participate (may be empty)
    pub motivation: String,

    /// Submission time
    pub submission_time: String,

    /// Submission token
    pub submission_token: String,
}

impl From<RegistrationInfo> for Record {
    fn from(value: RegistrationInfo) -> Self {
        Self::new(
            value.twitter,
            value.email,
            "false".to_string(),
            value.verifying_key,
            value.signature,
        )
    }
}

#[test]
fn test_extract_registry() {
    use manta_trusted_setup::groth16::ceremony::config::ppot::extract_registry;
    use std::path::PathBuf;
    let file = File::open("/Users/thomascnorton/Downloads/Trusted_Setup_Signups.csv")
        .expect("Cannot open file");
    let path = PathBuf::from(
        r"/Users/thomascnorton/Documents/Manta/manta-rs/manta-trusted-setup/data/test_registry.csv",
    );
    extract_registry::<RegistrationInfo>(
        &file,
        path,
        EXPECTED_HEADERS.into(),
        SHORT_HEADERS.into(),
    )
    .unwrap();
}

#[test]
fn test_set_headers() {
    use csv::Reader;
    use manta_trusted_setup::groth16::ceremony::config::ppot::set_header;

    let file = File::open("/Users/thomascnorton/Documents/Manta/manta-rs/manta-trusted-setup/data/registry_buffer.csv").expect("Cannot open file");
    let mut reader = Reader::from_reader(&file);
    assert!(set_header(&mut reader, EXPECTED_HEADERS.into(), SHORT_HEADERS.into()).is_ok());
    assert!(
        reader.byte_headers().unwrap()
            == vec![
                "name",
                "email",
                "signature",
                "verifying_key_null",
                "twitter_null",
                "why_privacy",
                "wallet",
                "score",
                "twitter",
                "verifying_key",
                "discord",
                "motivation",
                "submission_time",
                "submission_token",
            ]
    );
}
