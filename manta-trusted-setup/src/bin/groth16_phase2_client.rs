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

use clap::{Parser, Subcommand};
use dialoguer::{theme::ColorfulTheme, Input};
use manta_trusted_setup::groth16::ceremony::{
    config::ppot::{client_contribute, display_on_error, get_client_keys, register, Config},
    CeremonyError,
};
use manta_util::Array;

/// Welcome Message
pub const TITLE: &str = r" __  __             _          _____               _           _
|  \/  | __ _ _ __ | |_ __ _  |_   _| __ _   _ ___| |_ ___  __| |
| |\/| |/ _` | '_ \| __/ _` |   | || '__| | | / __| __/ _ \/ _` |
| |  | | (_| | | | | || (_| |   | || |  | |_| \__ \ ||  __/ (_| |
|_|  |_|\__,_|_| |_|\__\__,_|   |_||_|   \__,_|___/\__\___|\__,_|

 ____       _
/ ___|  ___| |_ _   _ _ __
\___ \ / _ \ __| | | | '_ \
 ___) |  __/ |_| |_| | |_) |
|____/ \___|\__|\__,_| .__/
                     |_|
";

/// Command
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Register for the Trusted Setup Ceremony
    Register,

    /// Contribute to the Trusted Setup Ceremony
    Contribute,
}

/// Command Line Arguments
#[derive(Debug, Parser)]
pub struct Arguments {
    /// Command
    #[clap(subcommand)]
    command: Command,

    /// URL
    #[clap(default_value = "https://ceremony.manta.network")]
    url: String,
}

impl Arguments {
    /// Takes command line arguments and executes the corresponding operations.
    #[inline]
    pub fn run(self) -> Result<(), CeremonyError<Config>> {
        println!("{}", TITLE);
        match self.command {
            Command::Register => {
                let twitter_account = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Your twitter account")
                    .interact_text()
                    .expect("Unable to get a valid twitter account.");
                let email = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Your email address")
                    .interact_text()
                    .expect("Unable to get a valid email.");
                register(twitter_account, email);
                Ok(())
            }
            Command::Contribute => {
                let (sk, pk) = match get_client_keys() {
                    Ok(keys) => keys,
                    Err(e) => panic!("Error while extracting the client keys: {}", e),
                };
                match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(4)
                    .enable_io()
                    .enable_time()
                    .build()
                {
                    Ok(runtime) => {
                        let pk = Array::from_unchecked(*pk.as_bytes());
                        runtime
                            .block_on(async { client_contribute::<Config>(sk, pk, self.url).await })
                    }
                    Err(e) => panic!("I/O Error while setting up the tokio Runtime: {:?}", e),
                }
            }
        }
    }
}

fn main() {
    display_on_error(Arguments::parse().run());
}

// cargo run --release --package manta-trusted-setup --all-features --bin groth16_phase2_client -- https://ceremony.manta.network register
// cargo run --release --package manta-trusted-setup --all-features --bin groth16_phase2_client -- http://localhost:8080 contribute
// cargo run --release --package manta-trusted-setup --all-features --bin groth16_phase2_client -- https://ceremony.manta.network contribute
