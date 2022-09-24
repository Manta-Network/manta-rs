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

use manta_trusted_setup::groth16::ceremony::CeremonyError;
#[cfg(all(feature = "bincode", feature = "serde"))]
use manta_trusted_setup::groth16::ceremony::{
    client::{handle_error, Error},
    config::ppot::{client_contribute, get_client_keys, register, Config},
};

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
    pub fn run(self) -> Result<(), CeremonyError<Config>> {
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
                let (sk, pk) =
                    get_client_keys().expect("Extracting the keys is not supposed to fail.");
                match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(4)
                    .enable_io()
                    .enable_time()
                    .build()
                {
                    Ok(runtime) => {
                        runtime.block_on(async { client_contribute::<Config>(sk, pk).await })
                    }
                    Err(err) => Err(CeremonyError::UnexpectedError(format!("{}", err))),
                }
            }
        }
    }
}

fn main() {
    handle_error(Arguments::parse().run());
}
