// Copyright 2019-2021 Manta Network.
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

//! Manta CLI

// NOTE: In order to customize the help messages and formatting of the CLI, some objects are not
//       documented and the documentation is instead written in macros or omitted entirely.
// TODO: In order to hook up a node instance here, we will want to eventually move this out of
//       `manta-rs` into its own repo.

use clap::{crate_version, AppSettings, Clap};

mod command;

/// Manta Network's Command Line Interface
#[derive(Clap)]
#[clap(
    name = "manta",
    version = crate_version!(),
    setting = AppSettings::PropagateVersion,
    setting = AppSettings::AllArgsOverrideSelf,
    after_help = "For more information about Manta, see 'https://github.com/Manta-Network'."
)]
struct Args {
    /// Path to configuration file
    #[clap(short, long, value_name = "PATH")]
    config: Option<String>,

    /// Set the verbosity level
    #[clap(short, long, parse(from_occurrences))]
    verbose: u8,

    #[clap(subcommand)]
    command: Command,
}

#[derive(Clap)]
enum Command {
    /// Run the testing suite and tools
    Test {
        /// Set the verbosity level
        #[clap(short, long, parse(from_occurrences))]
        verbose: u8,
    },

    /// Interact with a local wallet
    Wallet {
        /// Set the verbosity level
        #[clap(short, long, parse(from_occurrences))]
        verbose: u8,
    },
}

fn main() {
    let args = Args::parse();
    match args.command {
        Command::Test { .. } => println!("Test ..."),
        Command::Wallet { .. } => println!("Wallet ..."),
    }
}
