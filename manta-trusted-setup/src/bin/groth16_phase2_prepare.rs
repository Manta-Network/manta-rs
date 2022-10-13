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

//! Trusted Setup Ceremony Preparation
//! Given Phase 1 parameters and circuit descriptions, prepares files
//! needed for a server to act as ceremony coordinator.
//! NOTE: This currently saves an empty registry file.

use clap::{Parser, Subcommand};
use manta_trusted_setup::groth16::ceremony::{
    config::ppot::{Config, Record, Registry},
    coordinator::prepare,
    CeremonyError,
};
use std::path::PathBuf;

/// Command
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Transforms Phase 1 Parameters into Phase 2 Parameters.
    Prepare {
        phase_one_param_path: PathBuf,
        recovery_directory: PathBuf,
    },
}

/// Preparer CLI
#[derive(Debug, Parser)]
pub struct Arguments {
    /// Server Command
    #[clap(subcommand)]
    pub command: Command,
}

impl Arguments {
    /// Prepares for phase 2 ceremony
    #[inline]
    pub async fn run(self) -> Result<(), CeremonyError<Config>> {
        match self.command {
            Command::Prepare {
                phase_one_param_path,
                recovery_directory,
            } => {
                prepare::<Config, Registry, Record>(phase_one_param_path, recovery_directory);
            }
        };
        Ok(())
    }
}

#[async_std::main]
async fn main() {
    // exit_on_error(Arguments::parse().run());
    Arguments::parse()
        .run()
        .await
        .expect("Preparation error occurred");
}

// run with
// cargo run --release --all-features --bin groth16_phase2_prepare prepare /Users/thomascnorton/Documents/Manta/trusted-setup/challenge_0072 manta-trusted-setup/data
