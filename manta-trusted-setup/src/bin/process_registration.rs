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

use clap::{Parser, Subcommand};
use manta_trusted_setup::groth16::ceremony::{
    config::ppot::{Config, Participant},
    CeremonyError,
};
use manta_util::{
    Array,
};
use std::{collections::HashMap, path::PathBuf};

/// Registry type
type Registry = HashMap<Array<u8, 32>, Participant>;

/// Command
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Recovers a server from disk.
    Process {
        raw_registry_path: String,
        registry_path: String,
    },
}

/// Server CLI
#[derive(Debug, Parser)]
pub struct Arguments {
    /// Server Command
    #[clap(subcommand)]
    pub command: Command,
}

impl Arguments {
    /// Runs a server.
    #[inline]
    pub async fn run(self) -> Result<(), CeremonyError<Config>> {
        match self.command {
            Command::Process {
                raw_registry_path,
                registry_path
            } => todo!()
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
        .expect("Server error occurred");
}

// run with
// cargo run --release --all-features --bin groth16_phase2_server recover manta-trusted-setup/data manta-trusted-setup/data/registry.csv
// TODO: Update server start command!
// cargo build --release --all-features --bin groth16_phase2_server
