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
    config::ppot::{exit_on_error, Config, Record, Registry},
    server::{init_server},
    CeremonyError,
};
use manta_util::http::tide;

/// Command
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Transforms Phase 1 Parameters into Phase 2 Parameters.
    Prepare,

    /// Creates a new server.
    Create {
        registry_path: String,
        init_parameters_path: String,
        recovery_dir_path: String,
        server_url: String,
    },

    /// Recovers a server from disk.
    Recover {
        recovery_path: String,
        recovery_dir_path: String,
        server_url: String,
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
    pub fn run(self) -> Result<(), CeremonyError<Config>> {
        let server = match self.command {
            Command::Create {
                registry_path,
                init_parameters_path,
                recovery_dir_path,
                server_url
            } => init_server::<Registry, Config, Record, 2>(registry_path, recovery_dir_path),
            _ => {
                panic!()
            }
            // Command::Recover {
            //     recovery_path,
            //     recovery_dir_path,
            // } => recover(recovery_path, recovery_dir_path),
        };
        
        println!("Network starts to run!");
        let mut api = tide::Server::with_state(server);
        // api.at("/start").post(|r| S::execute(r, Server::start));
        // api.at("/query").post(|r| S::execute(r, Server::query));
        // api.at("/update").post(|r| S::execute(r, Server::update));
        // api.listen("127.0.0.1:8080")
        //     .await
        //     .expect("Should create a listener."); // TODO: use TLS
        Ok(())
    }
}

fn main() {
    exit_on_error(Arguments::parse().run());
}

// run with 
// cargo run --all-features --bin groth16_phase2_server create manta-trusted-setup/data/dummy_register.csv manta-trusted-setup/data manta-trusted-setup/data server_url