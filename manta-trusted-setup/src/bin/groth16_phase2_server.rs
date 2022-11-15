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

// Run on remote with
// cargo run --release --all-features --package manta-trusted-setup --bin groth16_phase2_server /home/mobula/manta-rs/manta-trusted-setup/data /home/mobula/manta-rs/manta-trusted-setup/data/registry.csv
// Build with
// cargo build --release --all-features --package manta-trusted-setup --bin groth16_phase2_server
// Run local with
// cargo run --release --all-features --package manta-trusted-setup --bin groth16_phase2_server /Users/thomascnorton/Documents/Manta/manta-rs/manta-trusted-setup/data /Users/thomascnorton/Documents/Manta/manta-rs/manta-trusted-setup/data/registry.csv

use clap::Parser;
use manta_trusted_setup::groth16::ceremony::{
    config::ppot::{Config, Participant},
    server::Server,
    CeremonyError,
};
use manta_util::{
    http::tide::{self, execute},
    Array,
};
use std::{collections::HashMap, path::PathBuf, time::Duration};

/// Registry type
type Registry = HashMap<Array<u8, 32>, Participant>;

/// Current server configuration
type S = Server<Config, Registry, 2, 3>;

/// Contribution time limit in seconds
const TIME_LIMIT: u64 = 2000; // TODO: What's correct?

/// Server CLI
#[derive(Debug, Parser)]
pub struct Arguments {
    recovery_dir_path: String,

    registry_path: String,
}

impl Arguments {
    /// Runs a server.
    #[inline]
    pub async fn run(self) -> Result<(), CeremonyError<Config>> {
        let server = S::recover(
            PathBuf::from(self.recovery_dir_path),
            PathBuf::from(self.registry_path),
            Duration::from_secs(TIME_LIMIT),
        )
        .expect("Unable to recover from file");

        println!("Network is running!");
        let mut api = tide::Server::with_state(server);
        // api.at("/")
        //     .serve_file("/home/mobula/manta-rs/manta-trusted-setup/index.html")
        //     .map_err(|_| CeremonyError::<Config>::Network {
        //         message: "Cannot load landing page.".to_string(),
        //     })?;
        api.at("/start")
            .post(|r| execute(r, Server::start_endpoint));
        api.at("/query")
            .post(|r| execute(r, Server::query_endpoint));
        api.at("/update")
            .post(|r| execute(r, Server::update_endpoint));

        api.listen("127.0.0.1:8080")
            .await
            .expect("Should create a listener.");
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

/// A hack for easily setting the `round_number` file to
/// say the round number is 0.
#[test]
fn reset_round_number() {
    use manta_trusted_setup::ceremony::util::serialize_into_file;
    use std::fs::OpenOptions;

    let round = 0u64;
    let directory =
        PathBuf::from("/Users/thomascnorton/Documents/Manta/manta-rs/manta-trusted-setup/data");

    serialize_into_file(
        OpenOptions::new().write(true).truncate(true).create(true),
        &directory.join(r"round_number"),
        &round,
    )
    .expect("Must serialize round number to file");
}

/// A hack for changing the `circuit_names` file to just contain one of the circuits.
/// Note that you must delete the original file b/c truncate won't overwrite the whole thing.
/// Note that if you want to change the length from 3 you have to do so above in the server's type (l. 42ish)
#[test]
fn change_circuit_names() {
    use manta_trusted_setup::ceremony::util::serialize_into_file;
    use std::fs::OpenOptions;

    let names = vec!["to_private".to_string(), "to_public".to_string(), "private_transfer".to_string()];
    let directory =
        PathBuf::from("/Users/thomascnorton/Documents/Manta/manta-rs/manta-trusted-setup/data");

    serialize_into_file(
        OpenOptions::new().write(true).truncate(true).create(true),
        &directory.join(r"circuit_names"),
        &names,
    )
    .expect("Writing circuit names to disk should succeed.");
}

// Try using new circuits from feat/server-bin branch