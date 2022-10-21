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

// TODO: Update server start command!

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
const TIME_LIMIT: u64 = 60;

/// Server CLI
#[derive(Debug, Parser)]
pub struct Arguments {
    #[clap(default_value = "manta-trusted-setup/data/")]
    recovery_dir_path: String,

    #[clap(default_value = "manta-trusted-setup/data/registry.csv")]
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
        api.at("/")
            .serve_file("/home/mobula/manta-rs/index.html")
            .map_err(|_| CeremonyError::<Config>::Network {
                message: "Cannot load landing page.".to_string(),
            })?;
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
