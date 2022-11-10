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
//! NOTE: This saves an empty registry file. Registry updates are
//! triggered automatically by server.

use clap::Parser;
use manta_trusted_setup::groth16::ceremony::{
    config::ppot::{Config, Record, Registry},
    coordinator::prepare,
    CeremonyError,
};
use std::path::PathBuf;

// for local server test:
// cargo run --release --package manta-trusted-setup --all-features --bin groth16_phase2_prepare /Users/thomascnorton/Documents/Manta/trusted-setup/challenge_0072 /Users/thomascnorton/Documents/Manta/manta-rs/manta-trusted-setup/data
/// Preparer CLI
#[derive(Debug, Parser)]
pub struct Arguments {
    phase_one_param_path: PathBuf,

    recovery_directory: PathBuf,
}

impl Arguments {
    /// Prepares for phase 2 ceremony
    #[inline]
    pub fn run(self) -> Result<(), CeremonyError<Config>> {
        prepare::<Config, Registry, Record>(self.phase_one_param_path, self.recovery_directory);
        Ok(())
    }
}

fn main() {
    Arguments::parse()
        .run()
        .expect("Preparation error occurred");
}
