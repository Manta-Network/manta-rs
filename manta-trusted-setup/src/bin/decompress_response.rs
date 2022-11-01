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

//! PPoT response file decompressor

// cargo run --release --bin decompress_response --all-features 0073 /home/mobula/ppot-verifier
// nohup cargo run --release --bin decompress_response --all-features 0073 /home/mobula/ppot-verifier &> ./decompress_response_0073.log &

use clap::Parser;
use manta_trusted_setup::groth16::ppot::kzg::{batched::decompress_response, PpotCeremony};
use memmap::MmapOptions;
use std::{fs::OpenOptions, io::Read, path::PathBuf, time::Instant};

/// Command Line Arguments
#[derive(Debug, Parser)]
pub struct Arguments {
    /// Round number to decompress, formatted as 4-digit string, e.g. 0012
    round: String,

    /// Directory containing response file
    directory: String,
}

impl Arguments {
    /// Prepares for phase 2 ceremony
    #[inline]
    pub fn run(self) {
        let now = Instant::now();

        let source_path =
            PathBuf::from(self.directory.clone()).join(format!("response_{}", self.round));
        println!("Decompressing response file at {:?}", source_path);
        let target_path =
            PathBuf::from(self.directory.clone()).join(format!("challenge_{}", self.round));
        let hash_path = PathBuf::from(self.directory).join(format!("response_{}_hash", self.round));

        let file = OpenOptions::new()
            .read(true)
            .open(source_path)
            .expect("Cannot open response file at path");
        let response_reader = unsafe {
            MmapOptions::new()
                .map(&file)
                .expect("Unable to create memory map for input")
        };
        let mut hash = [0u8; 64];
        let mut hash_file = OpenOptions::new()
            .read(true)
            .open(hash_path)
            .expect("Cannot open hash file at path");
        assert_eq!(
            hash_file
                .read(&mut hash[..])
                .expect("Failed to read hash from file"),
            64
        );

        decompress_response::<PpotCeremony>(&response_reader, hash, target_path)
            .expect("Error decompressing");
        println!(
            "Finished decompressing response file in {:?}",
            now.elapsed()
        );
    }
}

fn main() {
    Arguments::parse().run();
}
