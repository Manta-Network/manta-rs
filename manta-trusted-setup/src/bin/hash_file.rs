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

//! File hasher

use blake2::{Blake2b, Digest};
use clap::Parser;
use manta_util::into_array_unchecked;
use memmap::{Mmap, MmapOptions};
use std::{fs::OpenOptions, io::Write, path::PathBuf};

/// Command Line Arguments
#[derive(Debug, Parser)]
pub struct Arguments {
    /// Path to file
    path: String,
}

impl Arguments {
    /// Prepares for phase 2 ceremony
    #[inline]
    pub fn run(self) {
        let source_path = PathBuf::from(self.path.clone());
        let target_path = PathBuf::from(format!("{}_hash", self.path));
        println!("Hashing file at {:?}", source_path);

        hash_file(target_path, source_path).expect("Unable to hash file");
    }
}

pub fn main() {
    Arguments::parse().run();
}

/// Computes the hash of a potentially large file,
/// such as PPoT `challenge` or `response` files.
pub fn calculate_hash(input_map: &Mmap) -> [u8; 64] {
    let chunk_size = 1 << 30; // read by 1GB from map
    let mut hasher = Blake2b::default();

    for (counter, chunk) in input_map.chunks(chunk_size).enumerate() {
        hasher.update(chunk);
        println!("Have hashed {:?} GB of the file", counter);
    }
    into_array_unchecked(hasher.finalize())
}

/// Hashes the file at `path` and saves the hash to file at `target`.
fn hash_file(target: PathBuf, path: PathBuf) -> Result<(), std::io::Error> {
    // Make memory map from `path`
    let reader = OpenOptions::new()
        .read(true)
        .open(path)
        .expect("unable open file in this directory");
    // Make a memory map
    let reader = unsafe {
        MmapOptions::new()
            .map(&reader)
            .expect("unable to create a memory map for input")
    };
    let hash = calculate_hash(&reader);
    println!("Computed hash {:?}", hash);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(target)
        .expect("Unable to create target file");
    file.write_all(&hash)?;
    Ok(())
}
