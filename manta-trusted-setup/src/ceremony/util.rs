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

//! Utilities

use crate::ceremony::config::{Challenge, State};
use manta_crypto::arkworks::serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

use super::config::CeremonyConfig;

/// Logs `state` and `challenge` to a disk file at `path`.
pub fn log_to_file<C, P>(path: &P, state: State<C>, challenge: Challenge<C>)
where
    C: CeremonyConfig,
    P: AsRef<Path>,
    State<C>: CanonicalSerialize,
    Challenge<C>: CanonicalSerialize,
{
    let mut writer = Vec::new();
    state
        .serialize(&mut writer)
        .expect("Serializing states should succeed.");
    challenge
        .serialize(&mut writer)
        .expect("Serializing challenges should succeed.");
    let mut file = File::create(path).expect("Open file should succeed.");
    file.write_all(&writer)
        .expect("Write phase one parameters to disk should succeed.");
    file.flush().expect("Unable to flush file.");
}

/// Loads `state` and `challenge` from a disk file at `path`.
pub fn load_from_file<C, P>(path: P) -> (State<C>, Challenge<C>)
where
    C: CeremonyConfig,
    P: AsRef<Path>,
    State<C>: CanonicalDeserialize,
    Challenge<C>: CanonicalDeserialize,
{
    let mut file = File::open(path).expect("Open file should succeed.");
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .expect("Reading data should succeed.");
    let mut reader = &buf[..];
    (
        CanonicalDeserialize::deserialize(&mut reader).expect("Deserialize should succeed."),
        CanonicalDeserialize::deserialize(&mut reader).expect("Deserialize should succeed."),
    )
}
