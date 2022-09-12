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

//! Trusted Setup Ceremony Utilities

use manta_util::serde::{de::DeserializeOwned, Serialize};
use std::{
    fs::{File, OpenOptions},
    path::Path,
};

/// Serializes `data` to a file at `path` with the given `open_options`.
#[inline]
pub fn serialize_into_file<T, P>(
    open_options: &mut OpenOptions,
    path: &P,
    data: &T,
) -> bincode::Result<()>
where
    P: AsRef<Path>,
    T: Serialize,
{
    bincode::serialize_into(open_options.open(path)?, data)
}

/// Deserializes an element of type `T` from the file at `path`.
#[inline]
pub fn deserialize_from_file<T, P>(path: P) -> bincode::Result<T>
where
    P: AsRef<Path>,
    T: DeserializeOwned,
{
    bincode::deserialize_from(File::open(path)?)
}
