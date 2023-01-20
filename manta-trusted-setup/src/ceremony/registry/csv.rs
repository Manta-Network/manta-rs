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

//! Trusted Setup Ceremony Registry CSV Compatibility

use crate::ceremony::registry::Registry;
use core::fmt::Debug;
use openzl_util::serde::de::DeserializeOwned;
use std::{
    fs::{File, OpenOptions},
    io::{Seek, SeekFrom},
    path::Path,
};

/// CSV Record
pub trait Record<I, V>: DeserializeOwned {
    /// Error Type
    type Error;

    /// Parses a registry entry of type `(I, V)` from `self`.
    fn parse(self) -> Result<(I, V), Self::Error>;
}

/// Record Error
#[derive(Debug)]
pub enum Error<E> {
    /// Parsing Error
    Parse(E),

    /// CSV Reading Error
    Csv(csv::Error),
}

impl<T, E> From<T> for Error<E>
where
    T: Into<csv::Error>,
{
    #[inline]
    fn from(err: T) -> Self {
        Self::Csv(err.into())
    }
}

/// Loads a registry of type `R` from `path` using `T` as the record type.
#[inline]
pub fn load<I, V, T, R, P>(path: P) -> Result<R, Error<T::Error>>
where
    T: Record<I, V>,
    R: Registry<I, V>,
    P: AsRef<Path>,
    T::Error: Debug,
{
    let mut registry = R::new();
    load_append_entries::<_, _, T, _, _>(path, &mut registry)?;
    Ok(registry)
}

/// Loads new entries into `registry` from `path` using `T` as the record type without overwriting
/// existing entries. Returns the number of new entries added.
#[inline]
pub fn load_append_entries<I, V, T, R, P>(
    path: P,
    registry: &mut R,
) -> Result<usize, Error<T::Error>>
where
    T: Record<I, V>,
    R: Registry<I, V>,
    P: AsRef<Path>,
    T::Error: Debug,
{
    let length = registry.len();

    for (number, record) in csv::Reader::from_reader(File::open(path)?)
        .deserialize()
        .flatten()
        .enumerate()
    {
        match T::parse(record) {
            Ok((identifier, participant)) => {
                registry.insert(identifier, participant);
            }
            Err(e) => {
                println!("Line: {} Parsing error {e:?}", number + 2);
            }
        };
    }
    Ok(registry.len() - length)
}

/// Build an append-only CSV writer from a file path.
/// Missing files are created.
pub fn append_only_csv_writer<E, P>(path: P) -> Result<csv::Writer<File>, E>
where
    P: AsRef<Path>,
    E: From<std::io::Error>,
{
    let mut file = OpenOptions::new().write(true).create(true).open(&path)?;
    let mut file_is_empty = false;
    if file.seek(SeekFrom::End(0))? == 0 {
        file_is_empty = true;
    }
    Ok(csv::WriterBuilder::new()
        .has_headers(file_is_empty)
        .from_writer(file))
}
