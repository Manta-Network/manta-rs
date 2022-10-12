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
use manta_util::serde::de::DeserializeOwned;
use std::{fs::File, path::Path};

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
{
    let mut registry = R::new();
    load_append_entries::<_, _, T, _, _>(path, &mut registry)?;
    Ok(registry)
}

/// Loads new entries into `registry` from `path` using `T` as the record type. It doesn't overwrite 
/// existing entries.
#[inline]
pub fn load_append_entries<I, V, T, R, P>(path: P, registry: &mut R) -> Result<(), Error<T::Error>>
where
    T: Record<I, V>,
    R: Registry<I, V>,
    P: AsRef<Path>,
{
    for (number, record) in csv::Reader::from_reader(File::open(path)?)
        .deserialize()
        .flatten()
        .enumerate()
    {
        match T::parse(record) {
            Ok((identifier, participant)) => {
                registry.insert(identifier, participant);
            }
            Err(_) => {
                println!("Parsing error in line: {}", number + 2);
            }
        };
    }
    Ok(())
}
