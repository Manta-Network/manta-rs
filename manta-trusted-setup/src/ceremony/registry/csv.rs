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
    for record in csv::Reader::from_reader(File::open(path)?).deserialize() {
        let (identifier, participant) = T::parse(record?).map_err(Error::Parse)?;
        registry.insert(identifier, participant);
    }
    Ok(registry)
}
