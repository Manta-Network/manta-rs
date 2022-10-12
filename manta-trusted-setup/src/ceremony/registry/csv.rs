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
use csv::{Reader, StringRecord};

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

/// Loads new entries into `registry` from `path` using `T` as the record type. Does not overwrite 
/// existing entries.
#[inline]
pub fn load_append_entries<I, V, T, R, P>(path: P, registry: &mut R) -> Result<(), Error<T::Error>>
where
    T: Record<I, V>,
    R: Registry<I, V>,
    P: AsRef<Path>,
{
    // temp
    let mut reader = Reader::from_reader(File::open(path)?);
    let short_headers = vec![
        "name",
        "email",
        "signature",
        "verifying_key",
        "twitter",
        "why_privacy",
        "wallet",
        "score",
        "twitter_repeat",
        "verifying_key_repeat",
        "discord",
        "submission_time",
        "submission_token",
    ];
    // assert_eq!(expected_headers.len(), short_headers.len());
    reader.set_headers(StringRecord::from(short_headers));

    for (number, record) in reader
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

#[cfg(feature = "csv")]
#[test]
fn header_test() {
    use std::{fs::File};
    use crate::groth16::ceremony::config::ppot::RegistrationInfo;

    let file = File::open("/Users/thomascnorton/Documents/Manta/manta-rs/manta-trusted-setup/data/registry_buffer.csv").expect("Cannot open file");
    let mut reader = Reader::from_reader(file);

    let headers = reader.byte_headers().expect("Cannot get headers");
    println!("Headers are {:?}", headers);
    let expected_headers = vec![
        "First up, what\'s your first name?", "What is your email address? ", "Okay {{field:c393dfe5f7faa4de}}, what your signature?", "What\'s your public key, {{field:c393dfe5f7faa4de}}?", "Finally, what\'s your Twitter Handle?  ", "Alright {{field:c393dfe5f7faa4de}}, why is privacy important to you?", "We want to reward participation with a POAP designed to commemorate this historical Web 3 achievement. If you would like to receive one please share your wallet address", "score", "Finally, what\'s your Twitter Handle?  ", "What\'s your public key, {{field:c393dfe5f7faa4de}}?", "What\'s your Discord ID, {{field:c393dfe5f7faa4de}}?", "Submitted At", "Token"
    ];
    assert_eq!(headers, expected_headers);
    let short_headers = vec![
        "name",
        "email",
        "signature",
        "verifying_key",
        "twitter",
        "why_privacy",
        "wallet",
        "score",
        "twitter_repeat",
        "verifying_key_repeat",
        "discord",
        "submission_time",
        "submission_token",
    ];
    assert_eq!(expected_headers.len(), short_headers.len());
    reader.set_headers(StringRecord::from(short_headers));
    let headers = reader.byte_headers().expect("Cannot get headers");
    println!("Headers are now {:?}", headers);
    for record in reader.deserialize::<RegistrationInfo>() {
        println!("{:?}", record.unwrap().name);
    }
}
