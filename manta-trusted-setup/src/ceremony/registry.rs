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

//! Registry

use crate::{
    ceremony::{
        config::{g16_bls12_381::Participant, CeremonyConfig},
        signature::{ed_dalek, SignatureScheme},
        state::UserPriority,
    },
    util::AsBytes,
};
use alloc::collections::BTreeMap;
use manta_crypto::{
    arkworks::serialize::{CanonicalDeserialize, CanonicalSerialize},
    rand::{OsRng, Rand},
};
use manta_pay::crypto::constraint::arkworks::codec::SerializationError;
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

/// Has Contributed
pub trait HasContributed {
    /// Checks if the participant has contributed.
    fn has_contributed(&self) -> bool;

    /// Sets the participant as contributed.
    fn set_contributed(&mut self);
}

/// Registry
pub struct Registry<K, V>
where
    K: Ord,
{
    /// Map from key `K` to value `V`
    map: BTreeMap<K, V>,
}

impl<K, V> Registry<K, V>
where
    K: Ord,
{
    /// Builds a new [`Registry`].
    #[inline]
    pub fn new(map: BTreeMap<K, V>) -> Self {
        Self { map }
    }

    /// Inserts a `(key, value)` pair into registry.
    #[inline]
    pub fn insert(&mut self, key: K, value: V) -> Result<(), &'static str> {
        match self.map.insert(key, value) {
            None => Ok(()),
            Some(_) => Err("Invalid insertion into registry."),
        }
    }

    /// Gets the participant value given the `id` and returns `None` if the participant is not registered.
    #[inline]
    pub fn get(&self, id: &K) -> Option<&V> {
        self.map.get(id)
    }

    /// Gets the mutable reference of participant value given the `id` and returns `None` if the participant is not registered.
    #[inline]
    pub fn get_mut(&mut self, id: &K) -> Option<&mut V> {
        self.map.get_mut(id)
    }

    /// Checks if `id` has contributed.
    #[inline]
    pub fn has_contributed(&self, id: &K) -> bool
    where
        V: HasContributed,
    {
        self.map
            .get(id)
            .map(|v| v.has_contributed())
            .unwrap_or(false)
    }
}

impl<K, V> CanonicalSerialize for Registry<K, V>
where
    K: Ord + CanonicalSerialize,
    V: CanonicalSerialize,
{
    fn serialize<W>(&self, mut writer: W) -> Result<(), SerializationError>
    where
        W: Write,
    {
        self.map
            .serialize(&mut writer)
            .expect("Serializing should succeed");
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        self.map.serialized_size()
    }
}

impl<K, V> CanonicalDeserialize for Registry<K, V>
where
    K: Ord + CanonicalDeserialize,
    V: CanonicalDeserialize,
{
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        Ok(Self {
            map: CanonicalDeserialize::deserialize(&mut reader)
                .expect("Deserializing should succeed."),
        })
    }
}

/// Loads registry from a disk file at `registry`.
pub fn load_registry<C, P>(
    registry: P,
) -> Registry<ed_dalek::PublicKey, <C as CeremonyConfig>::Participant>
where
    P: AsRef<Path>,
    C: CeremonyConfig<Participant = Participant>,
{
    let mut map = BTreeMap::new();
    for record in
        csv::Reader::from_reader(File::open(registry).expect("Registry file should exist."))
            .records()
    {
        let result = record.expect("Read csv should succeed.");
        let twitter = result[0].to_string();
        let email = result[1].to_string();
        let public_key: ed_dalek::PublicKey = AsBytes::new(
            bs58::decode(result[3].to_string())
                .into_vec()
                .expect("Decode public key should succeed."),
        )
        .to_actual()
        .expect("Converting to a public key should succeed.");
        let signature: ed_dalek::Signature = AsBytes::new(
            bs58::decode(result[4].to_string())
                .into_vec()
                .expect("Decode signature should succeed."),
        )
        .to_actual()
        .expect("Converting to a signature should succeed.");
        ed_dalek::Ed25519::verify(
            format!(
                "manta-trusted-setup-twitter:{}, manta-trusted-setup-email:{}",
                twitter, email
            ),
            &0,
            &signature,
            &public_key,
        )
        .expect("Verifying signature should succeed.");
        let participant = Participant {
            twitter,
            priority: match result[2].to_string().parse::<bool>().unwrap() {
                true => UserPriority::High,
                false => UserPriority::Normal,
            },
            public_key,
            nonce: OsRng.gen(),
            contributed: false,
        };
        map.insert(participant.public_key, participant);
    }
    Registry::new(map)
}
