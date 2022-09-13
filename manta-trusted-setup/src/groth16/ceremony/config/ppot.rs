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

//! Groth16 Trusted Setup Ceremony Perpetual Powers of Tau Configuration

use core::marker::PhantomData;

use manta_crypto::{dalek::ed25519, signature::Sign};
use manta_util::serde::{Deserialize, Serialize};

use crate::{
    ceremony::{
        participant,
        registry::csv,
        signature::{Nonce, SignatureScheme},
    },
    groth16::ceremony::Ceremony,
};

/// Priority
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(
    bound(deserialize = "", serialize = ""),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
pub enum Priority {
    /// High Priority
    High,

    /// Normal Priority
    Normal,
}

impl From<Priority> for usize {
    #[inline]
    fn from(priority: Priority) -> Self {
        match priority {
            Priority::High => 0,
            Priority::Normal => 1,
        }
    }
}

/// Participant
pub struct Participant<S>
where
    S: SignatureScheme,
{
    /// Twitter Account
    twitter: String,

    /// Priority
    priority: Priority,

    /// Verifying Key
    verifying_key: S::VerifyingKey,

    /// Nonce
    nonce: S::Nonce,

    /// Boolean on whether this participant has contributed
    contributed: bool,
}

impl<S> Participant<S>
where
    S: SignatureScheme,
{
    /// Builds a new [`Participant`].
    #[inline]
    pub fn new(
        verifying_key: S::VerifyingKey,
        twitter: String,
        priority: Priority,
        nonce: S::Nonce,
        contributed: bool,
    ) -> Self {
        Self {
            verifying_key,
            twitter,
            priority,
            nonce,
            contributed,
        }
    }

    /// Gets `twitter`.
    #[inline]
    pub fn twitter(&self) -> &str {
        &self.twitter
    }
}

impl<S> participant::Participant for Participant<S>
where
    S: SignatureScheme,
{
    type Identifier = S::VerifyingKey;
    type VerifyingKey = S::VerifyingKey;
    type Nonce = S::Nonce;

    #[inline]
    fn id(&self) -> &Self::Identifier {
        &self.verifying_key
    }

    #[inline]
    fn verifying_key(&self) -> &Self::VerifyingKey {
        &self.verifying_key
    }

    #[inline]
    fn has_contributed(&self) -> bool {
        self.contributed
    }

    #[inline]
    fn set_contributed(&mut self) {
        self.contributed = true
    }

    #[inline]
    fn nonce(&self) -> &Self::Nonce {
        &self.nonce
    }

    #[inline]
    fn increment_nonce(&mut self) {
        self.nonce.increment();
    }
}

impl<S> participant::Priority for Participant<S>
where
    S: SignatureScheme,
{
    type Priority = Priority;

    #[inline]
    fn priority(&self) -> Self::Priority {
        self.priority.clone()
    }

    #[inline]
    fn reduce_priority(&mut self) {
        self.priority = Priority::Normal;
    }
}

/// Record
pub struct Record;

/* TODO:
impl<S> csv::Record<S::VerifyingKey, Participant<S>> for Record
where
    S: SignatureScheme,
{
    type Error;

    fn parse(self) -> Result<(S::VerifyingKey, Participant<S>), Self::Error> {
        if self.len() != 5 {
            return Err(CeremonyError::Unexpected(
                "Record format is wrong.".to_string(),
            ));
        }
        let twitter = record[0].to_string();
        let email = record[1].to_string();
        let verifying_key = ed25519::public_key_from_bytes(
            bs58::decode(record[3].to_string())
                .into_vec()
                .map_err(|_| CeremonyError::Unexpected("Cannot decode verifying key.".to_string()))?
                .try_into()
                .map_err(|_| CeremonyError::Unexpected("Cannot decode to array.".to_string()))?,
        );
        let signature: ed25519::Signature = ed25519::signature_from_bytes(
            bs58::decode(record[4].to_string())
                .into_vec()
                .map_err(|_| CeremonyError::Unexpected("Cannot decode signature.".to_string()))?
                .try_into()
                .map_err(|_| CeremonyError::Unexpected("Cannot decode to array.".to_string()))?,
        );
        verify::<_, _>(
            &verifying_key,
            0,
            &format!(
                "manta-trusted-setup-twitter:{}, manta-trusted-setup-email:{}",
                twitter, email
            ),
            &signature,
        )
        .map_err(|_| CeremonyError::Unexpected("Cannot verify signature.".to_string()))?;
        Ok((
            verifying_key,
            Participant::new(
                verifying_key,
                twitter,
                match record[2].to_string().parse::<bool>().unwrap() {
                    true => Priority::High,
                    false => Priority::Normal,
                },
                OsRng.gen::<_, u16>() as u64,
                false,
            ),
        ))
    }
}
 */

/* TODO: replace with `Record` parsing:

/// Prases a string `record` into a pair of `(C::Identifier, C::Participant)`.
#[inline]
pub fn parse<C>(
    record: csv::StringRecord,
) -> Result<(C::VerifyingKey, C::Participant), CeremonyError<C>>
where
    C: Ceremony<Nonce = u64, Participant = Participant<C>, VerifyingKey = ed25519::PublicKey>,
{
    if record.len() != 5 {
        return Err(CeremonyError::Unexpected(
            "Record format is wrong.".to_string(),
        ));
    }
    let twitter = record[0].to_string();
    let email = record[1].to_string();
    let verifying_key = ed25519::public_key_from_bytes(
        bs58::decode(record[3].to_string())
            .into_vec()
            .map_err(|_| CeremonyError::Unexpected("Cannot decode verifying key.".to_string()))?
            .try_into()
            .map_err(|_| CeremonyError::Unexpected("Cannot decode to array.".to_string()))?,
    );
    let signature: ed25519::Signature = ed25519::signature_from_bytes(
        bs58::decode(record[4].to_string())
            .into_vec()
            .map_err(|_| CeremonyError::Unexpected("Cannot decode signature.".to_string()))?
            .try_into()
            .map_err(|_| CeremonyError::Unexpected("Cannot decode to array.".to_string()))?,
    );
    verify::<_, _>(
        &verifying_key,
        0,
        &format!(
            "manta-trusted-setup-twitter:{}, manta-trusted-setup-email:{}",
            twitter, email
        ),
        &signature,
    )
    .map_err(|_| CeremonyError::Unexpected("Cannot verify signature.".to_string()))?;
    Ok((
        verifying_key,
        Participant::new(
            verifying_key,
            twitter,
            match record[2].to_string().parse::<bool>().unwrap() {
                true => Priority::High,
                false => Priority::Normal,
            },
            OsRng.gen::<_, u16>() as u64,
            false,
        ),
    ))
}

/// Loads registry from a disk file at `registry`.
#[inline]
pub fn load_registry<C, P, R>(registry_file: P) -> Result<R, CeremonyError<C>>
where
    C: Ceremony<Nonce = u64, Participant = Participant<C>, VerifyingKey = ed25519::PublicKey>,
    P: AsRef<Path>,
    R: Registry<C::VerifyingKey, C::Participant>,
{
    let mut registry = R::new();
    for record in csv::Reader::from_reader(
        File::open(registry_file)
            .map_err(|_| CeremonyError::Unexpected("Cannot open registry file.".to_string()))?,
    )
    .records()
    {
        let (identifier, participant) = parse(record.map_err(|_| {
            CeremonyError::Unexpected("Cannot parse record from csv.".to_string())
        })?)?;
        registry.register(identifier, participant);
    }
    Ok(registry)
}
*/
