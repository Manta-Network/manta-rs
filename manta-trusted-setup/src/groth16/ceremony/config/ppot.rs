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

use crate::ceremony::{
    participant,
    registry::csv,
    signature::{verify, Nonce as _, RawMessage, SignatureScheme},
};
use manta_crypto::{
    dalek::ed25519::{self, Ed25519},
    rand::{OsRng, Rand},
    signature::VerifyingKeyType,
};
use manta_util::serde::{Deserialize, Serialize};

type Signature = Ed25519<RawMessage<u64>>;
type VerifyingKey = <Signature as VerifyingKeyType>::VerifyingKey;
type Nonce = <Signature as SignatureScheme>::Nonce;

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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    bound(
        deserialize = "
        VerifyingKey: Deserialize<'de>,
        Nonce: Deserialize<'de>,
    ",
        serialize = "
        VerifyingKey: Serialize,
        Nonce: Serialize,
    "
    ),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
pub struct Participant {
    /// Twitter Account
    twitter: String,

    /// Priority
    priority: Priority,

    /// Verifying Key
    verifying_key: VerifyingKey,

    /// Nonce
    nonce: Nonce,

    /// Boolean on whether this participant has contributed
    contributed: bool,
}

impl Participant {
    /// Builds a new [`Participant`].
    #[inline]
    pub fn new(
        verifying_key: VerifyingKey,
        twitter: String,
        priority: Priority,
        nonce: Nonce,
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

impl participant::Participant for Participant {
    type Identifier = VerifyingKey;
    type VerifyingKey = VerifyingKey;
    type Nonce = Nonce;

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

impl participant::Priority for Participant {
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
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(
    bound(deserialize = "", serialize = ""),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
pub struct Record {
    twitter: String,
    email: String,
    priority: String,
    verifying_key: String,
    signature: String,
}

impl csv::Record<VerifyingKey, Participant> for Record {
    type Error = String;

    fn parse(self) -> Result<(VerifyingKey, Participant), Self::Error> {
        let verifying_key = ed25519::public_key_from_bytes(
            bs58::decode(self.verifying_key)
                .into_vec()
                .map_err(|_| "Cannot decode verifying key.".to_string())?
                .try_into()
                .map_err(|_| "Cannot decode to array.".to_string())?,
        );
        let signature: ed25519::Signature = ed25519::signature_from_bytes(
            bs58::decode(self.signature)
                .into_vec()
                .map_err(|_| "Cannot decode signature.".to_string())?
                .try_into()
                .map_err(|_| "Cannot decode to array.".to_string())?,
        );
        verify::<Signature, _>(
            &verifying_key,
            0,
            &format!(
                "manta-trusted-setup-twitter:{}, manta-trusted-setup-email:{}",
                self.twitter, self.email
            ),
            &signature,
        )
        .map_err(|_| "Cannot verify signature.".to_string())?;
        Ok((
            verifying_key,
            Participant::new(
                verifying_key,
                self.twitter,
                match self
                    .priority
                    .parse::<bool>()
                    .map_err(|_| "Cannot parse priority.".to_string())?
                {
                    true => Priority::High,
                    false => Priority::Normal,
                },
                OsRng.gen::<_, u16>() as u64,
                false,
            ),
        ))
    }
}
