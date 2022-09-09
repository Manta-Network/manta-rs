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

//! Groth16 Trusted Setup Ceremony

use crate::groth16::{ceremony::signature::SignatureScheme, mpc::Configuration};
use derivative::Derivative;
use manta_crypto::signature::{SignatureType, SigningKeyType, VerifyingKeyType};
use manta_util::{
    collections::vec_deque::MultiVecDeque,
    serde::{Deserialize, Serialize},
};

// pub mod client;
pub mod message;
pub mod participant;
pub mod registry;
pub mod server;
pub mod signature;
pub mod util;

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
pub mod coordinator;

/// Nonce
pub type Nonce<C> = <C as SignatureScheme>::Nonce;

/// Signature
pub type Signature<C> = <C as SignatureType>::Signature;

/// Signing Key
pub type SigningKey<C> = <C as SigningKeyType>::SigningKey;

/// Verifying Key
pub type VerifyingKey<C> = <C as VerifyingKeyType>::VerifyingKey;

/// Challenge Type
pub type Challenge<C> = <C as Configuration>::Challenge;

/// Participant Queue Type
pub type Queue<C, const LEVEL_COUNT: usize> =
    MultiVecDeque<<C as Ceremony>::Identifier, LEVEL_COUNT>;

/// Participant
pub trait Participant {
    /// Participant Identifier Type
    type Identifier;

    /// Participant Verifying Key Type
    type VerifyingKey;

    /// Nonce
    type Nonce;

    // /// Builds a new [`Participant`].
    // fn new(

    // ) -> Self;

    /// Returns the [`Identifier`](Self::Identifier) for `self`.
    fn id(&self) -> &Self::Identifier;

    /// Returns the [`VerifyingKey`](Self::VerifyingKey) for `self`.
    fn verifying_key(&self) -> &Self::VerifyingKey;

    /// Returns the priority level for `self`.
    ///
    /// # Note
    ///
    /// Lower level indicates a higher priority.
    fn level(&self) -> UserPriority;

    /// Returns nonce for `self`.
    fn get_nonce(&self) -> Self::Nonce;

    /// Set nonce of current participant
    fn increment_nonce(&mut self);

    /// Reduces the priority.
    fn reduce_priority(&mut self);

    /// Checks if the participant has contributed.
    fn has_contributed(&self) -> bool;

    /// Sets contributed.
    fn set_contributed(&mut self);
}

/// Ceremony Configuration
pub trait Ceremony: SignatureScheme + Configuration {
    /// Participant Identifier Type
    type Identifier: Clone + PartialEq;

    /// Participant Type
    type Participant: Participant<
        Identifier = Self::Identifier,
        Nonce = Nonce<Self>,
        VerifyingKey = VerifyingKey<Self>,
    >;
}

/// Ceremony Error
///
/// # Note
///
/// All errors here are visible to users.
#[derive(PartialEq, Serialize, Deserialize, Derivative)]
#[derivative(Debug(bound = "Nonce<C>: core::fmt::Debug"))]
#[serde(
    bound(
        serialize = "Nonce<C>: Serialize",
        deserialize = "Nonce<C>: Deserialize<'de>",
    ),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
pub enum CeremonyError<C>
where
    C: Ceremony,
{
    /// Malformed request that should not come from official client
    BadRequest,

    /// Nonce not in sync, and client needs to update the nonce
    NonceNotInSync(Nonce<C>),

    /// Not Registered
    NotRegistered,

    /// Already Contributed
    AlreadyContributed,

    /// Not Your Turn
    NotYourTurn,

    /// Timed-out
    Timeout,

    /// Unexpected Server Error
    Unexpected,
}

/// Priority
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(
    bound(deserialize = "", serialize = ""),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
pub enum UserPriority {
    /// High Priority
    High,

    /// Normal Priority
    Normal,
}

impl From<UserPriority> for usize {
    fn from(priority: UserPriority) -> Self {
        match priority {
            UserPriority::High => 0,
            UserPriority::Normal => 1,
        }
    }
}
