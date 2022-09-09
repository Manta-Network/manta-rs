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

use crate::groth16::{
    ceremony::signature::{Nonce, SignatureScheme},
    mpc::Configuration,
};
use manta_util::{
    collections::vec_deque::MultiVecDeque,
    serde::{Deserialize, Serialize},
};

pub mod client;
pub mod message;
pub mod participant;
pub mod registry;
pub mod server;
pub mod signature;
pub mod util;

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
pub mod coordinator;

/// Participant Queue Type
pub type Queue<C, const LEVEL_COUNT: usize> =
    MultiVecDeque<<C as Ceremony>::Identifier, LEVEL_COUNT>;

/// Participant
pub trait Participant {
    /// Identifier Type
    type Identifier;

    /// Verifying Key Type
    type VerifyingKey;

    /// Priority Type
    type Priority;

    /// Nonce Type
    type Nonce: Nonce;

    /// Returns the [`Identifier`](Self::Identifier) for `self`.
    fn id(&self) -> &Self::Identifier;

    /// Returns the [`VerifyingKey`](Self::VerifyingKey) for `self`.
    fn verifying_key(&self) -> &Self::VerifyingKey;

    /// Returns the priority level for `self`.
    fn priority(&self) -> Self::Priority;

    /// Reduces the priority.
    fn reduce_priority(&mut self);

    /// Checks if the participant has contributed.
    fn has_contributed(&self) -> bool;

    /// Sets contributed.
    fn set_contributed(&mut self);

    /// Returns the current nonce for `self`.
    fn nonce(&self) -> Self::Nonce;

    /// Increments the current nonce of `self` by one.
    fn increment_nonce(&mut self);
}

/// Ceremony Configuration
pub trait Ceremony: Configuration + SignatureScheme {
    /// Participant Identifier Type
    type Identifier: Clone + PartialEq;

    /// Participant Priority Type
    type Priority: Into<usize>;

    /// Participant Type
    type Participant: Participant<
        Identifier = Self::Identifier,
        VerifyingKey = Self::VerifyingKey,
        Priority = Self::Priority,
        Nonce = Self::Nonce,
    >;
}

/// Ceremony Error
#[derive(derivative::Derivative, Deserialize, Serialize, PartialEq)]
#[derivative(Debug(bound = "C::Nonce: core::fmt::Debug"))]
#[serde(
    bound(
        serialize = "C::Nonce: Serialize",
        deserialize = "C::Nonce: Deserialize<'de>",
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
    NonceNotInSync(C::Nonce),

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
