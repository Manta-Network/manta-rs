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

use crate::{
    ceremony::{
        participant::{Participant, Priority},
        signature::SignatureScheme,
    },
    groth16::mpc::Configuration,
};
use core::fmt::Debug;
use manta_util::{
    collections::vec_deque::MultiVecDeque,
    serde::{Deserialize, Serialize},
};

pub mod client;
pub mod config;
pub mod coordinator;
pub mod message;
pub mod server;

/// Participant Queue Type
pub type Queue<C, const LEVEL_COUNT: usize> =
    MultiVecDeque<<C as Ceremony>::Identifier, LEVEL_COUNT>;

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
            Nonce = Self::Nonce,
        > + Priority<Priority = Self::Priority>;
}

/// Ceremony Error
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            serialize = "C::Nonce: Serialize",
            deserialize = "C::Nonce: Deserialize<'de>",
        ),
        crate = "manta_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(Debug(bound = "C::Nonce: Debug"))]
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

    /// Client unable to Generate Request
    UnableToGenerateRequest(String),

    /// Unexpected Server Error
    Unexpected(String),

    /// Network Error
    Network(String),
}
