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
    groth16::mpc::{Configuration, State, StateSize},
    mpc,
};
use core::{fmt::Debug, time::Duration};
use manta_crypto::arkworks::pairing::Pairing;
use manta_util::{
    collections::vec_deque::MultiVecDeque,
    serde::{Deserialize, Serialize},
};

pub mod client;
pub mod config;
pub mod message;

#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
pub mod coordinator;

#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
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

/// Parallel Round Alias
///
/// In the ceremony we always use parallel round structures to support multiple Groth16 circuits at
/// the same time.
pub type Round<C> = mpc::ParallelRound<C>;

/// Ceremony Size Alias
///
/// In the ceremony we always use parallel round structures to support multiple Groth16 circuits at
/// the same time.
pub type CeremonySize = mpc::Parallel<StateSize>;

impl CeremonySize {
    /// Checks that each size in `self` matches each [`State`] in `states`.
    #[inline]
    pub fn matches<P>(&self, states: &[State<P>]) -> bool
    where
        P: Pairing,
    {
        self.len() == states.len() && self.iter().zip(states).all(|(l, r)| l.matches(&r.0))
    }
}

/// Ceremony Metadata
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Metadata {
    /// Ceremony Size
    pub ceremony_size: CeremonySize,

    /// Contribution Time Limit
    pub contribution_time_limit: Duration,
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

    /// Invalid Signature
    InvalidSignature {
        /// Expected Nonce
        ///
        /// We also return the nonce here in case the client has gotten out of sync with the server.
        expected_nonce: C::Nonce,
    },

    /// Not Registered
    NotRegistered,

    /// Already Contributed
    AlreadyContributed,

    /// Not Your Turn
    NotYourTurn,

    /// Timed out
    Timeout,

    /// Network Error
    Network,

    /// Unexpected Server Error
    Unexpected(UnexpectedError),
}

/// Unexpected Error
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Debug)]
pub enum UnexpectedError {
    /// Serialization Error
    Serialization,

    /// Failed to generate a valid Contribution
    FailedContribution,

    /// Missing Registered Participant
    MissingRegisteredParticipant,

    /// Incorrect State Size
    IncorrectStateSize,

    /// All Nonces were Used
    AllNoncesUsed,
}
