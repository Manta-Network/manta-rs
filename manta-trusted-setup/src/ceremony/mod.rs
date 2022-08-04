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

//! Client and Server Interfaces and Implementations for Manta Trusted Setup Ceremony

use core::{fmt, fmt::Display};

// pub mod bls_server;
pub mod coordinator;
pub mod message;
pub mod queue;
pub mod registry;
pub mod server;
pub mod signature;

/// Ceremony Error
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CeremonyError {
    /// Participant Already Registered Error
    AlreadyRegistered,

    /// Not Registered Error
    NotRegistered,

    /// Invalid Signature Error
    InvalidSignature,

    /// Not Your Turn Error
    NotYourTurn,

    /// Empty Waiting Queue Error
    WaitingQueueEmpty,

    /// Invalid Contribution Error
    InvalidContribution,

    /// Invalid Nonce
    InvalidNonce,
}

impl Display for CeremonyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CeremonyError::AlreadyRegistered => write!(f, "Already registered"),
            CeremonyError::NotRegistered => write!(f, "Not registered"),
            CeremonyError::InvalidSignature => write!(f, "Invalid signature"),
            CeremonyError::NotYourTurn => write!(f, "Not your turn"),
            CeremonyError::WaitingQueueEmpty => write!(f, "Waiting queue is empty"),
            CeremonyError::InvalidContribution => write!(f, "Invalid contribution"),
            _ => write!(f, "Unknown error"),
        }
    }
}
