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

use crate::ceremony::config::{CeremonyConfig, Nonce};
use serde::{Deserialize, Serialize};

// pub mod bls_server;
pub mod client;
pub mod config;
pub mod coordinator;
pub mod message;
pub mod queue;
pub mod registry;
pub mod server;
pub mod signature;

/// Ceremony Error
///
/// # Note
/// All errors here are visible to users.
#[derive(PartialEq, Serialize, Deserialize)]
#[serde(
    bound(
        serialize = "Nonce<C>: Serialize",
        deserialize = "Nonce<C>: Deserialize<'de>",
    ),
    deny_unknown_fields
)]
pub enum CeremonyError<C>
where
    C: CeremonyConfig,
{
    /// Malformed request that should not come from official client
    BadRequest,

    /// Nonce not in sync, and client needs to update the nonce
    NonceNotInSync(Nonce<C>),

    /// Not Registered
    NotRegistered,
}
