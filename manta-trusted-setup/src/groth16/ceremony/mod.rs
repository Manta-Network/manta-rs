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

use crate::mpc;

pub mod registry;

#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
pub mod coordinator;

#[cfg(all(feature = "bincode", feature = "serde"))]
#[cfg_attr(doc_cfg, doc(cfg(all(feature = "bincode", feature = "serde"))))]
pub mod signature;

/// Participant
pub trait Participant {
    /// Participant Identifier Type
    type Identifier;

    /// Returns the [`Identifier`](Self::Identifier) for `self`.
    fn id(&self) -> &Self::Identifier;

    /// Returns the priority level for `self`.
    fn level(&self) -> usize;
}

/// Ceremony Configuration
pub trait Ceremony: mpc::Types {
    /// Participant Identifier Type
    type Identifier: Clone + PartialEq;

    /// Participant Type
    type Participant: Participant<Identifier = Self::Identifier>;
}
