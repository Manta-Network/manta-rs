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

//! Trusted Setup Ceremony Participants

/// Participant
pub trait Participant {
    /// Identifier Type
    type Identifier;

    /// Verifying Key Type
    type VerifyingKey;

    /// Nonce Type
    type Nonce;

    /// Returns the [`Identifier`](Self::Identifier) for `self`.
    fn id(&self) -> &Self::Identifier;

    /// Returns the [`VerifyingKey`](Self::VerifyingKey) for `self`.
    fn verifying_key(&self) -> &Self::VerifyingKey;

    /// Checks if the participant has contributed.
    fn has_contributed(&self) -> bool;

    /// Sets contributed.
    fn set_contributed(&mut self);

    /// Returns the current nonce for `self`.
    fn nonce(&self) -> &Self::Nonce;

    /// Increments the current nonce of `self` by one.
    fn increment_nonce(&mut self);
}

/// Priority
pub trait Priority {
    /// Priority Type
    type Priority;

    /// Returns the priority level for `self`.
    fn priority(&self) -> Self::Priority;

    /// Reduces the priority.
    fn reduce_priority(&mut self);
}
