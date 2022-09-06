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

//! Groth16 Trusted Setup Ceremony Registry

/// Participant Registry
pub trait Registry<I, P> {
    /// Registers the `participant` into `self` returning `false` if the `participant` is already
    /// registered or their registration would conflict with another existing participant.
    fn register(&mut self, participant: P) -> bool;

    /// Returns a shared reference to the participant with the given `id` if they are registered.
    fn get(&self, id: &I) -> Option<&P>;

    /// Returns a mutable reference to the participant with the given `id` if they are registered.
    fn get_mut(&mut self, id: &I) -> Option<&mut P>;

    /// Returns `true` if the participant with the given `id` has already contributed to the
    /// ceremony.
    fn has_contributed(&self, id: &I) -> bool;
}
