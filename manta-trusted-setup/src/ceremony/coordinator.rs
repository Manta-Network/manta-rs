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
//! Ceremony coordinator.

use crate::{
    ceremony::{
        queue::{Identifier, Priority, Queue},
        registry::{Map, Registry},
    },
    mpc::Verify,
};

/// Coordinator with `V` as trusted setup verifier, `P` as participant, `M` as the map used by registry, `N` as the number of priority levels.
pub struct Coordinator<V, P, M, const N: usize>
where
    V: Verify,
    P: Priority + Identifier,
    M: Map<Key = P::Identifier, Value = P>,
{
    state: V::State,
    registry: Registry<M>,
    queue: Queue<P, N>,
}

impl<V, P, M, const N: usize> Coordinator<V, P, M, N>
where
    V: Verify,
    P: Priority + Identifier,
    M: Map<Key = P::Identifier, Value = P>,
{
    // TODO
}
