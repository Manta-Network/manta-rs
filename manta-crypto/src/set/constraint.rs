// Copyright 2019-2021 Manta Network.
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

//! Sets and Verified Set Proof Systems

use crate::{
    constraint::{AllocationMode, BooleanSystem, HasVariable, Var},
    set::{ContainmentProof, VerifiedSet},
};

/// Verified Set Proof System
pub trait VerifiedSetProofSystem<S>:
    BooleanSystem
    + HasVariable<S::Item, Mode = Self::ItemMode>
    + HasVariable<ContainmentProof<S>, Mode = Self::ContainmentProofMode>
where
    S: VerifiedSet,
{
    /// Item Allocation Mode
    type ItemMode: AllocationMode;

    /// Containment Proof Allocation Mode
    type ContainmentProofMode: AllocationMode;

    /// Asserts that `proof` is a witness to the fact that `item` is stored in the verified set.
    fn assert_verified(
        &mut self,
        proof: &Var<ContainmentProof<S>, Self>,
        item: &Var<S::Item, Self>,
    );
}
