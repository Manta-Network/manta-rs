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

//! Sets and Verified Set Constraint Systems

use crate::{
    constraint::{Alloc, BooleanSystem, Var, Variable},
    set::{ContainmentProof, VerifiedSet},
};

/// Containment Proof Variable
pub trait ContainmentProofVariable<P>:
    Variable<P, Type = ContainmentProof<Self::VerifiedSet>>
where
    P: BooleanSystem + ?Sized,
{
    /// Item Type
    type Item: Alloc<P>;

    /// Verified Set
    type VerifiedSet: VerifiedSet<Item = Self::Item>;

    /// Asserts that `self` is a witness to the fact that `item` is stored in the verified set.
    fn assert_verified(&self, item: &Var<Self::Item, P>, ps: &mut P);
}
