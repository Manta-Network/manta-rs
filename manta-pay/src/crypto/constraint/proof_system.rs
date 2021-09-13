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

//! Proof System Implementation

use manta_crypto::constraint::{Alloc, Allocation, Bool, BooleanSystem, ProofSystem, Variable};

/// Arkworks Proof System
#[derive(Default)]
pub struct ArkProofSystem;

/// TODO
pub struct BoolVar;

impl Variable<ArkProofSystem> for BoolVar {
    type Mode = ();
    type Type = bool;
}

impl Alloc<ArkProofSystem> for bool {
    type Mode = ();
    type Variable = BoolVar;

    #[inline]
    fn variable<'t>(
        ps: &mut ArkProofSystem,
        allocation: impl Into<Allocation<'t, Self, ArkProofSystem>>,
    ) -> Self::Variable
    where
        Self: 't,
    {
        let _ = (ps, allocation);
        todo!()
    }
}

impl BooleanSystem for ArkProofSystem {
    #[inline]
    fn assert(&mut self, b: Bool<Self>) {
        let _ = b;
        todo!()
    }
}

impl ProofSystem for ArkProofSystem {
    type Proof = ();

    type Error = ();

    #[inline]
    fn finish(self) -> Result<Self::Proof, Self::Error> {
        todo!()
    }
}
