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

//! Arkworks Proof System Implementation

use ark_ff::fields::Field;
use ark_r1cs_std::{alloc::AllocVar, bits::boolean::Boolean, eq::EqGadget};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError},
};
use manta_crypto::constraint::{
    Alloc, Allocation, AllocationMode, Bool, BooleanSystem, ProofSystem, PublicOrSecret, Variable,
};

/// Returns a blank variable assignment.
const fn blank<T>() -> Result<T, SynthesisError> {
    Err(SynthesisError::AssignmentMissing)
}

/// Arkworks Allocation Mode
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ArkAllocationMode {
    /// Allocates a Constant Variable
    Constant,

    /// Allocates a Public Input Variable
    Public,

    /// Allocates a Secret Witness Variable
    Secret,
}

impl AllocationMode for ArkAllocationMode {
    type Known = Self;
    type Unknown = PublicOrSecret;
}

/// Arkworks Proof System
pub struct ArkProofSystem<F>
where
    F: Field,
{
    /// Constraint System
    cs: ConstraintSystemRef<F>,
}

impl<F> Default for ArkProofSystem<F>
where
    F: Field,
{
    #[inline]
    fn default() -> Self {
        Self {
            cs: ConstraintSystem::new_ref(),
        }
    }
}

impl<F> Variable<ArkProofSystem<F>> for Boolean<F>
where
    F: Field,
{
    type Mode = ArkAllocationMode;
    type Type = bool;
}

impl<F> Alloc<ArkProofSystem<F>> for bool
where
    F: Field,
{
    type Mode = ArkAllocationMode;
    type Variable = Boolean<F>;

    #[inline]
    fn variable<'t>(
        ps: &mut ArkProofSystem<F>,
        allocation: impl Into<Allocation<'t, Self, ArkProofSystem<F>>>,
    ) -> Self::Variable
    where
        Self: 't,
    {
        use ArkAllocationMode::*;
        match allocation.into() {
            Allocation::Known(this, mode) => match mode {
                Constant => Self::Variable::new_constant(ns!(ps.cs, "boolean constant"), this),
                Public => Self::Variable::new_input(ns!(ps.cs, "boolean input"), move || Ok(this)),
                Secret => {
                    Self::Variable::new_witness(ns!(ps.cs, "boolean witness"), move || Ok(this))
                }
            },
            Allocation::Unknown(mode) => match mode {
                PublicOrSecret::Public => {
                    Self::Variable::new_input(ns!(ps.cs, "boolean input"), blank::<bool>)
                }
                PublicOrSecret::Secret => {
                    Self::Variable::new_witness(ns!(ps.cs, "boolean witness"), blank::<bool>)
                }
            },
        }
        .expect("Variable allocation is not allowed to fail.")
    }
}

impl<F> BooleanSystem for ArkProofSystem<F>
where
    F: Field,
{
    #[inline]
    fn assert(&mut self, b: Bool<Self>) {
        // FIXME: Is there a more direct way to do assertions?
        b.enforce_equal(&Boolean::TRUE)
            .expect("This should never fail.")
    }
}

impl<F> ProofSystem for ArkProofSystem<F>
where
    F: Field,
{
    type Proof = ();

    type Error = ();

    #[inline]
    fn finish(self) -> Result<Self::Proof, Self::Error> {
        todo!()
    }
}
