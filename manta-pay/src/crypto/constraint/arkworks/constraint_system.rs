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

//! Arkworks Constraint System Implementation

use ark_ff::{fields::Field, PrimeField};
use ark_r1cs_std::{alloc::AllocVar, bits::boolean::Boolean, eq::EqGadget};
use ark_relations::{ns, r1cs as ark_r1cs};
use manta_crypto::constraint::{
    measure::Measure, Add, Allocation, AllocationMode, ConstraintSystem, Equal, Public,
    PublicOrSecret, Secret, Variable,
};

pub use ark_r1cs::SynthesisError;
pub use ark_r1cs_std::fields::fp::FpVar;

/// Synthesis Result
pub type SynthesisResult<T = ()> = Result<T, SynthesisError>;

/// Returns an empty variable assignment for setup mode.
///
/// # Warning
///
/// This does not work for all variable assignments! For some assignemnts, the variable inherits
/// some structure from its input even though the input itself will not form part of the proving
/// key and verifying key that we produce after compiling the constraint system. For those cases,
/// some mocking is required and this function can not be used directly.
#[inline]
pub fn empty<T>() -> SynthesisResult<T> {
    Err(SynthesisError::AssignmentMissing)
}

/// Returns a filled variable assignment.
#[inline]
pub fn full<T>(t: T) -> impl FnOnce() -> SynthesisResult<T> {
    move || Ok(t)
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

impl From<Public> for ArkAllocationMode {
    #[inline]
    fn from(p: Public) -> Self {
        let _ = p;
        Self::Public
    }
}

impl From<Secret> for ArkAllocationMode {
    #[inline]
    fn from(s: Secret) -> Self {
        let _ = s;
        Self::Secret
    }
}

impl From<PublicOrSecret> for ArkAllocationMode {
    #[inline]
    fn from(pos: PublicOrSecret) -> Self {
        match pos {
            PublicOrSecret::Public => Self::Public,
            PublicOrSecret::Secret => Self::Secret,
        }
    }
}

/// Arkworks Rank-1 Constraint System
pub struct R1CS<F>
where
    F: Field,
{
    /// Constraint System
    pub(crate) cs: ark_r1cs::ConstraintSystemRef<F>,
}

impl<F> R1CS<F>
where
    F: Field,
{
    /// Constructs a new constraint system which is ready for unknown variables.
    #[inline]
    pub fn for_unknown() -> Self {
        // FIXME: This might not be the right setup for all proof systems.
        let cs = ark_r1cs::ConstraintSystem::new_ref();
        cs.set_optimization_goal(ark_r1cs::OptimizationGoal::Constraints);
        cs.set_mode(ark_r1cs::SynthesisMode::Setup);
        Self { cs }
    }

    /// Constructs a new constraint system which is ready for known variables.
    #[inline]
    pub fn for_known() -> Self {
        // FIXME: This might not be the right setup for all proof systems.
        let cs = ark_r1cs::ConstraintSystem::new_ref();
        cs.set_optimization_goal(ark_r1cs::OptimizationGoal::Constraints);
        Self { cs }
    }
}

impl<F> ConstraintSystem for R1CS<F>
where
    F: Field,
{
    type Bool = Boolean<F>;

    #[inline]
    fn assert(&mut self, b: Self::Bool) {
        b.enforce_equal(&Boolean::TRUE)
            .expect("This should never fail.");
    }
}

impl<F> Measure<PublicOrSecret> for R1CS<F>
where
    F: Field,
{
    #[inline]
    fn constraint_count(&self) -> usize {
        self.cs.num_constraints()
    }

    #[inline]
    fn variable_count(&self, mode: PublicOrSecret) -> usize {
        match mode {
            PublicOrSecret::Public => self.cs.num_instance_variables(),
            PublicOrSecret::Secret => self.cs.num_witness_variables(),
        }
    }
}

impl<F> Variable<R1CS<F>> for Boolean<F>
where
    F: Field,
{
    type Type = bool;

    type Mode = ArkAllocationMode;

    #[inline]
    fn new(cs: &mut R1CS<F>, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
        match allocation {
            Allocation::Known(this, ArkAllocationMode::Constant) => {
                Self::new_constant(ns!(cs.cs, "boolean constant"), this)
            }
            Allocation::Known(this, ArkAllocationMode::Public) => {
                Self::new_input(ns!(cs.cs, "boolean input"), full(this))
            }
            Allocation::Known(this, ArkAllocationMode::Secret) => {
                Self::new_witness(ns!(cs.cs, "boolean witness"), full(this))
            }
            Allocation::Unknown(PublicOrSecret::Public) => {
                Self::new_input(ns!(cs.cs, "boolean input"), empty::<bool>)
            }
            Allocation::Unknown(PublicOrSecret::Secret) => {
                Self::new_witness(ns!(cs.cs, "boolean witness"), empty::<bool>)
            }
        }
        .expect("Variable allocation is not allowed to fail.")
    }
}

impl<F> Equal<R1CS<F>> for Boolean<F>
where
    F: Field,
{
    #[inline]
    fn eq(cs: &mut R1CS<F>, lhs: &Self, rhs: &Self) -> Boolean<F> {
        let _ = cs;
        lhs.is_eq(rhs)
            .expect("Equality checking is not allowed to fail.")
    }
}

impl<F> Variable<R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    type Type = F;

    type Mode = ArkAllocationMode;

    #[inline]
    fn new(cs: &mut R1CS<F>, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
        match allocation {
            Allocation::Known(this, ArkAllocationMode::Constant) => {
                Self::new_constant(ns!(cs.cs, "prime field constant"), this)
            }
            Allocation::Known(this, ArkAllocationMode::Public) => {
                Self::new_input(ns!(cs.cs, "prime field input"), full(this))
            }
            Allocation::Known(this, ArkAllocationMode::Secret) => {
                Self::new_witness(ns!(cs.cs, "prime field witness"), full(this))
            }
            Allocation::Unknown(PublicOrSecret::Public) => {
                Self::new_input(ns!(cs.cs, "prime field input"), empty::<F>)
            }
            Allocation::Unknown(PublicOrSecret::Secret) => {
                Self::new_witness(ns!(cs.cs, "prime field witness"), empty::<F>)
            }
        }
        .expect("Variable allocation is not allowed to fail.")
    }
}

impl<F> Equal<R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    #[inline]
    fn eq(cs: &mut R1CS<F>, lhs: &Self, rhs: &Self) -> Boolean<F> {
        let _ = cs;
        lhs.is_eq(rhs)
            .expect("Equality checking is not allowed to fail.")
    }
}

impl<F> Add<R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    #[inline]
    fn add(cs: &mut R1CS<F>, lhs: Self, rhs: Self) -> Self {
        let _ = cs;
        lhs + rhs
    }
}
