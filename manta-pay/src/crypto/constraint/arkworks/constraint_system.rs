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

use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar, bits::boolean::Boolean, eq::EqGadget, select::CondSelectGadget,
};
use ark_relations::{ns, r1cs as ark_r1cs};
use manta_crypto::constraint::{
    measure::Measure, Add, ConditionalSelect, Constant, ConstraintSystem, Equal, Public, Secret,
    Variable,
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

/// Arkworks Rank-1 Constraint System
pub struct R1CS<F>
where
    F: PrimeField,
{
    /// Constraint System
    pub(crate) cs: ark_r1cs::ConstraintSystemRef<F>,
}

impl<F> R1CS<F>
where
    F: PrimeField,
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
    F: PrimeField,
{
    type Bool = Boolean<F>;

    #[inline]
    fn assert(&mut self, b: Self::Bool) {
        b.enforce_equal(&Boolean::TRUE)
            .expect("This should never fail.");
    }
}

impl<F> Measure for R1CS<F>
where
    F: PrimeField,
{
    #[inline]
    fn constraint_count(&self) -> usize {
        self.cs.num_constraints()
    }

    #[inline]
    fn public_variable_count(&self) -> Option<usize> {
        Some(self.cs.num_instance_variables())
    }

    #[inline]
    fn secret_variable_count(&self) -> Option<usize> {
        Some(self.cs.num_witness_variables())
    }
}

impl<F> Constant<R1CS<F>> for Boolean<F>
where
    F: PrimeField,
{
    type Type = bool;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
        AllocVar::new_constant(ns!(compiler.cs, "boolean constant"), this)
            .expect("Variable allocation is not allowed to fail.")
    }
}

impl<F> Variable<Public, R1CS<F>> for Boolean<F>
where
    F: PrimeField,
{
    type Type = bool;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
        Self::new_input(ns!(compiler.cs, "boolean public input"), full(this))
            .expect("Variable allocation is not allowed to fail.")
    }

    #[inline]
    fn new_unknown(compiler: &mut R1CS<F>) -> Self {
        Self::new_input(ns!(compiler.cs, "boolean public input"), empty::<bool>)
            .expect("Variable allocation is not allowed to fail.")
    }
}

impl<F> Variable<Secret, R1CS<F>> for Boolean<F>
where
    F: PrimeField,
{
    type Type = bool;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
        Self::new_witness(ns!(compiler.cs, "boolean secret witness"), full(this))
            .expect("Variable allocation is not allowed to fail.")
    }

    #[inline]
    fn new_unknown(compiler: &mut R1CS<F>) -> Self {
        Self::new_witness(ns!(compiler.cs, "boolean secret witness"), empty::<bool>)
            .expect("Variable allocation is not allowed to fail.")
    }
}

impl<F> Equal<R1CS<F>> for Boolean<F>
where
    F: PrimeField,
{
    #[inline]
    fn eq(lhs: &Self, rhs: &Self, compiler: &mut R1CS<F>) -> Boolean<F> {
        let _ = compiler;
        lhs.is_eq(rhs)
            .expect("Equality checking is not allowed to fail.")
    }
}

impl<F> Constant<R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    type Type = F;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
        AllocVar::new_constant(ns!(compiler.cs, "field constant"), this)
            .expect("Variable allocation is not allowed to fail.")
    }
}

impl<F> Variable<Public, R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    type Type = F;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
        Self::new_input(ns!(compiler.cs, "field public input"), full(this))
            .expect("Variable allocation is not allowed to fail.")
    }

    #[inline]
    fn new_unknown(compiler: &mut R1CS<F>) -> Self {
        Self::new_input(ns!(compiler.cs, "field public input"), empty::<F>)
            .expect("Variable allocation is not allowed to fail.")
    }
}

impl<F> Variable<Secret, R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    type Type = F;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
        Self::new_witness(ns!(compiler.cs, "field secret witness"), full(this))
            .expect("Variable allocation is not allowed to fail.")
    }

    #[inline]
    fn new_unknown(compiler: &mut R1CS<F>) -> Self {
        Self::new_witness(ns!(compiler.cs, "field secret witness"), empty::<F>)
            .expect("Variable allocation is not allowed to fail.")
    }
}

impl<F> Equal<R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    #[inline]
    fn eq(lhs: &Self, rhs: &Self, compiler: &mut R1CS<F>) -> Boolean<F> {
        let _ = compiler;
        lhs.is_eq(rhs)
            .expect("Equality checking is not allowed to fail.")
    }
}

impl<F> ConditionalSelect<R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    #[inline]
    fn select(bit: &Boolean<F>, lhs: &Self, rhs: &Self, compiler: &mut R1CS<F>) -> Self {
        let _ = compiler;
        Self::conditionally_select(bit, lhs, rhs)
            .expect("Conditionally selecting from two values is not allowed to fail.")
    }
}

impl<F> Add<R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    #[inline]
    fn add(lhs: Self, rhs: Self, compiler: &mut R1CS<F>) -> Self {
        let _ = compiler;
        lhs + rhs
    }
}
