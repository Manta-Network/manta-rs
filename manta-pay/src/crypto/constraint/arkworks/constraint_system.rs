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

use alloc::{vec, vec::Vec};
use ark_ff::{fields::Field, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar, bits::boolean::Boolean, eq::EqGadget, fields::fp::FpVar, uint8::UInt8, R1CSVar,
};
use ark_relations::{ns, r1cs as ark_r1cs};
use core::{borrow::Borrow, ops::AddAssign};
use manta_accounting::{AssetBalance, AssetId};
use manta_crypto::constraint::{
    measure::Measure, reflection::HasAllocation, types::Bool, Allocation, AllocationMode,
    ConstraintSystem, Equal, Public, PublicOrSecret, Secret, Variable, VariableSource,
};
use manta_util::{Concat, ConcatAccumulator};

/// Synthesis Result
pub type SynthesisResult<T = ()> = Result<T, ark_r1cs::SynthesisError>;

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
    Err(ark_r1cs::SynthesisError::AssignmentMissing)
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

/// Arkworks Constraint System
pub struct ArkConstraintSystem<F>
where
    F: Field,
{
    /// Constraint System
    pub(crate) cs: ark_r1cs::ConstraintSystemRef<F>,
}

impl<F> ArkConstraintSystem<F>
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

impl<F> ConstraintSystem for ArkConstraintSystem<F>
where
    F: Field,
{
    type Bool = Boolean<F>;

    #[inline]
    fn assert(&mut self, b: Bool<Self>) {
        b.enforce_equal(&Boolean::TRUE)
            .expect("This should never fail.");
    }
}

impl<F> Measure<PublicOrSecret> for ArkConstraintSystem<F>
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

impl<F> Variable<ArkConstraintSystem<F>> for Boolean<F>
where
    F: Field,
{
    type Type = bool;

    type Mode = ArkAllocationMode;

    #[inline]
    fn new(
        cs: &mut ArkConstraintSystem<F>,
        allocation: Allocation<Self::Type, Self::Mode>,
    ) -> Self {
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

impl<F> HasAllocation<ArkConstraintSystem<F>> for bool
where
    F: Field,
{
    type Variable = Boolean<F>;
    type Mode = ArkAllocationMode;
}

impl<F> Equal<ArkConstraintSystem<F>> for Boolean<F>
where
    F: Field,
{
    #[inline]
    fn eq(cs: &mut ArkConstraintSystem<F>, lhs: &Self, rhs: &Self) -> Boolean<F> {
        let _ = cs;
        lhs.is_eq(rhs)
            .expect("Equality checking is not allowed to fail.")
    }
}

/// Prime Field Element
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Fp<F>(F)
where
    F: PrimeField;

impl<F> Variable<ArkConstraintSystem<F>> for FpVar<F>
where
    F: PrimeField,
{
    type Type = Fp<F>;

    type Mode = ArkAllocationMode;

    #[inline]
    fn new(
        cs: &mut ArkConstraintSystem<F>,
        allocation: Allocation<Self::Type, Self::Mode>,
    ) -> Self {
        match allocation {
            Allocation::Known(this, ArkAllocationMode::Constant) => {
                Self::new_constant(ns!(cs.cs, "prime field constant"), this.0)
            }
            Allocation::Known(this, ArkAllocationMode::Public) => {
                Self::new_input(ns!(cs.cs, "prime field input"), full(this.0))
            }
            Allocation::Known(this, ArkAllocationMode::Secret) => {
                Self::new_witness(ns!(cs.cs, "prime field witness"), full(this.0))
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

impl<F> HasAllocation<ArkConstraintSystem<F>> for Fp<F>
where
    F: PrimeField,
{
    type Variable = FpVar<F>;
    type Mode = ArkAllocationMode;
}

/// Byte Array Variable
#[derive(derivative::Derivative)]
#[derivative(Clone, Debug)]
pub struct ByteArrayVar<F, const N: usize>(Vec<UInt8<F>>)
where
    F: Field;

impl<F, const N: usize> ByteArrayVar<F, N>
where
    F: Field,
{
    /// Returns an reference to the internal arkworks constriant system.
    #[inline]
    pub(crate) fn constraint_system_ref(&self) -> ark_r1cs::ConstraintSystemRef<F> {
        self.0.cs()
    }

    /// Allocates a new byte vector according to the `allocation` entry.
    #[inline]
    pub(crate) fn allocate(
        cs: &ark_r1cs::ConstraintSystemRef<F>,
        allocation: Allocation<[u8; N], PublicOrSecret>,
    ) -> Self
    where
        F: PrimeField,
    {
        Self(
            match allocation {
                Allocation::Known(this, PublicOrSecret::Public) => {
                    UInt8::new_input_vec(ns!(cs, "byte array public input"), this)
                }
                Allocation::Known(this, PublicOrSecret::Secret) => {
                    UInt8::new_witness_vec(ns!(cs, "byte array secret witness"), this)
                }
                Allocation::Unknown(PublicOrSecret::Public) => {
                    UInt8::new_input_vec(ns!(cs, "byte array public input"), &[0; N])
                }
                Allocation::Unknown(PublicOrSecret::Secret) => {
                    UInt8::new_witness_vec(ns!(cs, "byte array secret witness"), &vec![None; N])
                }
            }
            .expect("Variable allocation is not allowed to fail."),
        )
    }
}

impl<F, const N: usize> AsRef<[UInt8<F>]> for ByteArrayVar<F, N>
where
    F: Field,
{
    #[inline]
    fn as_ref(&self) -> &[UInt8<F>] {
        &self.0
    }
}

impl<F, const N: usize> Borrow<[UInt8<F>]> for ByteArrayVar<F, N>
where
    F: Field,
{
    #[inline]
    fn borrow(&self) -> &[UInt8<F>] {
        &self.0
    }
}

impl<F, const N: usize> Concat for ByteArrayVar<F, N>
where
    F: Field,
{
    type Item = UInt8<F>;

    #[inline]
    fn concat<A>(&self, accumulator: &mut A)
    where
        A: ConcatAccumulator<Self::Item> + ?Sized,
    {
        accumulator.extend(&self.0);
    }
}

impl<F, const N: usize> Variable<ArkConstraintSystem<F>> for ByteArrayVar<F, N>
where
    F: PrimeField,
{
    type Type = [u8; N];

    type Mode = PublicOrSecret;

    #[inline]
    fn new(
        cs: &mut ArkConstraintSystem<F>,
        allocation: Allocation<Self::Type, Self::Mode>,
    ) -> Self {
        Self::allocate(&cs.cs, allocation)
    }
}

impl<F, const N: usize> HasAllocation<ArkConstraintSystem<F>> for [u8; N]
where
    F: PrimeField,
{
    type Variable = ByteArrayVar<F, N>;
    type Mode = PublicOrSecret;
}

/// Asset Id Variable
#[derive(derivative::Derivative)]
#[derivative(Clone, Debug)]
pub struct AssetIdVar<F>
where
    F: PrimeField,
{
    /// Field Point
    field_point: FpVar<F>,

    /// Byte Array
    bytes: ByteArrayVar<F, { AssetId::SIZE }>,
}

impl<F> AssetIdVar<F>
where
    F: PrimeField,
{
    /// Builds a new [`AssetIdVar`] from `field_point` and `bytes`.
    #[inline]
    fn new(field_point: FpVar<F>, bytes: ByteArrayVar<F, { AssetId::SIZE }>) -> Self {
        Self { field_point, bytes }
    }
}

impl<F> Concat for AssetIdVar<F>
where
    F: PrimeField,
{
    type Item = UInt8<F>;

    #[inline]
    fn concat<A>(&self, accumulator: &mut A)
    where
        A: ConcatAccumulator<Self::Item> + ?Sized,
    {
        self.bytes.concat(accumulator);
    }
}

impl<F> Variable<ArkConstraintSystem<F>> for AssetIdVar<F>
where
    F: PrimeField,
{
    type Type = AssetId;

    type Mode = PublicOrSecret;

    #[inline]
    fn new(
        cs: &mut ArkConstraintSystem<F>,
        allocation: Allocation<Self::Type, Self::Mode>,
    ) -> Self {
        match allocation {
            Allocation::Known(this, mode) => Self::new(
                Fp(F::from(this.0)).as_known(cs, mode),
                this.into_bytes().as_known(cs, mode),
            ),
            Allocation::Unknown(mode) => Self::new(
                Fp::as_unknown(cs, mode),
                <[u8; AssetId::SIZE]>::as_unknown(cs, mode),
            ),
        }
    }
}

impl<F> HasAllocation<ArkConstraintSystem<F>> for AssetId
where
    F: PrimeField,
{
    type Variable = AssetIdVar<F>;
    type Mode = PublicOrSecret;
}

impl<F> Equal<ArkConstraintSystem<F>> for AssetIdVar<F>
where
    F: PrimeField,
{
    #[inline]
    fn eq(cs: &mut ArkConstraintSystem<F>, lhs: &Self, rhs: &Self) -> Boolean<F> {
        // TODO: Is `field_point` or `bytes` faster?
        let _ = cs;
        lhs.field_point
            .is_eq(&rhs.field_point)
            .expect("Equality checking is not allowed to fail.")
    }
}

/// Asset Balance Variable
#[derive(derivative::Derivative)]
#[derivative(Clone, Debug)]
pub struct AssetBalanceVar<F>
where
    F: PrimeField,
{
    /// Field Point
    field_point: FpVar<F>,

    /// Byte Array
    bytes: ByteArrayVar<F, { AssetBalance::SIZE }>,
}

impl<F> AssetBalanceVar<F>
where
    F: PrimeField,
{
    /// Builds a new [`AssetBalanceVar`] from `field_point` and `bytes`.
    #[inline]
    fn new(field_point: FpVar<F>, bytes: ByteArrayVar<F, { AssetBalance::SIZE }>) -> Self {
        Self { field_point, bytes }
    }
}

impl<F> Concat for AssetBalanceVar<F>
where
    F: PrimeField,
{
    type Item = UInt8<F>;

    #[inline]
    fn concat<A>(&self, accumulator: &mut A)
    where
        A: ConcatAccumulator<Self::Item> + ?Sized,
    {
        self.bytes.concat(accumulator);
    }
}

impl<F> Variable<ArkConstraintSystem<F>> for AssetBalanceVar<F>
where
    F: PrimeField,
{
    type Type = AssetBalance;

    type Mode = PublicOrSecret;

    #[inline]
    fn new(
        cs: &mut ArkConstraintSystem<F>,
        allocation: Allocation<Self::Type, Self::Mode>,
    ) -> Self {
        match allocation {
            Allocation::Known(this, mode) => Self::new(
                Fp(F::from(this.0)).as_known(cs, mode),
                this.into_bytes().as_known(cs, mode),
            ),
            Allocation::Unknown(mode) => Self::new(
                Fp::as_unknown(cs, mode),
                <[u8; AssetBalance::SIZE]>::as_unknown(cs, mode),
            ),
        }
    }
}

impl<F> HasAllocation<ArkConstraintSystem<F>> for AssetBalance
where
    F: PrimeField,
{
    type Variable = AssetBalanceVar<F>;
    type Mode = PublicOrSecret;
}

impl<F> Equal<ArkConstraintSystem<F>> for AssetBalanceVar<F>
where
    F: PrimeField,
{
    #[inline]
    fn eq(cs: &mut ArkConstraintSystem<F>, lhs: &Self, rhs: &Self) -> Boolean<F> {
        // TODO: Is `field_point` or `bytes` faster?
        let _ = cs;
        lhs.field_point
            .is_eq(&rhs.field_point)
            .expect("Equality checking is not allowed to fail.")
    }
}

impl<F> AddAssign for AssetBalanceVar<F>
where
    F: PrimeField,
{
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        self.field_point += rhs.field_point;
    }
}
