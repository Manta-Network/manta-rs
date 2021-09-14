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

use alloc::vec::Vec;
use ark_ff::{fields::Field, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar, bits::boolean::Boolean, eq::EqGadget, fields::fp::FpVar, uint8::UInt8,
    ToBytesGadget,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError},
};
use core::borrow::Borrow;
use manta_accounting::{AssetBalance, AssetId};
use manta_crypto::constraint::{
    Alloc, Allocation, AllocationMode, Bool, BooleanSystem, ProofSystem, Public, PublicOrSecret,
    Secret, Variable,
};
use manta_util::{Concat, ConcatAccumulator};

/// Synthesis Result
type SynthesisResult<T> = Result<T, SynthesisError>;

/// Returns an empty variable assignment.
#[inline]
const fn empty<T>() -> SynthesisResult<T> {
    Err(SynthesisError::AssignmentMissing)
}

/// Returns a filled variable assignment.
#[inline]
fn full<T>(t: T) -> impl FnOnce() -> SynthesisResult<T> {
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
                Public => Self::Variable::new_input(ns!(ps.cs, "boolean input"), full(this)),
                Secret => Self::Variable::new_witness(ns!(ps.cs, "boolean witness"), full(this)),
            },
            Allocation::Unknown(mode) => match mode {
                PublicOrSecret::Public => {
                    Self::Variable::new_input(ns!(ps.cs, "boolean input"), empty::<bool>)
                }
                PublicOrSecret::Secret => {
                    Self::Variable::new_witness(ns!(ps.cs, "boolean witness"), empty::<bool>)
                }
            },
        }
        .expect("Variable allocation is not allowed to fail.")
    }
}

/// Prime Field Element
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Fp<F>(F)
where
    F: PrimeField;

impl<F> Variable<ArkProofSystem<F>> for FpVar<F>
where
    F: PrimeField,
{
    type Mode = ArkAllocationMode;
    type Type = Fp<F>;
}

impl<F> Alloc<ArkProofSystem<F>> for Fp<F>
where
    F: PrimeField,
{
    type Mode = ArkAllocationMode;

    type Variable = FpVar<F>;

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
                Constant => {
                    Self::Variable::new_constant(ns!(ps.cs, "prime field constant"), this.0)
                }
                Public => Self::Variable::new_input(ns!(ps.cs, "prime field input"), full(this.0)),
                Secret => {
                    Self::Variable::new_witness(ns!(ps.cs, "prime field witness"), full(this.0))
                }
            },
            Allocation::Unknown(mode) => match mode {
                PublicOrSecret::Public => {
                    Self::Variable::new_input(ns!(ps.cs, "prime field input"), empty::<F>)
                }
                PublicOrSecret::Secret => {
                    Self::Variable::new_witness(ns!(ps.cs, "prime field witness"), empty::<F>)
                }
            },
        }
        .expect("Variable allocation is not allowed to fail.")
    }
}

/// Byte Array Variable
#[derive(derivative::Derivative)]
#[derivative(Clone, Debug)]
pub struct ByteArrayVar<F, const N: usize>(Vec<UInt8<F>>)
where
    F: Field;

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
        accumulator.extend(&self.0)
    }
}

impl<F, const N: usize> Variable<ArkProofSystem<F>> for ByteArrayVar<F, N>
where
    F: Field,
{
    type Mode = ArkAllocationMode;
    type Type = [u8; N];
}

impl<F, const N: usize> Alloc<ArkProofSystem<F>> for [u8; N]
where
    F: Field,
{
    type Mode = ArkAllocationMode;

    type Variable = ByteArrayVar<F, N>;

    #[inline]
    fn variable<'t>(
        ps: &mut ArkProofSystem<F>,
        allocation: impl Into<Allocation<'t, Self, ArkProofSystem<F>>>,
    ) -> Self::Variable
    where
        Self: 't,
    {
        todo!()
    }
}

/// Asset Id Variable
#[derive(derivative::Derivative)]
#[derivative(Clone, Debug)]
pub struct AssetIdVar<F>(FpVar<F>)
where
    F: PrimeField;

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
        accumulator.extend(&self.0.to_bytes().expect("This is not allowed to fail."))
    }
}

impl<F> Variable<ArkProofSystem<F>> for AssetIdVar<F>
where
    F: PrimeField,
{
    type Mode = PublicOrSecret;
    type Type = AssetId;
}

impl<F> Alloc<ArkProofSystem<F>> for AssetId
where
    F: PrimeField,
{
    type Mode = PublicOrSecret;

    type Variable = AssetIdVar<F>;

    #[inline]
    fn variable<'t>(
        ps: &mut ArkProofSystem<F>,
        allocation: impl Into<Allocation<'t, Self, ArkProofSystem<F>>>,
    ) -> Self::Variable
    where
        Self: 't,
    {
        AssetIdVar(match allocation.into() {
            Allocation::Known(this, mode) => Fp(F::from(this.0)).as_known(ps, mode),
            Allocation::Unknown(mode) => Fp::unknown(ps, mode),
        })
    }
}

/// Asset Balance Variable
#[derive(derivative::Derivative)]
#[derivative(Clone, Debug)]
pub struct AssetBalanceVar<F>(FpVar<F>)
where
    F: PrimeField;

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
        accumulator.extend(&self.0.to_bytes().expect("This is not allowed to fail."))
    }
}

impl<F> Variable<ArkProofSystem<F>> for AssetBalanceVar<F>
where
    F: PrimeField,
{
    type Mode = PublicOrSecret;
    type Type = AssetBalance;
}

impl<F> Alloc<ArkProofSystem<F>> for AssetBalance
where
    F: PrimeField,
{
    type Mode = PublicOrSecret;

    type Variable = AssetBalanceVar<F>;

    #[inline]
    fn variable<'t>(
        ps: &mut ArkProofSystem<F>,
        allocation: impl Into<Allocation<'t, Self, ArkProofSystem<F>>>,
    ) -> Self::Variable
    where
        Self: 't,
    {
        AssetBalanceVar(match allocation.into() {
            Allocation::Known(this, mode) => Fp(F::from(this.0)).as_known(ps, mode),
            Allocation::Unknown(mode) => Fp::unknown(ps, mode),
        })
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
