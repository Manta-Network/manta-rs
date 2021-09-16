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
    constraint::{
        reflection::{unknown, HasAllocation, HasVariable, Mode, Var},
        Allocation, AllocationMode, AllocationSystem, ConstraintSystem, Derived, Variable,
    },
    set::{ContainmentProof, Set, VerifiedSet},
};
use core::marker::PhantomData;

/// Containment Proof Allocation Mode Entry
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ContainmentProofModeEntry<PublicMode, SecretMode> {
    /// Public Input Allocation Mode
    pub public: PublicMode,

    /// Secret Witness Allocation Mode
    pub secret: SecretMode,
}

impl<PublicMode, SecretMode> ContainmentProofModeEntry<PublicMode, SecretMode> {
    /// Builds a new [`ContainmentProofModeEntry`] from a `public` mode and a `secret` mode.
    #[inline]
    pub fn new(public: PublicMode, secret: SecretMode) -> Self {
        Self { public, secret }
    }
}

impl<PublicMode, SecretMode> From<Derived> for ContainmentProofModeEntry<PublicMode, SecretMode>
where
    PublicMode: From<Derived>,
    SecretMode: From<Derived>,
{
    #[inline]
    fn from(d: Derived) -> Self {
        Self::new(d.into(), d.into())
    }
}

/// Containment Proof Allocation Mode
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContainmentProofMode<PublicMode, SecretMode>(PhantomData<(PublicMode, SecretMode)>)
where
    PublicMode: AllocationMode,
    SecretMode: AllocationMode;

impl<PublicMode, SecretMode> AllocationMode for ContainmentProofMode<PublicMode, SecretMode>
where
    PublicMode: AllocationMode,
    SecretMode: AllocationMode,
{
    type Known = ContainmentProofModeEntry<PublicMode::Known, SecretMode::Known>;
    type Unknown = ContainmentProofModeEntry<PublicMode::Unknown, SecretMode::Unknown>;
}

/// Containment Proof Variable
pub struct ContainmentProofVar<S, P>
where
    S: VerifiedSet + ?Sized,
    P: HasVariable<S::Public> + HasVariable<S::Secret> + ?Sized,
{
    /// Public Input
    public_input: Var<S::Public, P>,

    /// Secret Witness
    secret_witness: Var<S::Secret, P>,
}

impl<S, P> ContainmentProofVar<S, P>
where
    S: VerifiedSet + ?Sized,
    P: HasVariable<S::Public> + HasVariable<S::Secret> + ?Sized,
{
    /// Builds a new [`ContainmentProofVar`] from `public_input` and `secret_witness`.
    #[inline]
    pub fn new(public_input: Var<S::Public, P>, secret_witness: Var<S::Secret, P>) -> Self {
        Self {
            public_input,
            secret_witness,
        }
    }

    /// Asserts that `self` is a valid proof to the fact that `item` is stored in the verified set.
    #[inline]
    pub fn assert_validity<V>(&self, set: &V, item: &V::ItemVar, ps: &mut P)
    where
        P: ConstraintSystem,
        V: VerifiedSetVariable<P, Type = S>,
    {
        set.assert_valid_containment_proof(&self.public_input, &self.secret_witness, item, ps)
    }
}

impl<S, P> Variable<P> for ContainmentProofVar<S, P>
where
    S: VerifiedSet + ?Sized,
    P: HasVariable<S::Public> + HasVariable<S::Secret> + ?Sized,
{
    type Type = ContainmentProof<S>;

    type Mode = ContainmentProofMode<Mode<S::Public, P>, Mode<S::Secret, P>>;

    #[inline]
    fn new(ps: &mut P, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
        match allocation {
            Allocation::Known(this, mode) => Self::new(
                ps.allocate_known(&this.public_input, mode.public),
                ps.allocate_known(&this.secret_witness, mode.secret),
            ),
            Allocation::Unknown(mode) => Self::new(
                unknown::<S::Public, _>(ps, mode.public),
                unknown::<S::Secret, _>(ps, mode.secret),
            ),
        }
    }
}

impl<S, P> HasAllocation<P> for ContainmentProof<S>
where
    S: VerifiedSet + ?Sized,
    P: HasVariable<S::Public> + HasVariable<S::Secret> + ?Sized,
{
    type Variable = ContainmentProofVar<S, P>;
    type Mode = ContainmentProofMode<Mode<S::Public, P>, Mode<S::Secret, P>>;
}

/// Public Input Type for [`VerifiedSetVariable`]
pub type PublicInputType<V, P> = <<V as Variable<P>>::Type as VerifiedSet>::Public;

/// Secret Witness Type for [`VerifiedSetVariable`]
pub type SecretWitnessType<V, P> = <<V as Variable<P>>::Type as VerifiedSet>::Secret;

/// Public Input Variable for [`VerifiedSetVariable`]
pub type PublicInputVar<V, P> = Var<PublicInputType<V, P>, P>;

/// Secret Witness Variable for [`VerifiedSetVariable`]
pub type SecretWitnessVar<V, P> = Var<SecretWitnessType<V, P>, P>;

/// Verified Set Variable
pub trait VerifiedSetVariable<P>: Variable<P>
where
    P: ConstraintSystem
        + HasVariable<PublicInputType<Self, P>>
        + HasVariable<SecretWitnessType<Self, P>>
        + ?Sized,
    Self::Type: VerifiedSet,
{
    /// Item Variable
    type ItemVar: Variable<P, Type = <Self::Type as Set>::Item>;

    /// Asserts that `public_input` and `secret_witness` form a proof to the fact that `item` is
    /// stored in `self`.
    fn assert_valid_containment_proof(
        &self,
        public_input: &PublicInputVar<Self, P>,
        secret_witness: &SecretWitnessVar<Self, P>,
        item: &Self::ItemVar,
        ps: &mut P,
    );
}
