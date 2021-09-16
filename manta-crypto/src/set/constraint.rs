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
pub struct ContainmentProofVar<S, C>
where
    S: VerifiedSet + ?Sized,
    C: HasVariable<S::Public> + HasVariable<S::Secret> + ?Sized,
{
    /// Public Input
    public_input: Var<S::Public, C>,

    /// Secret Witness
    secret_witness: Var<S::Secret, C>,
}

impl<S, C> ContainmentProofVar<S, C>
where
    S: VerifiedSet + ?Sized,
    C: HasVariable<S::Public> + HasVariable<S::Secret> + ?Sized,
{
    /// Builds a new [`ContainmentProofVar`] from `public_input` and `secret_witness`.
    #[inline]
    pub fn new(public_input: Var<S::Public, C>, secret_witness: Var<S::Secret, C>) -> Self {
        Self {
            public_input,
            secret_witness,
        }
    }

    /// Asserts that `self` is a valid proof to the fact that `item` is stored in the verified set.
    #[inline]
    pub fn assert_validity<V>(&self, set: &V, item: &V::ItemVar, cs: &mut C)
    where
        C: ConstraintSystem,
        V: VerifiedSetVariable<C, Type = S>,
    {
        set.assert_valid_containment_proof(&self.public_input, &self.secret_witness, item, cs)
    }
}

impl<S, C> Variable<C> for ContainmentProofVar<S, C>
where
    S: VerifiedSet + ?Sized,
    C: HasVariable<S::Public> + HasVariable<S::Secret> + ?Sized,
{
    type Type = ContainmentProof<S>;

    type Mode = ContainmentProofMode<Mode<S::Public, C>, Mode<S::Secret, C>>;

    #[inline]
    fn new(cs: &mut C, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
        match allocation {
            Allocation::Known(this, mode) => Self::new(
                cs.allocate_known(&this.public_input, mode.public),
                cs.allocate_known(&this.secret_witness, mode.secret),
            ),
            Allocation::Unknown(mode) => Self::new(
                unknown::<S::Public, _>(cs, mode.public),
                unknown::<S::Secret, _>(cs, mode.secret),
            ),
        }
    }
}

impl<S, C> HasAllocation<C> for ContainmentProof<S>
where
    S: VerifiedSet + ?Sized,
    C: HasVariable<S::Public> + HasVariable<S::Secret> + ?Sized,
{
    type Variable = ContainmentProofVar<S, C>;
    type Mode = ContainmentProofMode<Mode<S::Public, C>, Mode<S::Secret, C>>;
}

/// Public Input Type for [`VerifiedSetVariable`]
pub type PublicInputType<V, C> = <<V as Variable<C>>::Type as VerifiedSet>::Public;

/// Secret Witness Type for [`VerifiedSetVariable`]
pub type SecretWitnessType<V, C> = <<V as Variable<C>>::Type as VerifiedSet>::Secret;

/// Public Input Variable for [`VerifiedSetVariable`]
pub type PublicInputVar<V, C> = Var<PublicInputType<V, C>, C>;

/// Secret Witness Variable for [`VerifiedSetVariable`]
pub type SecretWitnessVar<V, C> = Var<SecretWitnessType<V, C>, C>;

/// Verified Set Variable
pub trait VerifiedSetVariable<C>: Variable<C>
where
    C: ConstraintSystem
        + HasVariable<PublicInputType<Self, C>>
        + HasVariable<SecretWitnessType<Self, C>>
        + ?Sized,
    Self::Type: VerifiedSet,
{
    /// Item Variable
    type ItemVar: Variable<C, Type = <Self::Type as Set>::Item>;

    /// Asserts that `public_input` and `secret_witness` form a proof to the fact that `item` is
    /// stored in `self`.
    fn assert_valid_containment_proof(
        &self,
        public_input: &PublicInputVar<Self, C>,
        secret_witness: &SecretWitnessVar<Self, C>,
        item: &Self::ItemVar,
        cs: &mut C,
    );
}
