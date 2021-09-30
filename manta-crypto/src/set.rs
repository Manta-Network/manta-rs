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

//! Sets and Verified Sets

// FIXME: We should probably have something like a "verified set verification handle" which a
//        verified set can give to someone who wants to check a containment proof, since in general
//        we don't actually need access to the set itself, or having access to the set would be be
//        possible in any real implementation.
// FIXME: The `Set::contains` method is not really something we can always implement properly.
// FIXME: Should we just get rid of `Set` and just ensure we can get proofs working?

pub(super) mod prelude {
    #[doc(inline)]
    pub use super::{Set, VerifiedSet};
}

/// Set Trait
pub trait Set {
    /// Item Stored in the [`Set`]
    type Item;

    /// Returns `true` if `item` is stored in `self`.
    fn contains(&self, item: &Self::Item) -> bool;

    /// Tries to insert the `item` into `self`, returning the item back if it was already
    /// contained in `self`.
    fn try_insert(&mut self, item: Self::Item) -> Result<(), Self::Item>;

    /// Inserts the `item` into `self`, returning `true` if the `item` was not contained and
    /// `false` if the item was already contained in `self`.
    #[inline]
    fn insert(&mut self, item: Self::Item) -> bool {
        self.try_insert(item).is_err()
    }
}

/// Containment Proof for a [`VerifiedSet`]
pub struct ContainmentProof<S>
where
    S: VerifiedSet + ?Sized,
{
    /// Public Input
    public_input: S::Public,

    /// Secret Witness
    secret_witness: S::Secret,
}

impl<S> ContainmentProof<S>
where
    S: VerifiedSet + ?Sized,
{
    /// Builds a new [`ContainmentProof`] from `public_input` and `secret_witness`.
    #[inline]
    pub fn new(public_input: S::Public, secret_witness: S::Secret) -> Self {
        Self {
            public_input,
            secret_witness,
        }
    }

    /// Returns [`S::Public`](VerifiedSet::Public) discarding the [`ContainmentProof`].
    #[inline]
    pub fn into_public_input(self) -> S::Public {
        self.public_input
    }

    /// Verifies that the `item` is contained in some [`VerifiedSet`].
    #[inline]
    pub fn verify(&self, set: &S, item: &S::Item) -> bool {
        set.check_containment_proof(&self.public_input, &self.secret_witness, item)
    }

    /// Returns `true` if `self.public_input` is a valid input for the current state of `set`.
    #[inline]
    pub fn check_public_input(&self, set: &S) -> bool {
        set.check_public_input(&self.public_input)
    }
}

/// Verified Set Trait
pub trait VerifiedSet: Set {
    /// Public Input for [`Item`](Set::Item) Containment
    type Public;

    /// Secret Witness for [`Item`](Set::Item) Containment
    type Secret;

    /// Error Generating a [`ContainmentProof`]
    type ContainmentError;

    /// Returns `true` if `public_input` is a valid input for the current state of `self`.
    fn check_public_input(&self, public_input: &Self::Public) -> bool;

    /// Returns `true` if `public_input` and `secret_witness` make up a valid proof that `item`
    /// is stored in `self`.
    fn check_containment_proof(
        &self,
        public_input: &Self::Public,
        secret_witness: &Self::Secret,
        item: &Self::Item,
    ) -> bool;

    /// Generates a proof that the given `item` is stored in `self`.
    fn get_containment_proof(
        &self,
        item: &Self::Item,
    ) -> Result<ContainmentProof<Self>, Self::ContainmentError>;
}

/// Constraint System Gadgets for Sets and Verified Sets
pub mod constraint {
    use super::*;
    use crate::constraint::{
        reflection::{unknown, HasAllocation, HasVariable, Mode, Var},
        Allocation, AllocationMode, AllocationSystem, ConstraintSystem, Derived, Variable,
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

        /// Asserts that `self` is a valid proof to the fact that `item` is stored in the
        /// verified set.
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

        /// Asserts that `public_input` and `secret_witness` form a proof to the fact that `item`
        /// is stored in `self`.
        fn assert_valid_containment_proof(
            &self,
            public_input: &PublicInputVar<Self, C>,
            secret_witness: &SecretWitnessVar<Self, C>,
            item: &Self::ItemVar,
            cs: &mut C,
        );
    }
}
