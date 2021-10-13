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

//! Verified Sets

// TODO: Should `insert` or `insert_non_proving` be the default?

/// Verified Set Verifier
pub trait Verifier {
    /// Item Type
    type Item: ?Sized;

    /// Public Part of the [`Item`](Self::Item) Membership Proof
    type Public;

    /// Secret Part of the [`Item`](Self::Item) Membership Proof
    type Secret;

    /// Verifies that `public` and `secret` form a proof to the fact that `item` is contained in
    /// the verified set which returned `self`.
    fn verify(&self, public: &Self::Public, secret: &Self::Secret, item: &Self::Item) -> bool;
}

/// Verified Set
pub trait VerifiedSet {
    /// Item Type
    type Item: ?Sized;

    /// Public Part of the [`Item`](Self::Item) Membership Proof
    type Public;

    /// Secret Part of the [`Item`](Self::Item) Membership Proof
    type Secret;

    /// [`MembershipProof`] Verifier Type
    type Verifier: Verifier<Item = Self::Item, Public = Self::Public, Secret = Self::Secret>;

    /// Returns the internal verifier for `self`.
    fn verifier(&self) -> &Self::Verifier;

    /// Returns the maximum number of elements that can be stored in `self`.
    fn capacity(&self) -> usize;

    /// Returns the number of elements that are contained in `self`.
    fn len(&self) -> usize;

    /// Returns `true` if `self` contains no elements.
    #[inline]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Inserts `item` into `self` with the guarantee that `self` can later return a valid proof of
    /// membership for `item` with a call to [`get_membership_proof`](Self::get_membership_proof).
    fn insert_provable(&mut self, item: &Self::Item) -> bool;

    /// Inserts `item` into `self` without the guarantee that `self` with be able to return a proof
    /// of membership for `item`.
    ///
    /// # Implementation Note
    ///
    /// By default, this method uses [`insert_provable`](Self::insert_provable) to store `item`
    /// in `self`.
    #[inline]
    fn insert(&mut self, item: &Self::Item) -> bool {
        self.insert_provable(item)
    }

    /// Returns `true` if `public` is a valid input for the current state of `self`.
    fn check_public(&self, public: &Self::Public) -> bool;

    /// Generates a proof that the given `item` is stored in `self`.
    fn get_membership_proof(&self, item: &Self::Item) -> Option<MembershipProof<Self::Verifier>>;

    /// Returns `true` if `item` is stored in `self`.
    ///
    /// # Implementation Note
    ///
    /// This method must at least return `true` for `item` whenever a valid proof of membership
    /// exists. It may return `true` in other cases when `self` knows that it has `item` stored but
    /// cannot return a proof for it.
    #[inline]
    fn contains(&self, item: &Self::Item) -> bool {
        self.get_membership_proof(item).is_some()
    }
}

impl<S> Verifier for S
where
    S: VerifiedSet,
{
    type Item = S::Item;

    type Public = S::Public;

    type Secret = S::Secret;

    #[inline]
    fn verify(&self, public: &Self::Public, secret: &Self::Secret, item: &Self::Item) -> bool {
        self.check_public(public) && self.verifier().verify(public, secret, item)
    }
}

/// Membership Proof for a [`Verifier`]
pub struct MembershipProof<V>
where
    V: Verifier + ?Sized,
{
    /// Public Proof Part
    public: V::Public,

    /// Secret Proof Part
    secret: V::Secret,
}

impl<V> MembershipProof<V>
where
    V: Verifier + ?Sized,
{
    /// Builds a new [`MembershipProof`] from `public` and `secret`.
    #[inline]
    pub fn new(public: V::Public, secret: V::Secret) -> Self {
        Self { public, secret }
    }

    /// Returns [`V::Public`](Verifier::Public) discarding the [`MembershipProof`].
    #[inline]
    pub fn into_public(self) -> V::Public {
        self.public
    }

    /// Returns `true` if the public part of `self` is a valid input for the current state of `set`.
    #[inline]
    pub fn check_public<S>(&self, set: &S) -> bool
    where
        S: VerifiedSet<Item = V::Item, Public = V::Public, Secret = V::Secret, Verifier = V>,
    {
        set.check_public(&self.public)
    }

    /// Verifies that the `item` is contained in some [`VerifiedSet`].
    #[inline]
    pub fn verify(&self, verifier: &V, item: &V::Item) -> bool {
        verifier.verify(&self.public, &self.secret, item)
    }
}

/// Constraint System Gadgets for Sets and Verified Sets
pub mod constraint {
    use super::*;
    use crate::constraint::{
        reflection::{unknown, HasAllocation, HasVariable, Mode, Var},
        Allocation, AllocationMode, AllocationSystem, ConstraintSystem, Derived, Variable,
    };
    use core::marker::PhantomData;

    /// Membership Proof Allocation Mode Entry
    #[derive(derivative::Derivative)]
    #[derivative(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
    pub struct MembershipProofModeEntry<PublicMode, SecretMode> {
        /// Public Allocation Mode
        pub public: PublicMode,

        /// Secret Allocation Mode
        pub secret: SecretMode,
    }

    impl<PublicMode, SecretMode> MembershipProofModeEntry<PublicMode, SecretMode> {
        /// Builds a new [`MembershipProofModeEntry`] from a `public` mode and a `secret` mode.
        #[inline]
        pub fn new(public: PublicMode, secret: SecretMode) -> Self {
            Self { public, secret }
        }
    }

    impl<PublicMode, SecretMode> From<Derived> for MembershipProofModeEntry<PublicMode, SecretMode>
    where
        PublicMode: From<Derived>,
        SecretMode: From<Derived>,
    {
        #[inline]
        fn from(d: Derived) -> Self {
            Self::new(d.into(), d.into())
        }
    }

    /// Membership Proof Allocation Mode
    #[derive(derivative::Derivative)]
    #[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct MembershipProofMode<PublicMode, SecretMode>(PhantomData<(PublicMode, SecretMode)>)
    where
        PublicMode: AllocationMode,
        SecretMode: AllocationMode;

    impl<PublicMode, SecretMode> AllocationMode for MembershipProofMode<PublicMode, SecretMode>
    where
        PublicMode: AllocationMode,
        SecretMode: AllocationMode,
    {
        type Known = MembershipProofModeEntry<PublicMode::Known, SecretMode::Known>;
        type Unknown = MembershipProofModeEntry<PublicMode::Unknown, SecretMode::Unknown>;
    }

    /// Membership Proof Variable
    pub struct MembershipProofVar<V, C>
    where
        V: Verifier + ?Sized,
        C: HasVariable<V::Public> + HasVariable<V::Secret> + ?Sized,
    {
        /// Public Proof Part
        public: Var<V::Public, C>,

        /// Secret Proof Part
        secret: Var<V::Secret, C>,
    }

    impl<V, C> MembershipProofVar<V, C>
    where
        V: Verifier + ?Sized,
        C: HasVariable<V::Public> + HasVariable<V::Secret> + ?Sized,
    {
        /// Builds a new [`MembershipProofVar`] from `public` and `secret`.
        #[inline]
        pub fn new(public: Var<V::Public, C>, secret: Var<V::Secret, C>) -> Self {
            Self { public, secret }
        }

        /// Asserts that `self` is a valid proof to the fact that `item` is stored in the
        /// verified set.
        #[inline]
        pub fn assert_validity<VV>(&self, verifier: &VV, item: &VV::ItemVar, cs: &mut C)
        where
            C: ConstraintSystem,
            VV: VerifierVariable<C, Type = V>,
        {
            verifier.assert_valid_membership_proof(&self.public, &self.secret, item, cs)
        }
    }

    impl<V, C> Variable<C> for MembershipProofVar<V, C>
    where
        V: Verifier + ?Sized,
        C: HasVariable<V::Public> + HasVariable<V::Secret> + ?Sized,
    {
        type Type = MembershipProof<V>;

        type Mode = MembershipProofMode<Mode<V::Public, C>, Mode<V::Secret, C>>;

        #[inline]
        fn new(cs: &mut C, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
            match allocation {
                Allocation::Known(this, mode) => Self::new(
                    cs.allocate_known(&this.public, mode.public),
                    cs.allocate_known(&this.secret, mode.secret),
                ),
                Allocation::Unknown(mode) => Self::new(
                    unknown::<V::Public, _>(cs, mode.public),
                    unknown::<V::Secret, _>(cs, mode.secret),
                ),
            }
        }
    }

    impl<V, C> HasAllocation<C> for MembershipProof<V>
    where
        V: Verifier + ?Sized,
        C: HasVariable<V::Public> + HasVariable<V::Secret> + ?Sized,
    {
        type Variable = MembershipProofVar<V, C>;
        type Mode = MembershipProofMode<Mode<V::Public, C>, Mode<V::Secret, C>>;
    }

    /// Public Proof Part for [`VerifierVariable`]
    pub type PublicType<V, C> = <<V as Variable<C>>::Type as Verifier>::Public;

    /// Secret Proof Part for [`VerifierVariable`]
    pub type SecretType<V, C> = <<V as Variable<C>>::Type as Verifier>::Secret;

    /// Public Proof Part Variable for [`VerifierVariable`]
    pub type PublicVar<V, C> = Var<PublicType<V, C>, C>;

    /// Secret Proof Part Variable for [`VerifierVariable`]
    pub type SecretVar<V, C> = Var<SecretType<V, C>, C>;

    /// Verified Set Variable
    pub trait VerifierVariable<C>: Variable<C>
    where
        C: ConstraintSystem
            + HasVariable<PublicType<Self, C>>
            + HasVariable<SecretType<Self, C>>
            + ?Sized,
        Self::Type: Verifier,
    {
        /// Item Variable
        type ItemVar: Variable<C, Type = <Self::Type as Verifier>::Item>;

        /// Asserts that `public` and `secret` form a proof to the fact that `item` is stored in
        /// `self`.
        fn assert_valid_membership_proof(
            &self,
            public: &PublicVar<Self, C>,
            secret: &SecretVar<Self, C>,
            item: &Self::ItemVar,
            cs: &mut C,
        );
    }
}
