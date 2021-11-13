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

//! Dynamic Cryptographic Accumulators

// TODO: See if we can modify `Accumulator` so that it can extend the `Verifier` trait directly.

/// Matching Set
///
/// This is a generalization of a single-element matching system, where there can be multiple
/// elements to match against.
pub trait MatchingSet<T> {
    /// Checks if `t` matches any element in `self`.
    fn contains(&self, t: &T) -> bool;
}

impl<T> MatchingSet<T> for T
where
    T: PartialEq,
{
    #[inline]
    fn contains(&self, t: &T) -> bool {
        self.eq(t)
    }
}

/// Accumulator Membership Verifier
pub trait Verifier {
    /// Item Type
    type Item: ?Sized;

    /// Public Checkpoint Type
    type Checkpoint;

    /// Secret Witness Type
    type Witness;

    /// Verification Type
    type Verification;

    /// Verifies that `item` is stored in a known accumulator with `checkpoint` and `witness`.
    fn verify(
        &self,
        item: &Self::Item,
        checkpoint: &Self::Checkpoint,
        witness: &Self::Witness,
    ) -> Self::Verification;
}

impl<V> Verifier for &V
where
    V: Verifier + ?Sized,
{
    type Item = V::Item;

    type Checkpoint = V::Checkpoint;

    type Witness = V::Witness;

    type Verification = V::Verification;

    #[inline]
    fn verify(
        &self,
        item: &Self::Item,
        checkpoint: &Self::Checkpoint,
        witness: &Self::Witness,
    ) -> Self::Verification {
        (*self).verify(item, checkpoint, witness)
    }
}

/// Accumulator
pub trait Accumulator {
    /// Item Type
    type Item: ?Sized;

    /// Public Checkpoint Type
    type Checkpoint;

    /// Secret Witness Type
    type Witness;

    /// Verifier Type
    type Verifier: Verifier<Item = Self::Item, Checkpoint = Self::Checkpoint, Witness = Self::Witness>
        + ?Sized;

    /// Checkpoint Matching Set Type
    type CheckpointSet: MatchingSet<Self::Checkpoint>;

    /// Returns the verifier for `self`.
    fn verifier(&self) -> &Self::Verifier;

    /// Returns the checkpoint matching set for the current state of `self`.
    fn checkpoints(&self) -> Self::CheckpointSet;

    /// Returns `true` if `checkpoint` is contained in the current checkpoint matching set
    /// associated to `self`.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for implementations of [`Accumulator`] which can do a
    /// checkpoint matching without having to return an entire owned [`Self::CheckpointSet`].
    #[inline]
    fn matching_checkpoint(&self, checkpoint: &Self::Checkpoint) -> bool {
        self.checkpoints().contains(checkpoint)
    }

    /// Inserts `item` into `self` with the guarantee that `self` can later return a valid
    /// membership proof for `item` with a call to [`prove`](Self::prove). This method returns
    /// `false` if the maximum capacity of the accumulator would be exceeded by inserting `item`.
    fn insert(&mut self, item: &Self::Item) -> bool;

    /// Returns a membership proof for `item` if it is contained in `self`.
    fn prove(&self, item: &Self::Item) -> Option<MembershipProof<Self::Verifier>>;

    /// Returns `true` if `item` is stored in `self`.
    ///
    /// # Implementation Note
    ///
    /// This method must at least return `true` for `item` whenever a valid proof of membership
    /// exists. It may return `true` in other cases when `self` knows that it has `item` stored but
    /// cannot return a proof for it, like in the case of [`OptimizedAccumulator`] implementations.
    /// In other words, this method is allowed to return false negatives, but not false positives.
    #[inline]
    fn contains(&self, item: &Self::Item) -> bool {
        self.prove(item).is_some()
    }
}

impl<A> Accumulator for &mut A
where
    A: Accumulator + ?Sized,
{
    type Item = A::Item;

    type Checkpoint = A::Checkpoint;

    type Witness = A::Witness;

    type Verifier = A::Verifier;

    type CheckpointSet = A::CheckpointSet;

    #[inline]
    fn verifier(&self) -> &Self::Verifier {
        (**self).verifier()
    }

    #[inline]
    fn checkpoints(&self) -> Self::CheckpointSet {
        (**self).checkpoints()
    }

    #[inline]
    fn matching_checkpoint(&self, checkpoint: &Self::Checkpoint) -> bool {
        (**self).matching_checkpoint(checkpoint)
    }

    #[inline]
    fn insert(&mut self, item: &Self::Item) -> bool {
        (**self).insert(item)
    }

    #[inline]
    fn prove(&self, item: &Self::Item) -> Option<MembershipProof<Self::Verifier>> {
        (**self).prove(item)
    }

    #[inline]
    fn contains(&self, item: &Self::Item) -> bool {
        (**self).contains(item)
    }
}

/// Constant Capacity Accumulator
pub trait ConstantCapacityAccumulator: Accumulator {
    /// Returns the total number of items that can be stored in `self`.
    fn capacity() -> usize;
}

/// Exact Size Accumulator
pub trait ExactSizeAccumulator: Accumulator {
    /// Returns the number of items stored in `self`.
    fn len(&self) -> usize;

    /// Returns `true` if the length of `self` is zero.
    #[inline]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Optimized Accumulator
pub trait OptimizedAccumulator: Accumulator {
    /// Inserts `item` into `self` without the guarantee that `self` with be able to return a proof
    /// of membership for `item`. This method returns `false` if the maximum capacity of the
    /// accumulator would be exceeded by inserting `item`.
    ///
    /// # Implementation Note
    ///
    /// By default, this method uses [`insert`] to store `item` in `self`. Since this method may
    /// insert items which will never have membership proofs, the [`contains`] method is allowed to
    /// return `false` for those items if necessary. In other words, the [`contains`] method is
    /// allowed to return false negatives, but not false positives.
    ///
    /// [`insert`]: Accumulator::insert
    /// [`contains`]: Accumulator::contains
    #[inline]
    fn insert_nonprovable(&mut self, item: &<Self::Verifier as Verifier>::Item) -> bool {
        self.insert(item)
    }
}

/// Accumulator Membership Proof
pub struct MembershipProof<V>
where
    V: Verifier + ?Sized,
{
    /// Public Checkpoint
    checkpoint: V::Checkpoint,

    /// Secret Witness
    witness: V::Witness,
}

impl<V> MembershipProof<V>
where
    V: Verifier + ?Sized,
{
    /// Builds a new [`MembershipProof`] from `checkpoint` and `witness`.
    #[inline]
    pub fn new(checkpoint: V::Checkpoint, witness: V::Witness) -> Self {
        Self {
            checkpoint,
            witness,
        }
    }

    /// Converts `self` into its checkpoint, dropping the [`V::Witness`](Verifier::Witness).
    #[inline]
    pub fn into_checkpoint(self) -> V::Checkpoint {
        self.checkpoint
    }

    /// Returns `true` if the checkpoint associated to `self` is contained in `checkpoints`.
    #[inline]
    pub fn checkpoint_contained_in<S>(&self, checkpoints: &S) -> bool
    where
        S: MatchingSet<V::Checkpoint>,
    {
        checkpoints.contains(&self.checkpoint)
    }

    /// Returns `true` if the checkpoint associated to `self` is contained in the current
    /// checkpoint matching set associated to `accumulator`.
    #[inline]
    pub fn matching_checkpoint<A>(&self, accumulator: &A) -> bool
    where
        A: Accumulator<
            Item = V::Item,
            Checkpoint = V::Checkpoint,
            Witness = V::Witness,
            Verifier = V,
        >,
    {
        accumulator.matching_checkpoint(&self.checkpoint)
    }

    /// Verifies that `item` is stored in a known accumulator using `verifier`.
    #[inline]
    pub fn verify(&self, item: &V::Item, verifier: &V) -> V::Verification {
        verifier.verify(item, &self.checkpoint, &self.witness)
    }
}

/// Constraint System Gadgets for Accumulators
#[cfg(feature = "constraint")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "constraint")))]
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
    pub struct MembershipProofModeEntry<CheckpointMode, WitnessMode> {
        /// Public Checkpoint Allocation Mode
        pub checkpoint: CheckpointMode,

        /// Secret Witness Allocation Mode
        pub witness: WitnessMode,
    }

    impl<CheckpointMode, WitnessMode> MembershipProofModeEntry<CheckpointMode, WitnessMode> {
        /// Builds a new [`MembershipProofModeEntry`] from a `checkpoint` mode and a `witness` mode.
        #[inline]
        pub fn new(checkpoint: CheckpointMode, witness: WitnessMode) -> Self {
            Self {
                checkpoint,
                witness,
            }
        }
    }

    impl<CheckpointMode, WitnessMode> From<Derived>
        for MembershipProofModeEntry<CheckpointMode, WitnessMode>
    where
        CheckpointMode: From<Derived>,
        WitnessMode: From<Derived>,
    {
        #[inline]
        fn from(d: Derived) -> Self {
            Self::new(d.into(), d.into())
        }
    }

    /// Membership Proof Allocation Mode
    #[derive(derivative::Derivative)]
    #[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct MembershipProofMode<CheckpointMode, WitnessMode>(
        PhantomData<(CheckpointMode, WitnessMode)>,
    )
    where
        CheckpointMode: AllocationMode,
        WitnessMode: AllocationMode;

    impl<CheckpointMode, WitnessMode> AllocationMode
        for MembershipProofMode<CheckpointMode, WitnessMode>
    where
        CheckpointMode: AllocationMode,
        WitnessMode: AllocationMode,
    {
        type Known = MembershipProofModeEntry<CheckpointMode::Known, WitnessMode::Known>;
        type Unknown = MembershipProofModeEntry<CheckpointMode::Unknown, WitnessMode::Unknown>;
    }

    /// Membership Proof Variable
    pub struct MembershipProofVar<V, C>
    where
        V: Verifier + ?Sized,
        C: HasVariable<V::Checkpoint> + HasVariable<V::Witness> + ?Sized,
    {
        /// Public Checkpoint Variable
        checkpoint: Var<V::Checkpoint, C>,

        /// Secret Witness Variable
        witness: Var<V::Witness, C>,
    }

    impl<V, C> MembershipProofVar<V, C>
    where
        V: Verifier + ?Sized,
        C: HasVariable<V::Checkpoint> + HasVariable<V::Witness> + ?Sized,
    {
        /// Builds a new [`MembershipProofVar`] from `checkpoint` and `witness` variables.
        #[inline]
        pub fn new(checkpoint: Var<V::Checkpoint, C>, witness: Var<V::Witness, C>) -> Self {
            Self {
                checkpoint,
                witness,
            }
        }

        /// Asserts that `self` is a valid proof to the fact that `item` is stored in some known
        /// accumulator.
        #[inline]
        pub fn assert_validity<VV>(&self, item: &VV::ItemVar, verifier: &VV, cs: &mut C)
        where
            C: ConstraintSystem,
            VV: VerifierVariable<C, Type = V>,
        {
            verifier.assert_valid_membership_proof(item, &self.checkpoint, &self.witness, cs);
        }
    }

    impl<V, C> Variable<C> for MembershipProofVar<V, C>
    where
        V: Verifier + ?Sized,
        C: HasVariable<V::Checkpoint> + HasVariable<V::Witness> + ?Sized,
    {
        type Type = MembershipProof<V>;

        type Mode = MembershipProofMode<Mode<V::Checkpoint, C>, Mode<V::Witness, C>>;

        #[inline]
        fn new(cs: &mut C, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
            match allocation {
                Allocation::Known(this, mode) => Self::new(
                    cs.allocate_known(&this.checkpoint, mode.checkpoint),
                    cs.allocate_known(&this.witness, mode.witness),
                ),
                Allocation::Unknown(mode) => Self::new(
                    unknown::<V::Checkpoint, _>(cs, mode.checkpoint),
                    unknown::<V::Witness, _>(cs, mode.witness),
                ),
            }
        }
    }

    impl<V, C> HasAllocation<C> for MembershipProof<V>
    where
        V: Verifier + ?Sized,
        C: HasVariable<V::Checkpoint> + HasVariable<V::Witness> + ?Sized,
    {
        type Variable = MembershipProofVar<V, C>;
        type Mode = MembershipProofMode<Mode<V::Checkpoint, C>, Mode<V::Witness, C>>;
    }

    /// Public Checkpoint Type for [`VerifierVariable`]
    pub type CheckpointType<V, C> = <<V as Variable<C>>::Type as Verifier>::Checkpoint;

    /// Secret Witness Type for [`VerifierVariable`]
    pub type WitnessType<V, C> = <<V as Variable<C>>::Type as Verifier>::Witness;

    /// Public Checkpoint Variable Type for [`VerifierVariable`]
    pub type CheckpointVar<V, C> = Var<CheckpointType<V, C>, C>;

    /// Secret Witness Variable Type for [`VerifierVariable`]
    pub type WitnessVar<V, C> = Var<WitnessType<V, C>, C>;

    /// Verified Set Variable
    pub trait VerifierVariable<C>: Variable<C>
    where
        C: ConstraintSystem
            + HasVariable<CheckpointType<Self, C>>
            + HasVariable<WitnessType<Self, C>>
            + ?Sized,
        Self::Type: Verifier,
    {
        /// Item Variable
        type ItemVar: Variable<C, Type = <Self::Type as Verifier>::Item>;

        /// Asserts that `checkpoint` and `witness` form a proof to the fact that `item` is stored
        /// in some known accumulator.
        fn assert_valid_membership_proof(
            &self,
            item: &Self::ItemVar,
            checkpoint: &CheckpointVar<Self, C>,
            witness: &WitnessVar<Self, C>,
            cs: &mut C,
        );
    }
}

/// Testing Framework
#[cfg(feature = "test")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "test")))]
pub mod test {
    use super::*;
    use alloc::vec::Vec;
    use core::fmt::Debug;

    /// Asserts that `accumulator` can prove the membership of `item` after it is inserted.
    #[inline]
    pub fn assert_provable_membership<A>(accumulator: &mut A, item: &A::Item) -> A::Checkpoint
    where
        A: Accumulator,
        A::Verifier: Verifier<Verification = bool>,
    {
        assert!(
            accumulator.insert(item),
            "Item could not be inserted into the accumulator."
        );
        assert!(
            accumulator.contains(item),
            "Item was supposed to be contained in the accumulator after insertion."
        );
        if let Some(proof) = accumulator.prove(item) {
            assert!(
                proof.verify(item, accumulator.verifier()),
                "Invalid proof returned for inserted item."
            );
            proof.into_checkpoint()
        } else {
            panic!("Item was supposed to be contained in the accumulator after insertion.")
        }
    }

    /// Asserts that the `accumulator` yields unique checkpoints after every insertion of items from
    /// `iter`.
    #[inline]
    pub fn assert_unique_checkpoints<'i, A, I>(accumulator: &mut A, iter: I)
    where
        A: Accumulator,
        A::Item: 'i,
        A::Checkpoint: Debug + PartialEq,
        A::Verifier: Verifier<Verification = bool>,
        I: IntoIterator<Item = &'i A::Item>,
    {
        let checkpoints = iter
            .into_iter()
            .map(move |item| assert_provable_membership(accumulator, item))
            .collect::<Vec<_>>();
        for (i, x) in checkpoints.iter().enumerate() {
            for (j, y) in checkpoints.iter().enumerate().skip(i + 1) {
                assert_ne!(x, y, "Found matching checkpoints at {:?} and {:?}.", i, j)
            }
        }
    }
}
