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

    /// Secret Witness Type
    type Witness;

    /// Output Type
    type Output;

    /// Verification Type
    type Verification;

    /// Verifies that `item` is stored in a known accumulator with accumulated `output` and
    /// membership `witness`.
    fn verify(
        &self,
        item: &Self::Item,
        witness: &Self::Witness,
        output: &Self::Output,
    ) -> Self::Verification;
}

impl<V> Verifier for &V
where
    V: Verifier + ?Sized,
{
    type Item = V::Item;

    type Witness = V::Witness;

    type Output = V::Output;

    type Verification = V::Verification;

    #[inline]
    fn verify(
        &self,
        item: &Self::Item,
        witness: &Self::Witness,
        output: &Self::Output,
    ) -> Self::Verification {
        (*self).verify(item, witness, output)
    }
}

/// Accumulator Output Type
pub type Output<A> = <<A as Accumulator>::Verifier as Verifier>::Output;

/// Accumulator
pub trait Accumulator {
    /// Item Type
    type Item: ?Sized;

    /// Verifier Type
    type Verifier: Verifier<Item = Self::Item> + ?Sized;

    /// Output Matching Set Type
    type OutputSet: MatchingSet<<Self::Verifier as Verifier>::Output>;

    /// Returns the verifier for `self`.
    fn verifier(&self) -> &Self::Verifier;

    /// Returns the output matching set for the current state of `self`.
    fn outputs(&self) -> Self::OutputSet;

    /// Returns `true` if `output` is contained in the current output matching set associated to
    /// `self`.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for implementations of [`Accumulator`] which can do a
    /// output matching without having to return an entire owned [`Self::OutputSet`].
    #[inline]
    fn matching_output(&self, output: &Output<Self>) -> bool {
        self.outputs().contains(output)
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

    type Verifier = A::Verifier;

    type OutputSet = A::OutputSet;

    #[inline]
    fn verifier(&self) -> &Self::Verifier {
        (**self).verifier()
    }

    #[inline]
    fn outputs(&self) -> Self::OutputSet {
        (**self).outputs()
    }

    #[inline]
    fn matching_output(&self, output: &Output<Self>) -> bool {
        (**self).matching_output(output)
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

    /// Removes the witnesses to the membership of `item` in `self`. The resulting state of the
    /// accumulator after removing a proof should be the same as if the item had been inserted into
    /// the accumulator with [`insert_nonprovable`](Self::insert_nonprovable). This method returns
    /// `true` if the item was successfully demoted to non-provable.
    ///
    /// # Implementation Note
    ///
    /// By default, this method does nothing and returns `false`. Implementations of this method may
    /// fail arbitrarily, and should only successfully remove a proof if the implementation is
    /// efficient enough. Space and time tradeoffs should be studied to determine the usefulness of
    /// this method.
    #[inline]
    fn remove_proof(&mut self, item: &<Self::Verifier as Verifier>::Item) -> bool {
        let _ = item;
        false
    }
}

/// Accumulator Membership Proof
pub struct MembershipProof<V>
where
    V: Verifier + ?Sized,
{
    /// Secret Membership Witness
    witness: V::Witness,

    /// Accumulator Output
    output: V::Output,
}

impl<V> MembershipProof<V>
where
    V: Verifier + ?Sized,
{
    /// Builds a new [`MembershipProof`] from `witness` and `output`.
    #[inline]
    pub fn new(witness: V::Witness, output: V::Output) -> Self {
        Self { witness, output }
    }

    /// Returns the accumulated output part of `self`, dropping the
    /// [`V::Witness`](Verifier::Witness).
    #[inline]
    pub fn into_output(self) -> V::Output {
        self.output
    }

    /// Returns `true` if the output associated to `self` is contained in `outputs`.
    #[inline]
    pub fn output_contained_in<S>(&self, outputs: &S) -> bool
    where
        S: MatchingSet<V::Output>,
    {
        outputs.contains(&self.output)
    }

    /// Returns `true` if the output associated to `self` is contained in the current output
    /// matching set associated to `accumulator`.
    #[inline]
    pub fn matching_output<A>(&self, accumulator: &A) -> bool
    where
        A: Accumulator<Verifier = V>,
    {
        accumulator.matching_output(&self.output)
    }

    /// Verifies that `item` is stored in a known accumulator using `verifier`.
    #[inline]
    pub fn verify(&self, item: &V::Item, verifier: &V) -> V::Verification {
        verifier.verify(item, &self.witness, &self.output)
    }
}

/// Constraint System Gadgets for Accumulators
pub mod constraint {
    use super::*;
    use crate::constraint::{Allocation, AllocationMode, Derived, Variable, VariableSource};
    use core::marker::PhantomData;

    /// Membership Proof Allocation Mode Entry
    #[derive(derivative::Derivative)]
    #[derivative(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
    pub struct MembershipProofModeEntry<WitnessMode, OutputMode> {
        /// Secret Witness Allocation Mode
        pub witness: WitnessMode,

        /// Accumulated Value Allocation Mode
        pub output: OutputMode,
    }

    impl<WitnessMode, OutputMode> MembershipProofModeEntry<WitnessMode, OutputMode> {
        /// Builds a new [`MembershipProofModeEntry`] from a witness` mode and an `output` mode.
        #[inline]
        pub fn new(witness: WitnessMode, output: OutputMode) -> Self {
            Self { witness, output }
        }
    }

    impl<WitnessMode, OutputMode> From<Derived> for MembershipProofModeEntry<WitnessMode, OutputMode>
    where
        WitnessMode: From<Derived>,
        OutputMode: From<Derived>,
    {
        #[inline]
        fn from(d: Derived) -> Self {
            Self::new(d.into(), d.into())
        }
    }

    /// Membership Proof Allocation Mode
    #[derive(derivative::Derivative)]
    #[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct MembershipProofMode<WitnessMode, OutputMode>(PhantomData<(WitnessMode, OutputMode)>)
    where
        WitnessMode: AllocationMode,
        OutputMode: AllocationMode;

    impl<WitnessMode, OutputMode> AllocationMode for MembershipProofMode<WitnessMode, OutputMode>
    where
        WitnessMode: AllocationMode,
        OutputMode: AllocationMode,
    {
        type Known = MembershipProofModeEntry<WitnessMode::Known, OutputMode::Known>;
        type Unknown = MembershipProofModeEntry<WitnessMode::Unknown, OutputMode::Unknown>;
    }

    impl<C, V> Variable<C> for MembershipProof<V>
    where
        C: ?Sized,
        V: Variable<C> + Verifier + ?Sized,
        V::Type: Verifier,
        V::Witness: Variable<C, Type = <V::Type as Verifier>::Witness>,
        V::Output: Variable<C, Type = <V::Type as Verifier>::Output>,
    {
        type Type = MembershipProof<V::Type>;

        type Mode = MembershipProofMode<
            <V::Witness as Variable<C>>::Mode,
            <V::Output as Variable<C>>::Mode,
        >;

        #[inline]
        fn new(cs: &mut C, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
            match allocation {
                Allocation::Known(this, mode) => Self::new(
                    this.witness.as_known(cs, mode.witness),
                    this.output.as_known(cs, mode.output),
                ),
                Allocation::Unknown(mode) => Self::new(
                    V::Witness::new_unknown(cs, mode.witness),
                    V::Output::new_unknown(cs, mode.output),
                ),
            }
        }
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
    pub fn assert_provable_membership<A>(accumulator: &mut A, item: &A::Item) -> Output<A>
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
            proof.into_output()
        } else {
            panic!("Item was supposed to be contained in the accumulator after insertion.")
        }
    }

    /// Asserts that the `accumulator` yields unique accumulated values after every insertion of
    /// items from `iter`.
    #[inline]
    pub fn assert_unique_outputs<'i, A, I>(accumulator: &mut A, iter: I)
    where
        A: Accumulator,
        A::Item: 'i,
        A::Verifier: Verifier<Verification = bool>,
        Output<A>: Debug + PartialEq,
        I: IntoIterator<Item = &'i A::Item>,
    {
        let outputs = iter
            .into_iter()
            .map(move |item| assert_provable_membership(accumulator, item))
            .collect::<Vec<_>>();
        for (i, x) in outputs.iter().enumerate() {
            for (j, y) in outputs.iter().enumerate().skip(i + 1) {
                assert_ne!(x, y, "Found matching checkpoints at {:?} and {:?}.", i, j)
            }
        }
    }
}
