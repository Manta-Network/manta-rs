// Copyright 2019-2022 Manta Network.
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

use crate::constraint::{Allocate, Allocator, Constant, Derived, Variable};
use core::marker::PhantomData;

/// Accumulator Membership Model Types
pub trait Types {
    /// Item Type
    type Item: ?Sized;

    /// Secret Witness Type
    type Witness;

    /// Output Type
    type Output;
}

/// Accumulator Membership Model
pub trait Model<COM = ()>: Types {
    /// Verification Type
    ///
    /// Typically this is either [`bool`], a [`Result`] type, or a circuit boolean variable.
    type Verification;

    /// Verifies that `item` is stored in a known accumulator with accumulated `output` and
    /// membership `witness`.
    fn verify(
        &self,
        item: &Self::Item,
        witness: &Self::Witness,
        output: &Self::Output,
        compiler: &mut COM,
    ) -> Self::Verification;
}

/// Accumulator Item Hash Function
pub trait ItemHashFunction<T, COM = ()> {
    /// Item Type
    type Item;

    /// Converts `value` into an [`Item`](Self::Item) that is compatible with the relevant
    /// accumulator.
    fn item_hash(&self, value: &T, compiler: &mut COM) -> Self::Item;
}

/// Accumulator Membership Model Validity Assertion
///
/// For situations where we just want to assert validity of the membership proof, we can use this
/// trait as an optimization path for [`Model::verify`]. See [`assert_valid`](Self::assert_valid)
/// for more details.
pub trait AssertValidVerification<COM = ()>: Model<COM> {
    /// Asserts that the verification of the storage of `item` in the known accumulator is valid.
    ///
    /// # Optimization
    ///
    /// In compilers where assertions for more complex statements other than booleans being `true`,
    /// this function can provide an optimization path to reduce the cost of assertion.
    fn assert_valid(
        &self,
        item: &Self::Item,
        witness: &Self::Witness,
        output: &Self::Output,
        compiler: &mut COM,
    );
}

/// Accumulator Witness Type
pub type Witness<A> = <<A as Accumulator>::Model as Types>::Witness;

/// Accumulator Output Type
pub type Output<A> = <<A as Accumulator>::Model as Types>::Output;

/// Accumulator
pub trait Accumulator {
    /// Item Type
    type Item: ?Sized;

    /// Model Type
    type Model: Model<Item = Self::Item> + ?Sized;

    /// Returns the model associated with `self`.
    fn model(&self) -> &Self::Model;

    /// Inserts `item` into `self` with the guarantee that `self` can later return a valid
    /// membership proof for `item` with a call to [`prove`](Self::prove). This method returns
    /// `false` if the maximum capacity of the accumulator would be exceeded by inserting `item`.
    fn insert(&mut self, item: &Self::Item) -> bool;

    /// Returns a membership proof for `item` if it is contained in `self`.
    fn prove(&self, item: &Self::Item) -> Option<MembershipProof<Self::Model>>;

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
    type Model = A::Model;

    #[inline]
    fn model(&self) -> &Self::Model {
        (**self).model()
    }

    #[inline]
    fn insert(&mut self, item: &Self::Item) -> bool {
        (**self).insert(item)
    }

    #[inline]
    fn prove(&self, item: &Self::Item) -> Option<MembershipProof<Self::Model>> {
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
    fn insert_nonprovable(&mut self, item: &Self::Item) -> bool {
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
    fn remove_proof(&mut self, item: &Self::Item) -> bool {
        let _ = item;
        false
    }
}

/// Accumulator Membership Proof
pub struct MembershipProof<M, COM = ()>
where
    M: Model<COM> + ?Sized,
{
    /// Secret Membership Witness
    witness: M::Witness,

    /// Accumulator Output
    output: M::Output,

    /// Type Parameter Marker
    __: PhantomData<COM>,
}

impl<M, COM> MembershipProof<M, COM>
where
    M: Model<COM> + ?Sized,
{
    /// Builds a new [`MembershipProof`] from `witness` and `output`.
    #[inline]
    pub fn new(witness: M::Witness, output: M::Output) -> Self {
        Self {
            witness,
            output,
            __: PhantomData,
        }
    }

    /// Returns the accumulated output part of `self`, dropping the [`M::Witness`](Types::Witness).
    #[inline]
    pub fn into_output(self) -> M::Output {
        self.output
    }

    /// Returns a reference to the accumulated output part of `self`.
    #[inline]
    pub fn output(&self) -> &M::Output {
        &self.output
    }

    /// Verifies that `item` is stored in a known accumulator using `model`.
    #[inline]
    pub fn verify(&self, model: &M, item: &M::Item, compiler: &mut COM) -> M::Verification {
        model.verify(item, &self.witness, &self.output, compiler)
    }

    /// Asserts that the verification of the storage of `item` in the known accumulator is valid.
    #[inline]
    pub fn assert_valid(&self, model: &M, item: &M::Item, compiler: &mut COM)
    where
        M: AssertValidVerification<COM>,
    {
        model.assert_valid(item, &self.witness, &self.output, compiler)
    }

    /// Converts `self` from the `M` accumulator model to the `N` accumulator model.
    ///
    /// # Validity
    ///
    /// This function cannot guarantee that the point-wise conversion of the witness and output
    /// preserves the membership proof validity.
    #[inline]
    pub fn into<N>(self) -> MembershipProof<N, COM>
    where
        N: Model<COM> + ?Sized,
        M::Witness: Into<N::Witness>,
        M::Output: Into<N::Output>,
    {
        MembershipProof::new(self.witness.into(), self.output.into())
    }
}

impl<M, W, O, COM> Variable<Derived<(W, O)>, COM> for MembershipProof<M, COM>
where
    M: Model<COM> + Constant<COM>,
    M::Type: Model,
    M::Witness: Variable<W, COM, Type = <M::Type as Types>::Witness>,
    M::Output: Variable<O, COM, Type = <M::Type as Types>::Output>,
{
    type Type = MembershipProof<M::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self::new(compiler.allocate_unknown(), compiler.allocate_unknown())
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(
            this.witness.as_known(compiler),
            this.output.as_known(compiler),
        )
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
        A::Model: Model<Verification = bool>,
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
                proof.verify(accumulator.model(), item, &mut ()),
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
        A::Model: Model<Verification = bool>,
        Output<A>: Debug + PartialEq,
        I: IntoIterator<Item = &'i A::Item>,
    {
        let outputs = iter
            .into_iter()
            .map(move |item| assert_provable_membership(accumulator, item))
            .collect::<Vec<_>>();
        for (i, x) in outputs.iter().enumerate() {
            for (j, y) in outputs.iter().enumerate().skip(i + 1) {
                assert_ne!(x, y, "Found matching outputs at {:?} and {:?}.", i, j)
            }
        }
    }
}
