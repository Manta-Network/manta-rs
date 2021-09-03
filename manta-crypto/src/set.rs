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

pub(crate) mod prelude {
    #[doc(inline)]
    pub use crate::set::{Set, VerifiedSet};
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

    /// Inserts the `item` into `self`, returning `true` if the item was already contained in
    /// `self`.
    #[inline]
    fn insert(&mut self, item: Self::Item) -> bool {
        self.try_insert(item).is_err()
    }
}

/// Verified Containment Trait
pub trait VerifyContainment<Public, Item>
where
    Public: ?Sized,
    Item: ?Sized,
{
    /// Verifies that `self` is a proof that `item` is contained in some [`VerifiedSet`].
    fn verify(&self, public: &Public, item: &Item) -> bool;
}

/// Containment Proof for a [`VerifiedSet`]
pub struct ContainmentProof<S>
where
    S: VerifiedSet + ?Sized,
{
    /// Public Input
    pub input: S::Public,

    /// Secret Witness
    witness: S::Secret,
}

impl<S> ContainmentProof<S>
where
    S: VerifiedSet + ?Sized,
{
    /// Builds a new [`ContainmentProof`] from public `input` and secret `witness`.
    #[inline]
    pub fn new(input: S::Public, witness: S::Secret) -> Self {
        Self { input, witness }
    }

    /// Verifies that the `item` is contained in some [`VerifiedSet`].
    #[inline]
    pub fn verify(&self, item: &S::Item) -> bool {
        self.witness.verify(&self.input, item)
    }
}

/// Verified Set Trait
pub trait VerifiedSet {
    /// Item Stored in the [`VerifiedSet`]
    type Item;

    /// Public Input for [`Item`](Self::Item) Containment
    type Public;

    /// Secret Witness for [`Item`](Self::Item) Containment
    type Secret: VerifyContainment<Self::Public, Self::Item>;

    /// Error Generating a [`ContainmentProof`]
    type ContainmentError;

    /// Returns `true` if `public` is a valid input for the current state of `self`.
    fn check_public_input(&self, public: &Self::Public) -> bool;

    /// Generates a proof that the given `item` is stored in `self`.
    fn get_containment_proof(
        &self,
        item: &Self::Item,
    ) -> Result<ContainmentProof<Self>, Self::ContainmentError>;

    /// Returns `true` if there exists a proof that `item` is stored in `self`.
    #[inline]
    fn contains(&self, item: &Self::Item) -> bool {
        self.get_containment_proof(item).is_ok()
    }

    /// Tries to insert the `item` into `self`, returning the item back if it was already
    /// contained in `self`.
    fn try_insert(&mut self, item: Self::Item) -> Result<(), Self::Item>;

    /// Inserts the `item` into `self`, returning `true` if the item was already contained in
    /// `self`.
    #[inline]
    fn insert(&mut self, item: Self::Item) -> bool {
        self.try_insert(item).is_err()
    }
}

impl<S> Set for S
where
    S: VerifiedSet + ?Sized,
{
    type Item = S::Item;

    #[inline]
    fn contains(&self, item: &Self::Item) -> bool {
        self.contains(item)
    }

    #[inline]
    fn try_insert(&mut self, item: Self::Item) -> Result<(), Self::Item> {
        self.try_insert(item)
    }

    #[inline]
    fn insert(&mut self, item: Self::Item) -> bool {
        self.insert(item)
    }
}
