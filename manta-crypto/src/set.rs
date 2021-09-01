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

use core::{fmt::Debug, hash::Hash};
use manta_codec::{ScaleDecode, ScaleEncode};

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
pub trait VerifyContainment<Public, Item> {
	/// Verifies that `self` is a proof that `item` is contained in some [`VerifiedSet`].
	fn verify(&self, public: &Public, item: &Item) -> bool;
}

/// Containment Proof for a [`VerifiedSet`]
#[derive(derivative::Derivative, ScaleDecode, ScaleEncode)]
#[derivative(
	Clone(bound = "S::Public: Clone, S::Secret: Clone"),
	Debug(bound = "S::Public: Debug, S::Secret: Debug"),
	Default(bound = "S::Public: Default, S::Secret: Default"),
	Eq(bound = "S::Public: Eq, S::Secret: Eq"),
	Hash(bound = "S::Public: Hash, S::Secret: Hash"),
	PartialEq(bound = "S::Public: PartialEq, S::Secret: PartialEq")
)]
pub struct ContainmentProof<S: ?Sized>
where
	S: VerifiedSet,
{
	/// Public Input
	pub input: S::Public,

	/// Secret Witness
	pub witness: S::Secret,
}

impl<S> ContainmentProof<S>
where
	S: VerifiedSet,
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

	/// Returns `true` if `public` is a valid input for the current state of `self`.
	fn check_public_input(&self, public: &Self::Public) -> bool;

	/// Generates a proof that the given `item` is stored in `self`.
	fn get_containment_proof(&self, item: &Self::Item) -> Option<ContainmentProof<Self>>;

	/// Returns `true` if there exists a proof that `item` is stored in `self`.
	#[inline]
	fn contains(&self, item: &Self::Item) -> bool {
		self.get_containment_proof(item).is_some()
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
