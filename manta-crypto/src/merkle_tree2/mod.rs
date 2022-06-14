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

//! Merkle Trees and Forests

use crate::{
    accumulator,
    constraint::{Allocator, Assert, Bool, Constant, Has, PartialEq, Variable},
    merkle_tree2::path::Path,
};

pub mod path;

/// Index Selector
///
/// The index selector is used to determine the order of the inputs to [`Hash::join`]. For a binary
/// Merkle Tree, this type is a boolean inside of `COM`.
pub trait Selector<COM = ()> {}

/// Merkle Tree Hash Function
pub trait Hash<COM = ()> {
    /// Selector Type
    type Selector: Selector<COM>;

    /// Hash Digest Type
    type Output;

    /// Computes the joined hash of `lhs` and `rhs` producing a new [`Output`](Self::Output) on the
    /// next layer of the tree.
    fn join(&self, lhs: &Self::Output, rhs: &Self::Output, compiler: &mut COM) -> Self::Output;

    /// Computes the joined hash of `lhs` and `rhs`, in the order determined by `selector`,
    /// producing a new [`Output`](Self::Output) on the next layer of the tree.
    fn join_with(
        &self,
        selector: &Self::Selector,
        lhs: &Self::Output,
        rhs: &Self::Output,
        compiler: &mut COM,
    ) -> Self::Output;
}

/// Selector Iterator Trait Alias
///
/// This `trait` can be used as an alias to the explicit borrowing [`IntoIterator`] requirement.
pub trait SelectorIter<'s, H, COM = ()>: IntoIterator<Item = &'s H::Selector>
where
    H: Hash<COM>,
    H::Selector: 's,
{
}

impl<'s, S, H, COM> SelectorIter<'s, H, COM> for S
where
    H: Hash<COM>,
    H::Selector: 's,
    S: IntoIterator<Item = &'s H::Selector>,
{
}

/// Global Selector
///
/// A global selector reflects a selection rule for the entire tree. In this case, it is simply some
/// iterator over [`Selector`]s which has `HEIGHT`-many entries. The iterator can have more elements
/// than `HEIGHT` but for allocation efficiency should contain exactly `HEIGHT`-many.
pub trait GlobalSelector<H, const HEIGHT: usize, COM = ()>
where
    H: Hash<COM>,
    for<'s> &'s Self: SelectorIter<'s, H, COM>,
{
}

///
pub trait Configuration<const HEIGHT: usize, COM = ()>
where
    for<'s> &'s Self::GlobalSelector: SelectorIter<'s, Self::Hash, COM>,
    COM: Has<bool>,
{
    ///
    type Output: Clone + PartialEq<Self::Output, COM>;

    ///
    type Hash: Hash<COM, Output = Self::Output>;

    ///
    type GlobalSelector: GlobalSelector<Self::Hash, HEIGHT, COM>;
}

///
pub struct Parameters<C, const HEIGHT: usize, COM = ()>(
    /// Merkle Tree Hash Function
    pub C::Hash,
)
where
    C: Configuration<HEIGHT, COM>,
    for<'s> &'s C::GlobalSelector: SelectorIter<'s, C::Hash, COM>,
    COM: Has<bool>;

impl<C, const HEIGHT: usize, COM> accumulator::Model<COM> for Parameters<C, HEIGHT, COM>
where
    C: Configuration<HEIGHT, COM>,
    for<'s> &'s C::GlobalSelector: SelectorIter<'s, C::Hash, COM>,
    COM: Has<bool>,
{
    type Item = C::Output;
    type Witness = Path<C::Hash, HEIGHT, C::GlobalSelector, COM>;
    type Output = C::Output;
    type Verification = Bool<COM>;

    #[inline]
    fn verify(
        &self,
        item: &Self::Item,
        witness: &Self::Witness,
        output: &Self::Output,
        compiler: &mut COM,
    ) -> Self::Verification {
        witness
            .root(&self.0, item.clone(), compiler)
            .eq(output, compiler)
    }
}
