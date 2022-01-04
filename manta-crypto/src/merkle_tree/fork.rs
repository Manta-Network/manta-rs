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

//! Merkle Tree Forks

// TODO: Implement derive-able traits for these types.
// TODO: See if we can get rid of the smart pointer logic.

use crate::merkle_tree::{
    capacity,
    inner_tree::{BTreeMap, InnerMap, PartialInnerTree},
    partial::Partial,
    path::CurrentInnerPath,
    Configuration, InnerDigest, Leaf, LeafDigest, Node, Parameters, Parity, Tree,
};
use alloc::{vec, vec::Vec};
use core::{borrow::Borrow, fmt::Debug, hash::Hash, marker::PhantomData, mem, ops::Deref};
use manta_util::pointer::{self, PointerFamily};

/// Fork-able Merkle Tree
pub struct Trunk<C, T, P = pointer::SingleThreaded>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
    P: PointerFamily<T>,
{
    /// Base Merkle Tree
    base: Option<P::Strong>,

    /// Type Parameter Marker
    __: PhantomData<C>,
}

impl<C, T, P> Trunk<C, T, P>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
    P: PointerFamily<T>,
{
    /// Builds a new [`Trunk`] from a reference-counted tree.
    #[inline]
    fn build(base: Option<P::Strong>) -> Self {
        Self {
            base,
            __: PhantomData,
        }
    }

    /// Builds a new [`Trunk`] from a `base` merkle tree.
    #[inline]
    pub fn new(base: T) -> Self {
        Self::build(Some(P::new(base)))
    }

    /// Converts `self` back into its inner [`Tree`].
    ///
    /// # Safety
    ///
    /// This method automatically detaches all of the forks associated to this trunk. To attach them
    /// to another trunk, use [`Fork::attach`].
    #[inline]
    pub fn into_tree(self) -> T {
        P::claim(self.base.unwrap())
    }

    /// Creates a new fork of this trunk.
    #[inline]
    pub fn fork<M>(&self, parameters: &Parameters<C>) -> Fork<C, T, P, M>
    where
        M: Default + InnerMap<C>,
        LeafDigest<C>: Default,
    {
        Fork::new(parameters, self)
    }

    /// Tries to attach `fork` to `self` as its new trunk, returning `false` if `fork` has
    /// too many leaves to fit in `self`.
    #[inline]
    pub fn attach<M>(&self, parameters: &Parameters<C>, fork: &mut Fork<C, T, P, M>) -> bool
    where
        M: Default + InnerMap<C>,
        LeafDigest<C>: Default,
    {
        fork.attach(parameters, self)
    }

    /// Tries to merge `fork` onto `self`, returning `fork` back if it could not be merged.
    ///
    /// # Safety
    ///
    /// If the merge succeeds, this method automatically detaches all of the forks associated to
    /// this trunk. To attach them to another trunk, use [`Fork::attach`]. To attach them to this
    /// trunk, [`attach`](Self::attach) can also be used.
    ///
    /// Since merging will add leaves to the base tree, forks which were previously associated to
    /// this trunk will have to catch up. If [`Fork::attach`] or [`attach`](Self::attach) is used,
    /// the leaves which were added in this merge will exist before the first leaf in the fork in
    /// the final tree.
    #[inline]
    pub fn merge<M>(
        &mut self,
        parameters: &Parameters<C>,
        fork: Fork<C, T, P, M>,
    ) -> Result<(), Fork<C, T, P, M>>
    where
        M: Default + InnerMap<C>,
        LeafDigest<C>: Default,
    {
        match fork.get_attached_base(self) {
            Some(base) => {
                self.merge_branch(parameters, base, fork.base_contribution, fork.branch);
                Ok(())
            }
            _ => Err(fork),
        }
    }

    /// Performs a merge of the `branch` onto `fork_base`, setting `self` equal to the resulting
    /// merged tree.
    #[inline]
    fn merge_branch<M>(
        &mut self,
        parameters: &Parameters<C>,
        fork_base: P::Strong,
        base_contribution: BaseContribution,
        branch: Partial<C, M>,
    ) where
        M: InnerMap<C> + Default,
        LeafDigest<C>: Default,
    {
        self.base = Some(fork_base);
        let mut base = P::claim(mem::take(&mut self.base).unwrap());
        assert!(base
            .extend_digests(
                parameters,
                Fork::<C, T, P, M>::extract_leaves(base_contribution, branch)
            )
            .is_ok());
        self.base = Some(P::new(base));
    }

    /// Borrows the underlying merkle tree pointer.
    #[inline]
    fn borrow_base(&self) -> &P::Strong {
        self.base.as_ref().unwrap()
    }

    /// Returns a new weak pointer to the base tree.
    #[inline]
    fn downgrade(&self) -> P::Weak {
        P::downgrade(self.borrow_base())
    }

    /// Checks if the internal base tree uses the same pointer as `base`.
    #[inline]
    fn ptr_eq_base(&self, base: &P::Strong) -> bool {
        P::strong_ptr_eq(self.borrow_base(), base)
    }
}

impl<C, T, P> AsRef<T> for Trunk<C, T, P>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
    P: PointerFamily<T>,
{
    #[inline]
    fn as_ref(&self) -> &T {
        self.borrow_base().as_ref()
    }
}

impl<C, T, P> Borrow<T> for Trunk<C, T, P>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
    P: PointerFamily<T>,
{
    #[inline]
    fn borrow(&self) -> &T {
        self.borrow_base().borrow()
    }
}

impl<C, T, P> Deref for Trunk<C, T, P>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
    P: PointerFamily<T>,
{
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.borrow_base().deref()
    }
}

/// Base Tree Leaf Contribution
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum BaseContribution {
    /// No Leaves Contributed
    Empty,

    /// Left Leaf Contributed
    LeftLeaf,

    /// Both Leaves Contributed
    BothLeaves,
}

impl Default for BaseContribution {
    #[inline]
    fn default() -> Self {
        Self::Empty
    }
}

/// Merkle Tree Fork
pub struct Fork<C, T, P = pointer::SingleThreaded, M = BTreeMap<C>>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
    P: PointerFamily<T>,
    M: Default + InnerMap<C>,
{
    /// Base Merkle Tree
    base: P::Weak,

    /// Base Tree Contribution
    base_contribution: BaseContribution,

    /// Branch Data
    branch: Partial<C, M>,
}

impl<C, T, P, M> Fork<C, T, P, M>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
    P: PointerFamily<T>,
    M: Default + InnerMap<C>,
{
    /// Builds a new [`Fork`] from `trunk`.
    #[inline]
    pub fn new(parameters: &Parameters<C>, trunk: &Trunk<C, T, P>) -> Self
    where
        LeafDigest<C>: Default,
    {
        Self::with_leaves(parameters, trunk, Default::default()).unwrap()
    }

    /// Builds a new [`Fork`] from `trunk` extended by `leaf_digests`, returning `None` if
    /// appending `leaf_digests` would exceed the capacity of the `trunk`.
    #[inline]
    pub fn with_leaves(
        parameters: &Parameters<C>,
        trunk: &Trunk<C, T, P>,
        leaf_digests: Vec<LeafDigest<C>>,
    ) -> Option<Self>
    where
        LeafDigest<C>: Default,
    {
        let (base_contribution, branch) =
            Self::new_branch(parameters, trunk.borrow_base().as_ref(), leaf_digests)?;
        Some(Self {
            base: trunk.downgrade(),
            base_contribution,
            branch,
        })
    }

    /// Builds a new branch off of `base`, extending by `leaf_digests`.
    #[inline]
    fn new_branch(
        parameters: &Parameters<C>,
        base: &T,
        leaf_digests: Vec<LeafDigest<C>>,
    ) -> Option<(BaseContribution, Partial<C, M>)>
    where
        LeafDigest<C>: Default,
    {
        if leaf_digests.len() + base.len() >= capacity::<C>() {
            return None;
        }
        Some(Self::new_branch_unchecked(parameters, base, leaf_digests))
    }

    /// Builds a new branch off of `base`, extending by `leaf_digests` without checking that
    /// `base` can accept new leaves.
    #[inline]
    fn new_branch_unchecked(
        parameters: &Parameters<C>,
        base: &T,
        leaf_digests: Vec<LeafDigest<C>>,
    ) -> (BaseContribution, Partial<C, M>)
    where
        LeafDigest<C>: Default,
    {
        let (base_contribution, base_inner_digest, base_leaf_digests, inner_path) =
            Self::generate_branch_setup(parameters, base);
        let mut partial = Partial::new_unchecked(
            base_leaf_digests,
            PartialInnerTree::from_current(parameters, base_inner_digest, inner_path),
        );
        let partial_tree_len = partial.len();
        for (i, digest) in leaf_digests.into_iter().enumerate() {
            partial.push_leaf_digest(parameters, Node(partial_tree_len + i), digest);
        }
        (base_contribution, partial)
    }

    /// Generates the setup data to compute [`new_branch_unchecked`](Self::new_branch_unchecked).
    #[inline]
    fn generate_branch_setup(
        parameters: &Parameters<C>,
        base: &T,
    ) -> (
        BaseContribution,
        InnerDigest<C>,
        Vec<LeafDigest<C>>,
        CurrentInnerPath<C>,
    )
    where
        LeafDigest<C>: Default,
    {
        if base.is_empty() {
            (
                BaseContribution::Empty,
                Default::default(),
                Default::default(),
                base.current_path(parameters).inner_path,
            )
        } else {
            let current_leaf = base.current_leaf();
            let current_path = base.current_path(parameters);
            match current_path.leaf_index().parity() {
                Parity::Left => (
                    BaseContribution::LeftLeaf,
                    parameters.join_leaves(&current_leaf, &current_path.sibling_digest),
                    vec![current_leaf],
                    current_path.inner_path,
                ),
                Parity::Right => (
                    BaseContribution::BothLeaves,
                    parameters.join_leaves(&current_path.sibling_digest, &current_leaf),
                    vec![current_path.sibling_digest, current_leaf],
                    current_path.inner_path,
                ),
            }
        }
    }

    /// Extracts the non-base leaves from `branch`.
    #[inline]
    fn extract_leaves(
        base_contribution: BaseContribution,
        branch: Partial<C, M>,
    ) -> Vec<LeafDigest<C>>
    where
        LeafDigest<C>: Default,
    {
        let mut leaf_digests = branch.into_leaves();
        mem::drop(leaf_digests.drain(0..base_contribution as usize));
        leaf_digests
    }

    /// Tries to rebase `branch` at `base`.
    #[inline]
    fn try_rebase(
        parameters: &Parameters<C>,
        base: &T,
        base_contribution: &mut BaseContribution,
        branch: &mut Partial<C, M>,
    ) -> bool
    where
        LeafDigest<C>: Default,
    {
        if branch.len() + base.len() - (*base_contribution as usize) >= capacity::<C>() {
            return false;
        }
        let (new_base_contribution, new_branch) = Self::new_branch_unchecked(
            parameters,
            base,
            Self::extract_leaves(*base_contribution, mem::take(branch)),
        );
        *base_contribution = new_base_contribution;
        *branch = new_branch;
        true
    }

    /// Tries to attach this fork to a new `trunk`, returning `false` if `self` has too many leaves
    /// to fit in `trunk`.
    #[inline]
    pub fn attach(&mut self, parameters: &Parameters<C>, trunk: &Trunk<C, T, P>) -> bool
    where
        LeafDigest<C>: Default,
    {
        if !Self::try_rebase(
            parameters,
            trunk.borrow_base().as_ref(),
            &mut self.base_contribution,
            &mut self.branch,
        ) {
            return false;
        }
        self.base = trunk.downgrade();
        true
    }

    /// Returns `true` if this fork is attached to some [`Trunk`].
    #[inline]
    pub fn is_attached(&self) -> bool {
        P::upgrade(&self.base).is_some()
    }

    /// Returns `true` if this fork is attached to `trunk`.
    #[inline]
    pub fn is_attached_to(&self, trunk: &Trunk<C, T, P>) -> bool {
        matches!(P::upgrade(&self.base), Some(base) if trunk.ptr_eq_base(&base))
    }

    /// Returns the attached base tree if `self` is attached to `trunk`.
    #[inline]
    fn get_attached_base(&self, trunk: &Trunk<C, T, P>) -> Option<P::Strong> {
        match P::upgrade(&self.base) {
            Some(base) if trunk.ptr_eq_base(&base) => Some(base),
            _ => None,
        }
    }

    /// Computes the length of this fork of the tree.
    #[inline]
    pub fn len(&self) -> usize {
        self.branch.len()
    }

    /// Returns `true` if this fork is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.branch.is_empty()
    }

    /// Returns the current root of this fork.
    #[inline]
    pub fn root(&self) -> &InnerDigest<C> {
        self.branch.root()
    }

    /// Appends a new `leaf` onto this fork.
    ///
    /// Returns `None` if this fork has been detached from its trunk. Use [`attach`](Self::attach)
    /// to re-associate a trunk to this fork.
    #[inline]
    pub fn push(&mut self, parameters: &Parameters<C>, leaf: &Leaf<C>) -> Option<bool>
    where
        LeafDigest<C>: Default,
    {
        let _ = P::upgrade(&self.base)?;
        Some(self.branch.push(parameters, leaf))
    }
}
