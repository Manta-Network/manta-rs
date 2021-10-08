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

// TODO: Think about whether we want to keep the `raw::MerkleTreePointerFamily` API sealed or not.
// TODO: Implement derive-able traits for these types.
// TODO: See if we can get rid of the smart pointer logic.

use crate::merkle_tree::{
    capacity,
    inner_tree::{BTreeMap, InnerMap, PartialInnerTree},
    partial::Partial,
    path::CurrentInnerPath,
    Configuration, InnerDigest, Leaf, LeafDigest, MerkleTree, Node, Parity, Tree,
};
use alloc::{vec, vec::Vec};
use core::{borrow::Borrow, fmt::Debug, hash::Hash, mem, ops::Deref};

/// Fork-able Merkle Tree
pub struct Trunk<C, T, P = raw::SingleThreaded>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
    P: raw::MerkleTreePointerFamily<C, T>,
{
    /// Base Merkle Tree
    base: Option<P::Strong>,
}

impl<C, T, P> Trunk<C, T, P>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
    P: raw::MerkleTreePointerFamily<C, T>,
{
    /// Builds a new [`Trunk`] from a reference-counted [`MerkleTree`].
    #[inline]
    fn new_inner(base: Option<P::Strong>) -> Self {
        Self { base }
    }

    /// Builds a new [`Trunk`] from a `base` merkle tree.
    #[inline]
    pub fn new(base: MerkleTree<C, T>) -> Self {
        Self::new_inner(Some(P::new(base)))
    }

    /// Converts `self` back into its inner [`MerkleTree`].
    ///
    /// # Safety
    ///
    /// This method automatically detaches all of the forks associated to this trunk. To attach them
    /// to another trunk, use [`Fork::attach`].
    #[inline]
    pub fn into_tree(self) -> MerkleTree<C, T> {
        P::claim(self.base.unwrap())
    }

    /// Creates a new fork of this trunk.
    #[inline]
    pub fn fork<M>(&self) -> Fork<C, T, P, M>
    where
        M: InnerMap<C> + Default,
    {
        Fork::new(self)
    }

    /// Tries to attach `fork` to `self` as its new trunk, returning `false` if `fork` has
    /// too many leaves to fit in `self`.
    #[inline]
    pub fn attach<M>(&self, fork: &mut Fork<C, T, P, M>) -> bool
    where
        M: InnerMap<C> + Default,
    {
        fork.attach(self)
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
    pub fn merge<M>(&mut self, fork: Fork<C, T, P, M>) -> Result<(), Fork<C, T, P, M>>
    where
        M: InnerMap<C> + Default,
    {
        match fork.get_attached_base(self) {
            Some(base) => {
                self.merge_branch(base, fork.base_contribution, fork.branch);
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
        fork_base: P::Strong,
        base_contribution: BaseContribution,
        branch: Partial<C, M>,
    ) where
        M: InnerMap<C> + Default,
    {
        self.base = Some(fork_base);
        let mut base = P::claim(mem::take(&mut self.base).unwrap());
        assert!(base
            .tree
            .extend_digests(
                &base.parameters,
                Fork::<C, T, P, M>::extract_leaves(base_contribution, branch),
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

impl<C, T, P> AsRef<MerkleTree<C, T>> for Trunk<C, T, P>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
    P: raw::MerkleTreePointerFamily<C, T>,
{
    #[inline]
    fn as_ref(&self) -> &MerkleTree<C, T> {
        self.borrow_base().as_ref()
    }
}

impl<C, T, P> Borrow<MerkleTree<C, T>> for Trunk<C, T, P>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
    P: raw::MerkleTreePointerFamily<C, T>,
{
    #[inline]
    fn borrow(&self) -> &MerkleTree<C, T> {
        self.borrow_base().borrow()
    }
}

impl<C, T, P> Deref for Trunk<C, T, P>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
    P: raw::MerkleTreePointerFamily<C, T>,
{
    type Target = MerkleTree<C, T>;

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
pub struct Fork<C, T, P = raw::SingleThreaded, M = BTreeMap<C>>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
    P: raw::MerkleTreePointerFamily<C, T>,
    M: InnerMap<C> + Default,
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
    P: raw::MerkleTreePointerFamily<C, T>,
    M: InnerMap<C> + Default,
{
    /// Builds a new [`Fork`] from `trunk`.
    #[inline]
    pub fn new(trunk: &Trunk<C, T, P>) -> Self {
        Self::with_leaves(trunk, Default::default()).unwrap()
    }

    /// Builds a new [`Fork`] from `trunk` extended by `leaf_digests`, returning `None` if
    /// appending `leaf_digests` would exceed the capacity of the `trunk`.
    #[inline]
    pub fn with_leaves(trunk: &Trunk<C, T, P>, leaf_digests: Vec<LeafDigest<C>>) -> Option<Self> {
        let (base_contribution, branch) =
            Self::new_branch(trunk.borrow_base().as_ref(), leaf_digests)?;
        Some(Self {
            base: trunk.downgrade(),
            base_contribution,
            branch,
        })
    }

    /// Builds a new branch off of `base`, extending by `leaf_digests`.
    #[inline]
    fn new_branch(
        base: &MerkleTree<C, T>,
        leaf_digests: Vec<LeafDigest<C>>,
    ) -> Option<(BaseContribution, Partial<C, M>)> {
        if leaf_digests.len() + base.len() >= capacity::<C>() {
            return None;
        }
        Some(Self::new_branch_unchecked(base, leaf_digests))
    }

    /// Builds a new branch off of `base`, extending by `leaf_digests` without checking that
    /// `base` can accept new leaves.
    #[inline]
    fn new_branch_unchecked(
        base: &MerkleTree<C, T>,
        leaf_digests: Vec<LeafDigest<C>>,
    ) -> (BaseContribution, Partial<C, M>) {
        let (base_contribution, base_inner_digest, base_leaf_digests, inner_path) =
            Self::generate_branch_setup(base);
        let mut partial = Partial::new_unchecked(
            base_leaf_digests,
            PartialInnerTree::from_current(&base.parameters, base_inner_digest, inner_path),
        );
        let partial_tree_len = partial.len();
        for (i, digest) in leaf_digests.into_iter().enumerate() {
            partial.push_leaf_digest(&base.parameters, Node(partial_tree_len + i), digest);
        }
        (base_contribution, partial)
    }

    /// Generates the setup data to compute [`new_branch_unchecked`](Self::new_branch_unchecked).
    #[inline]
    fn generate_branch_setup(
        base: &MerkleTree<C, T>,
    ) -> (
        BaseContribution,
        InnerDigest<C>,
        Vec<LeafDigest<C>>,
        CurrentInnerPath<C>,
    ) {
        if base.is_empty() {
            (
                BaseContribution::Empty,
                Default::default(),
                Default::default(),
                base.current_path().inner_path,
            )
        } else {
            let current_leaf = base.current_leaf();
            let current_path = base.current_path();
            match current_path.leaf_index().parity() {
                Parity::Left => (
                    BaseContribution::LeftLeaf,
                    base.parameters
                        .join_leaves(&current_leaf, &current_path.sibling_digest),
                    vec![current_leaf],
                    current_path.inner_path,
                ),
                Parity::Right => (
                    BaseContribution::BothLeaves,
                    base.parameters
                        .join_leaves(&current_path.sibling_digest, &current_leaf),
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
    ) -> Vec<LeafDigest<C>> {
        let mut leaf_digests = branch.into_leaves();
        mem::drop(leaf_digests.drain(0..base_contribution as usize));
        leaf_digests
    }

    /// Tries to rebase `branch` at `base`.
    #[inline]
    fn try_rebase(
        base: &MerkleTree<C, T>,
        base_contribution: &mut BaseContribution,
        branch: &mut Partial<C, M>,
    ) -> bool {
        if branch.len() + base.len() - (*base_contribution as usize) >= capacity::<C>() {
            return false;
        }
        let (new_base_contribution, new_branch) = Self::new_branch_unchecked(
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
    pub fn attach(&mut self, trunk: &Trunk<C, T, P>) -> bool {
        if !Self::try_rebase(
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
    pub fn push(&mut self, leaf: &Leaf<C>) -> Option<bool> {
        Some(
            self.branch
                .push(&P::upgrade(&self.base)?.as_ref().parameters, leaf),
        )
    }
}

/// Raw Forking Primitives
pub mod raw {
    use super::*;
    use alloc::{
        rc::{Rc, Weak as WeakRc},
        sync::{Arc, Weak as WeakArc},
    };
    use manta_util::{create_seal, seal};

    create_seal! {}

    /// Merkle Tree Pointer Family
    pub trait MerkleTreePointerFamily<C, T>: sealed::Sealed
    where
        C: Configuration + ?Sized,
        T: Tree<C>,
    {
        /// Strong Pointer
        type Strong: AsRef<MerkleTree<C, T>>
            + Borrow<MerkleTree<C, T>>
            + Deref<Target = MerkleTree<C, T>>;

        /// Weak Pointer
        type Weak;

        /// Returns a new strong pointer holding `base`.
        fn new(base: MerkleTree<C, T>) -> Self::Strong;

        /// Claims ownership of the underlying merkle tree from `strong`.
        ///
        /// # Panics
        ///
        /// This method can only panic if there are other outstanding strong pointers. This method
        /// will still succeed if there are other outstanding weak pointers, but they will all be
        /// disassociated to `strong`.
        fn claim(strong: Self::Strong) -> MerkleTree<C, T>;

        /// Returns a new weak pointer to `strong`.
        fn downgrade(strong: &Self::Strong) -> Self::Weak;

        /// Tries to upgrade `weak` to a strong pointer, returning `None` if there is no strong
        /// pointer associated to `weak`.
        fn upgrade(weak: &Self::Weak) -> Option<Self::Strong>;

        /// Checks if two strong pointers point to the same allocation.
        fn strong_ptr_eq(lhs: &Self::Strong, rhs: &Self::Strong) -> bool;
    }

    /// Implements [`MerkleTreePointerFamily`] for `$type` with `$strong` and `$weak` pointers.
    macro_rules! impl_pointer_family {
        ($type:tt, $strong:ident, $weak:ident) => {
            seal!($type);
            impl<C, T> MerkleTreePointerFamily<C, T> for $type
            where
                C: Configuration + ?Sized,
                T: Tree<C>,
            {
                type Strong = $strong<MerkleTree<C, T>>;

                type Weak = $weak<MerkleTree<C, T>>;

                #[inline]
                fn new(base: MerkleTree<C, T>) -> Self::Strong {
                    $strong::new(base)
                }

                #[inline]
                fn claim(strong: Self::Strong) -> MerkleTree<C, T> {
                    $strong::try_unwrap(strong).ok().unwrap()
                }

                #[inline]
                fn downgrade(strong: &Self::Strong) -> Self::Weak {
                    $strong::downgrade(strong)
                }

                #[inline]
                fn upgrade(weak: &Self::Weak) -> Option<Self::Strong> {
                    weak.upgrade()
                }

                #[inline]
                fn strong_ptr_eq(lhs: &Self::Strong, rhs: &Self::Strong) -> bool {
                    $strong::ptr_eq(lhs, rhs)
                }
            }
        };
    }

    /// Single-Threaded Merkle Tree Pointer Family
    ///
    /// This is the pointer family for [`Rc`].
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct SingleThreaded;

    impl_pointer_family!(SingleThreaded, Rc, WeakRc);

    /// Thread-Safe Merkle Tree Pointer Family
    ///
    /// This is the pointer family for [`Arc`].
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct ThreadSafe;

    impl_pointer_family!(ThreadSafe, Arc, WeakArc);
}
