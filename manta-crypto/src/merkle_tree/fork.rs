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

extern crate alloc;

use crate::merkle_tree::{
    capacity, inner_tree::InnerTree, Configuration, GetPath, GetPathError, InnerDigest, Leaf,
    LeafDigest, MerkleTree, Path, Root, Tree,
};
use alloc::vec::Vec;
use core::{fmt::Debug, hash::Hash, mem};

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
    /// This function automatically detaches all of the forks associated to this trunk. To
    /// attach them to another trunk, use [`Fork::attach`].
    #[inline]
    pub fn into_tree(self) -> MerkleTree<C, T> {
        P::claim(self.base.unwrap())
    }

    /// Creates a new fork of this trunk.
    #[inline]
    pub fn fork(&self) -> Fork<C, T, P> {
        Fork::new(self)
    }

    /// Attaches `fork` to `self` as its new trunk.
    #[inline]
    pub fn attach(&self, fork: &mut Fork<C, T, P>) {
        fork.attach(self)
    }

    /// Tries to merge `fork` onto `self`, returning `fork` back if it could not be merged.
    ///
    /// # Safety
    ///
    /// If the merge succeeds, this function automatically detaches all of the forks associated to
    /// this trunk. To attach them to another trunk, use [`Fork::attach`]. To attach them to this
    /// trunk, [`attach`](Self::attach) can also be used.
    ///
    /// Since merging will add leaves to the base tree, forks which were previously associated to
    /// this trunk will have to catch up. If [`Fork::attach`] or [`attach`](Self::attach) is used,
    /// the leaves which were added in this merge will exist before the first leaf in the fork in
    /// the final tree.
    #[inline]
    pub fn merge(&mut self, fork: Fork<C, T, P>) -> Result<(), Fork<C, T, P>> {
        match fork.get_attached_base(self) {
            Some(base) => {
                self.merge_branch(base, fork.branch);
                Ok(())
            }
            _ => Err(fork),
        }
    }

    /// Performs a merge of the `branch` onto `fork_base`, setting `self` equal to the resulting
    /// merged tree.
    #[inline]
    fn merge_branch(&mut self, fork_base: P::Strong, branch: Branch<C>) {
        self.base = Some(fork_base);
        let mut base = P::claim(mem::take(&mut self.base).unwrap());
        branch.merge(&mut base);
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

/// Merkle Tree Fork
pub struct Fork<C, T, P = raw::SingleThreaded>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
    P: raw::MerkleTreePointerFamily<C, T>,
{
    /// Base Merkle Tree
    base: P::Weak,

    /// Branch Data
    branch: Branch<C>,
}

impl<C, T, P> Fork<C, T, P>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
    P: raw::MerkleTreePointerFamily<C, T>,
{
    /// Builds a new [`Fork`] from `trunk`.
    #[inline]
    pub fn new(trunk: &Trunk<C, T, P>) -> Self {
        Self::with_leaves(trunk, Default::default())
    }

    /// Builds a new [`Fork`] from `trunk` extended by `leaf_digests`
    #[inline]
    pub fn with_leaves(trunk: &Trunk<C, T, P>, leaf_digests: Vec<LeafDigest<C>>) -> Self {
        Self {
            base: trunk.downgrade(),
            branch: Branch::new(trunk.borrow_base().as_ref(), leaf_digests),
        }
    }

    /// Attaches this fork to a new `trunk`.
    #[inline]
    pub fn attach(&mut self, trunk: &Trunk<C, T, P>) {
        self.base = trunk.downgrade();
        self.branch.rebase(trunk.borrow_base().as_ref());
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
    ///
    /// Returns `None` if this fork has been detached from its trunk. Use [`attach`](Self::attach)
    /// to re-associate a trunk to this fork.
    #[inline]
    pub fn len(&self) -> Option<usize> {
        Some(P::upgrade(&self.base)?.as_ref().len() + self.branch.len())
    }

    /// Returns `true` if this fork is empty.
    ///
    /// Returns `None` if this fork has been detached from its trunk. Use [`attach`](Self::attach)
    /// to re-associate a trunk to this fork.
    #[inline]
    pub fn is_empty(&self) -> Option<bool> {
        Some(self.len()? == 0)
    }

    /// Computes the current root of this fork.
    ///
    /// Returns `None` if this fork has been detached from its trunk. Use [`attach`](Self::attach)
    /// to re-associate a trunk to this fork.
    #[inline]
    pub fn root(&self) -> Option<Root<C>> {
        Some(self.branch.root(P::upgrade(&self.base)?.as_ref()))
    }

    /// Appends a new `leaf` onto this fork.
    ///
    /// Returns `None` if this fork has been detached from its trunk. Use [`attach`](Self::attach)
    /// to re-associate a trunk to this fork.
    #[inline]
    pub fn push(&mut self, leaf: &Leaf<C>) -> Option<bool> {
        Some(self.branch.push(P::upgrade(&self.base)?.as_ref(), leaf))
    }
}

/* TODO:
/// Fork Path Error
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "GetPathError<C, T>: Clone"),
    Copy(bound = "GetPathError<C, T>: Copy"),
    Debug(bound = "GetPathError<C, T>: Debug"),
    Eq(bound = "GetPathError<C, T>: Eq"),
    Hash(bound = "GetPathError<C, T>: Hash"),
    PartialEq(bound = "GetPathError<C, T>: PartialEq")
)]
pub enum ForkGetPathError<C, T>
where
    C: Configuration + ?Sized,
    T: GetPath<C>,
{
    /// Trunk Path Query Error
    TrunkError(GetPathError<C, T>),

    /// Unknown Index on Branch Error
    UnknownIndexOnBranch,
}
*/

/// Merkle Tree Fork Branch
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "LeafDigest<C>: Clone, InnerDigest<C>: Clone"),
    Debug(bound = "LeafDigest<C>: Debug, InnerDigest<C>: Debug"),
    Default(bound = "LeafDigest<C>: Default, InnerDigest<C>: Default"),
    Eq(bound = "LeafDigest<C>: Eq, InnerDigest<C>: Eq"),
    Hash(bound = "LeafDigest<C>: Hash, InnerDigest<C>: Hash"),
    PartialEq(bound = "LeafDigest<C>: PartialEq, InnerDigest<C>: PartialEq")
)]
pub struct Branch<C>
where
    C: Configuration + ?Sized,
{
    /// Leaf Digests
    pub leaf_digests: Vec<LeafDigest<C>>,

    /// Inner Digests
    pub inner_digests: InnerTree<C>,
}

impl<C> Branch<C>
where
    C: Configuration + ?Sized,
{
    /// Builds a new [`Branch`] from `base` and `leaf_digests`.
    #[inline]
    fn new<T>(base: &MerkleTree<C, T>, leaf_digests: Vec<LeafDigest<C>>) -> Self
    where
        T: Tree<C>,
    {
        let mut this = Self {
            leaf_digests,
            inner_digests: Default::default(),
        };
        this.rebase(base);
        this
    }

    /// Restarts `self` at a new base.
    #[inline]
    fn rebase<T>(&mut self, base: &MerkleTree<C, T>)
    where
        T: Tree<C>,
    {
        todo!()
    }

    /// Computes the length of this branch.
    #[inline]
    pub fn len(&self) -> usize {
        self.leaf_digests.len()
    }

    /// Returns `true` if this branch is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Computes the root of the fork which has `self` as its branch and `base` as its base tree.
    #[inline]
    fn root<T>(&self, base: &MerkleTree<C, T>) -> Root<C>
    where
        T: Tree<C>,
    {
        todo!()
    }

    /// Appends a new `leaf` to this branch, recomputing the relevant inner digests relative to
    /// the `base` tree.
    #[inline]
    fn push<T>(&mut self, base: &MerkleTree<C, T>, leaf: &Leaf<C>) -> bool
    where
        T: Tree<C>,
    {
        if base.tree.len() + self.len() >= capacity::<C>() {
            return false;
        }

        todo!()
    }

    /// Merges `self` onto the `base` merkle tree.
    #[inline]
    fn merge<T>(self, base: &mut MerkleTree<C, T>)
    where
        T: Tree<C>,
    {
        base.tree.merge_branch(&base.parameters, MergeBranch(self))
    }
}

/// Fork Merge Branch
///
/// An type which can only be instantiated by the merkle tree forking implementation, which
/// prevents running [`Tree::merge_branch`] on arbitrary user-constructed [`Branch`] values.
pub struct MergeBranch<C>(Branch<C>)
where
    C: Configuration + ?Sized;

impl<C> From<MergeBranch<C>> for Branch<C>
where
    C: Configuration + ?Sized,
{
    #[inline]
    fn from(branch: MergeBranch<C>) -> Self {
        branch.0
    }
}

/// Raw Forking Primitives
pub mod raw {
    use super::*;
    use alloc::{
        rc::{Rc, Weak as WeakRc},
        sync::{Arc, Weak as WeakArc},
    };
    use core::borrow::Borrow;
    use manta_util::{create_seal, seal};

    create_seal! {}

    /// Merkle Tree Pointer Family
    pub trait MerkleTreePointerFamily<C, T>: sealed::Sealed
    where
        C: Configuration + ?Sized,
        T: Tree<C>,
    {
        /// Strong Pointer
        type Strong: AsRef<MerkleTree<C, T>> + Borrow<MerkleTree<C, T>>;

        /// Weak Pointer
        type Weak;

        /// Returns a new strong pointer holding `base`.
        fn new(base: MerkleTree<C, T>) -> Self::Strong;

        /// Claims ownership of the underlying merkle tree from `strong`.
        ///
        /// # Panics
        ///
        /// This function can only panic if there are other outstanding strong pointers. This
        /// function will still succeed if there are other outstanding weak pointers, but they will
        /// all be disassociated to `strong`.
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
