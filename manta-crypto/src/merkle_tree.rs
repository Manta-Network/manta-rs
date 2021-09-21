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

//! Merkle Trees

// TODO: The following optimizations/configurations must be possible:
//
//    1. Subtree Computation/Memoization
//    2. Root computation from only the past
//    3. Path computation from only the past
//    4. Incremental Update
//    5. Only store relevant history subset
//

extern crate alloc;

use alloc::{collections::BTreeMap, vec::Vec};
use core::{borrow::Borrow, convert::Infallible, fmt::Debug, hash::Hash, iter::Rev, ops::Range};

/// Merkle Tree Leaf Hash
pub trait LeafHash {
    /// Leaf Type
    type Leaf: ?Sized;

    /// Leaf Hash Parameters Type
    type Parameters;

    /// Leaf Hash Output Type
    type Output: Default;

    /// Computes the digest of the `leaf` using `parameters`.
    fn digest(parameters: &Self::Parameters, leaf: &Self::Leaf) -> Self::Output;
}

/// Merkle Tree Inner Hash
pub trait InnerHash {
    /// Leaf Hash Type
    type LeafHash: LeafHash;

    /// Inner Hash Parameters Type
    type Parameters;

    /// Inner Hash Output Type
    type Output: Default + PartialEq;

    /// Combines two inner digests into a new inner digest using `parameters`.
    fn join(parameters: &Self::Parameters, lhs: &Self::Output, rhs: &Self::Output) -> Self::Output;

    /// Combines two [`LeafHash`](Self::LeafHash) digests into an inner digest.
    fn join_leaves(
        parameters: &Self::Parameters,
        lhs: &<Self::LeafHash as LeafHash>::Output,
        rhs: &<Self::LeafHash as LeafHash>::Output,
    ) -> Self::Output;
}

/// Merkle Tree Configuration
pub trait Configuration {
    /// Leaf Hash Type
    type LeafHash: LeafHash;

    /// Inner Hash Type
    type InnerHash: InnerHash<LeafHash = Self::LeafHash>;

    /// Merkle Tree Structure Type
    type Tree: Tree<Self>;

    /// Height Type
    type Height: Copy + Into<usize>;

    /// Fixed Height of the Merkle Tree
    const HEIGHT: Self::Height;
}

/// Leaf Type
pub type Leaf<C> = <<C as Configuration>::LeafHash as LeafHash>::Leaf;

/// Leaf Hash Parameters Type
pub type LeafHashParamters<C> = <<C as Configuration>::LeafHash as LeafHash>::Parameters;

/// Leaf Hash Digest Type
pub type LeafDigest<C> = <<C as Configuration>::LeafHash as LeafHash>::Output;

/// Inner Hash Parameters Type
pub type InnerHashParameters<C> = <<C as Configuration>::InnerHash as InnerHash>::Parameters;

/// Inner Hash Digest Type
pub type InnerDigest<C> = <<C as Configuration>::InnerHash as InnerHash>::Output;

/// Merkle Tree Root Type
pub type Root<C> = InnerDigest<C>;

/// Returns the capacity of the merkle tree with the given [`C::HEIGHT`](Configuration::HEIGHT)
/// parameter.
#[inline]
pub fn capacity<C>() -> usize
where
    C: Configuration + ?Sized,
{
    1usize << (C::HEIGHT.into() - 1)
}

/// Returns the path length of the merkle tree with the given [`C::HEIGHT`](Configuration::HEIGHT)
/// parameter.
#[inline]
pub fn path_length<C>() -> usize
where
    C: Configuration + ?Sized,
{
    C::HEIGHT.into() - 2
}

/// Returns an iterator over the depth of an inner path in reverse order, from the leaves of the
/// tree to the root.
#[inline]
pub fn path_iter<C>() -> Rev<Range<usize>>
where
    C: Configuration + ?Sized,
{
    (0..path_length::<C>()).into_iter().rev()
}

/// Merkle Tree Structure
pub trait Tree<C>: Sized
where
    C: Configuration + ?Sized,
{
    /// Path Query Type
    type Query;

    /// Path Error Type
    type Error;

    /// Builds a new merkle tree.
    fn new(parameters: &Parameters<C>) -> Self;

    /// Builds a new merkle tree with the given `leaves`.
    #[inline]
    fn from_leaves<L>(parameters: &Parameters<C>, leaves: L) -> Option<Self>
    where
        L: IntoIterator<Item = LeafDigest<C>>,
    {
        let leaves = leaves.into_iter();
        if leaves.size_hint().0 > capacity::<C>() {
            return None;
        }
        let mut tree = Self::new(parameters);
        for leaf in leaves {
            if !tree.append(parameters, leaf) {
                return None;
            }
        }
        Some(tree)
    }

    /// Returns the length of `self`.
    fn len(&self) -> usize;

    /// Returns `true` if the length of `self` is zero.
    #[inline]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the [`Root`] of the merkle tree.
    fn root(&self, parameters: &Parameters<C>) -> Root<C>;

    /// Returns the [`Path`] to some element of the merkle tree given by the `query`.
    fn path(&self, parameters: &Parameters<C>, query: Self::Query) -> Result<Path<C>, Self::Error>;

    /// Inserts `leaf_digest` at the next avaiable leaf node of the tree, returning `false` if the
    /// leaf could not be inserted because the tree has exhausted its capacity.
    fn append(&mut self, parameters: &Parameters<C>, leaf_digest: LeafDigest<C>) -> bool;
}

/// Full Merkle Tree Backing Structure
pub struct FullTree<C>
where
    C: Configuration + ?Sized,
{
    /// Leaf Digests
    leaf_digests: Vec<LeafDigest<C>>,

    /// Inner Digests
    inner_digests: BTreeMap<usize, InnerDigest<C>>,
}

impl<C> FullTree<C>
where
    C: Configuration + ?Sized,
{
    /// Returns the sibling leaf node to `index`.
    #[inline]
    fn sibling_leaf(&self, index: Node) -> Option<&LeafDigest<C>> {
        self.leaf_digests.get(index.sibling().0)
    }

    /// Computes the index into the `inner_digests` map for a node of the given `depth` and `index`.
    #[inline]
    fn inner_digest_index(depth: usize, index: Node) -> usize {
        (1 << (depth + 1)) + index.0 - 1
    }

    /// Returns the inner digest at the given `depth` and `index` of the merkle tree.
    ///
    /// # Note
    ///
    /// The `depth` of the tree tracks the inner nodes not including the root. The root of the tree
    /// is at `depth := -1` and `index := 0`.
    #[inline]
    fn get_inner_digest(&self, depth: usize, index: Node) -> Option<&InnerDigest<C>> {
        self.inner_digests
            .get(&Self::inner_digest_index(depth, index))
    }

    /// Sets the inner digest at the given `depth` and `index` of the merkle tree to the
    /// `inner_digest` value.
    ///
    /// # Note
    ///
    /// The `depth` of the tree tracks the inner nodes not including the root. The root of the tree
    /// is at `depth := -1` and `index := 0`.
    #[inline]
    fn set_inner_digest(&mut self, depth: usize, index: Node, inner_digest: InnerDigest<C>) {
        self.inner_digests
            .insert(Self::inner_digest_index(depth, index), inner_digest);
    }

    /// Computes the inner path of a node starting at the leaf given by `index`.
    #[inline]
    fn compute_inner_path(&self, mut index: Node) -> Vec<InnerDigest<C>>
    where
        InnerDigest<C>: Clone,
    {
        path_iter::<C>()
            .map(move |depth| {
                self.get_inner_digest(depth, index.into_parent().sibling())
                    .map(Clone::clone)
                    .unwrap_or_default()
            })
            .collect()
    }

    /// Computes the root of the merkle tree, modifying the inner tree in-place, starting at the
    /// leaf given by `index`.
    #[inline]
    fn compute_root(
        &mut self,
        parameters: &Parameters<C>,
        mut index: Node,
        base: InnerDigest<C>,
    ) -> Root<C>
    where
        InnerDigest<C>: Clone,
    {
        path_iter::<C>().fold(base, |acc, depth| {
            self.set_inner_digest(depth, index.into_parent(), acc.clone());
            index.join(
                parameters,
                &acc,
                self.get_inner_digest(depth, index.sibling())
                    .unwrap_or(&Default::default()),
            )
        })
    }
}

impl<C> Tree<C> for FullTree<C>
where
    C: Configuration + ?Sized,
    LeafDigest<C>: Clone,
    InnerDigest<C>: Clone,
{
    type Query = usize;

    type Error = ();

    #[inline]
    fn new(parameters: &Parameters<C>) -> Self {
        let _ = parameters;
        Self {
            leaf_digests: Default::default(),
            inner_digests: Default::default(),
        }
    }

    #[inline]
    fn len(&self) -> usize {
        self.leaf_digests.len()
    }

    #[inline]
    fn root(&self, parameters: &Parameters<C>) -> Root<C> {
        let _ = parameters;
        self.inner_digests
            .get(&0)
            .map(Clone::clone)
            .unwrap_or_default()
    }

    #[inline]
    fn path(&self, parameters: &Parameters<C>, query: Self::Query) -> Result<Path<C>, Self::Error> {
        let _ = parameters;
        if query > capacity::<C>() {
            return Err(());
        }
        let leaf_index = Node(query);
        Ok(Path::new(
            leaf_index,
            self.sibling_leaf(leaf_index)
                .map(Clone::clone)
                .unwrap_or_default(),
            self.compute_inner_path(leaf_index),
        ))
    }

    #[inline]
    fn append(&mut self, parameters: &Parameters<C>, leaf_digest: LeafDigest<C>) -> bool {
        let len = self.len();
        if len >= capacity::<C>() {
            return false;
        }
        let leaf_index = Node(len);
        let root = self.compute_root(
            parameters,
            leaf_index,
            leaf_index.join_leaves(
                parameters,
                &leaf_digest,
                self.sibling_leaf(leaf_index).unwrap_or(&Default::default()),
            ),
        );
        self.inner_digests.insert(0, root);
        self.leaf_digests.push(leaf_digest);
        true
    }
}

/// Latest Node Merkle Tree Backing Structure
pub struct LatestNodeTree<C>
where
    C: Configuration + ?Sized,
{
    /// Leaf Digest
    leaf_digest: Option<LeafDigest<C>>,

    /// Path
    path: Path<C>,

    /// Root
    root: Root<C>,
}

impl<C> LatestNodeTree<C>
where
    C: Configuration + ?Sized,
{
    /// Returns the number of leaves in the merkle tree.
    #[inline]
    fn len(&self) -> usize {
        if self.leaf_digest.is_none() {
            0
        } else {
            self.path.leaf_node_index.0 + 1
        }
    }

    /// Returns the next avaiable index or `None` if the merkle tree is full.
    #[inline]
    fn next_index(&self) -> Option<Node> {
        let len = self.len();
        if len == 0 {
            Some(Node(0))
        } else if len < capacity::<C>() - 1 {
            Some(Node(len + 1))
        } else {
            None
        }
    }
}

impl<C> Tree<C> for LatestNodeTree<C>
where
    C: Configuration + ?Sized,
    Root<C>: Clone,
    Path<C>: Clone,
{
    type Query = ();

    type Error = Infallible;

    #[inline]
    fn new(parameters: &Parameters<C>) -> Self {
        let _ = parameters;
        Self {
            leaf_digest: Default::default(),
            path: Default::default(),
            root: Default::default(),
        }
    }

    #[inline]
    fn len(&self) -> usize {
        self.len()
    }

    #[inline]
    fn root(&self, parameters: &Parameters<C>) -> Root<C> {
        let _ = parameters;
        self.root.clone()
    }

    #[inline]
    fn path(&self, parameters: &Parameters<C>, query: Self::Query) -> Result<Path<C>, Self::Error> {
        let _ = (parameters, query);
        Ok(self.path.clone())
    }

    #[inline]
    fn append(&mut self, parameters: &Parameters<C>, leaf_digest: LeafDigest<C>) -> bool {
        let index = match self.next_index() {
            Some(index) => index,
            _ => return false,
        };

        if index.is_zero() {
            self.root = self.path.root_relative_to(parameters, &leaf_digest);
            self.leaf_digest = Some(leaf_digest);
        } else {
            todo!()
        }

        true
    }
}

/// Left or Right Side of a Subtree
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Parity {
    /// Left Side of the Subtree
    Left,

    /// Right Side of the Subtree
    Right,
}

impl Default for Parity {
    #[inline]
    fn default() -> Self {
        Self::Left
    }
}

impl Parity {
    /// Computes the [`Parity`] of the given `index`.
    #[inline]
    pub const fn from_index(index: usize) -> Self {
        if index % 2 == 0 {
            Self::Left
        } else {
            Self::Right
        }
    }

    /// Returns `true` if `self` represents the left side of a subtree.
    #[inline]
    pub const fn is_left(&self) -> bool {
        matches!(self, Self::Left)
    }

    /// Returns `true` if `self` represents the right side of a subtree.
    #[inline]
    pub const fn is_right(&self) -> bool {
        matches!(self, Self::Right)
    }
}

/// Node Index
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Node(pub usize);

impl Node {
    /// Returns `true` if `self` is the left-most index.
    #[inline]
    pub const fn is_zero(&self) -> bool {
        self.0 == 0
    }

    /// Returns the [`Parity`] of this node.
    #[inline]
    pub const fn parity(&self) -> Parity {
        Parity::from_index(self.0)
    }

    /// Returns the [`Node`] which is the sibling to `self`.
    #[inline]
    pub const fn sibling(&self) -> Self {
        match self.parity() {
            Parity::Left => Self(self.0 + 1),
            Parity::Right => Self(self.0 - 1),
        }
    }

    /// Returns the parent [`Node`] of this node.
    #[inline]
    pub const fn parent(&self) -> Self {
        Self(self.0 >> 1)
    }

    /// Converts `self` into its parent, returning the parent [`Node`].
    #[inline]
    pub fn into_parent(&mut self) -> Self {
        *self = self.parent();
        *self
    }

    /// Combines two inner digests into a new inner digest using `parameters`, swapping the order
    /// of `lhs` and `rhs` depending on the location of `self` in its subtree.
    #[inline]
    pub fn join<C>(
        &self,
        parameters: &Parameters<C>,
        lhs: &InnerDigest<C>,
        rhs: &InnerDigest<C>,
    ) -> InnerDigest<C>
    where
        C: Configuration + ?Sized,
    {
        match self.parity() {
            Parity::Left => C::InnerHash::join(&parameters.inner, lhs, rhs),
            Parity::Right => C::InnerHash::join(&parameters.inner, rhs, lhs),
        }
    }

    /// Combines two leaf digests into a new inner digest using `parameters`, swapping the order
    /// of `lhs` and `rhs` depending on the location of `self` in its subtree.
    #[inline]
    pub fn join_leaves<C>(
        &self,
        parameters: &Parameters<C>,
        lhs: &LeafDigest<C>,
        rhs: &LeafDigest<C>,
    ) -> InnerDigest<C>
    where
        C: Configuration + ?Sized,
    {
        match self.parity() {
            Parity::Left => {
                C::InnerHash::join_leaves(&parameters.inner, lhs.borrow(), rhs.borrow())
            }
            Parity::Right => {
                C::InnerHash::join_leaves(&parameters.inner, rhs.borrow(), lhs.borrow())
            }
        }
    }
}

impl From<Node> for usize {
    #[inline]
    fn from(index: Node) -> Self {
        index.0
    }
}

impl From<usize> for Node {
    #[inline]
    fn from(index: usize) -> Self {
        Self(index)
    }
}

/// Merkle Tree Parameters
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "LeafHashParamters<C>: Clone, InnerHashParameters<C>: Clone"),
    Copy(bound = "LeafHashParamters<C>: Copy, InnerHashParameters<C>: Copy"),
    Debug(bound = "LeafHashParamters<C>: Debug, InnerHashParameters<C>: Debug"),
    Default(bound = "LeafHashParamters<C>: Default, InnerHashParameters<C>: Default"),
    Eq(bound = "LeafHashParamters<C>: Eq, InnerHashParameters<C>: Eq"),
    Hash(bound = "LeafHashParamters<C>: Hash, InnerHashParameters<C>: Hash"),
    PartialEq(bound = "LeafHashParamters<C>: PartialEq, InnerHashParameters<C>: PartialEq")
)]
pub struct Parameters<C>
where
    C: Configuration + ?Sized,
{
    /// Leaf Hash Parameters
    pub leaf: LeafHashParamters<C>,

    /// Inner Hash Parameters
    pub inner: InnerHashParameters<C>,
}

impl<C> Parameters<C>
where
    C: Configuration + ?Sized,
{
    /// Computes the leaf digest of `leaf` using `self`.
    #[inline]
    pub fn digest(&self, leaf: &Leaf<C>) -> LeafDigest<C> {
        C::LeafHash::digest(&self.leaf, leaf)
    }

    /// Combines two inner digests into a new inner digest using `self`.
    #[inline]
    pub fn join(&self, lhs: &InnerDigest<C>, rhs: &InnerDigest<C>) -> InnerDigest<C> {
        C::InnerHash::join(&self.inner, lhs, rhs)
    }

    /// Combines two leaf digests into a new inner digest using `self`.
    #[inline]
    pub fn join_leaves(&self, lhs: &LeafDigest<C>, rhs: &LeafDigest<C>) -> InnerDigest<C> {
        C::InnerHash::join_leaves(&self.inner, lhs, rhs)
    }
}

/// Merkle Tree Path
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "LeafDigest<C>: Clone, InnerDigest<C>: Clone"),
    Debug(bound = "LeafDigest<C>: Debug, InnerDigest<C>: Debug"),
    Eq(bound = "LeafDigest<C>: Eq, InnerDigest<C>: Eq"),
    Hash(bound = "LeafDigest<C>: Hash, InnerDigest<C>: Hash"),
    PartialEq(bound = "LeafDigest<C>: PartialEq, InnerDigest<C>: PartialEq")
)]
pub struct Path<C>
where
    C: Configuration + ?Sized,
{
    /// Leaf Node Index
    leaf_node_index: Node,

    /// Sibling Digest
    sibling_digest: LeafDigest<C>,

    /// Inner Path
    ///
    /// The inner path is stored in the direction leaf-to-root.
    inner_path: Vec<InnerDigest<C>>,
}

impl<C> Path<C>
where
    C: Configuration + ?Sized,
{
    /// Builds a new [`Path`] from `leaf_node_index`, `sibling_digest`, and `inner_path`.
    #[inline]
    pub fn new(
        leaf_node_index: Node,
        sibling_digest: LeafDigest<C>,
        inner_path: Vec<InnerDigest<C>>,
    ) -> Self {
        Self {
            leaf_node_index,
            sibling_digest,
            inner_path,
        }
    }

    /// Computes the root of the merkle tree relative to `leaf_digest` using `parameters`.
    #[inline]
    pub fn root_relative_to(
        &self,
        parameters: &Parameters<C>,
        leaf_digest: &LeafDigest<C>,
    ) -> Root<C> {
        let mut node_index = self.leaf_node_index;
        self.inner_path.iter().fold(
            node_index.join_leaves(parameters, leaf_digest, &self.sibling_digest),
            move |acc, d| node_index.into_parent().join(parameters, &acc, d),
        )
    }

    /// Returns `true` if `self` is a witness to the fact that `leaf` is stored in a merkle tree
    /// with the given `root`.
    #[inline]
    pub fn is_valid(&self, parameters: &Parameters<C>, root: &Root<C>, leaf: &Leaf<C>) -> bool {
        root == &self.root_relative_to(parameters, &parameters.digest(leaf))
    }
}

impl<C> Default for Path<C>
where
    C: Configuration + ?Sized,
{
    #[inline]
    fn default() -> Self {
        let path_length = path_length::<C>();
        let mut inner_path = Vec::with_capacity(path_length);
        inner_path.resize_with(path_length, InnerDigest::<C>::default);
        Self::new(Default::default(), Default::default(), inner_path)
    }
}

/// Merkle Tree
pub struct MerkleTree<C>
where
    C: Configuration + ?Sized,
{
    /// Merkle Tree Parameters
    parameters: Parameters<C>,

    /// Underlying Tree Structure
    tree: C::Tree,
}

impl<C> MerkleTree<C>
where
    C: Configuration + ?Sized,
{
    /// Builds a new [`MerkleTree`].
    #[inline]
    pub fn new(parameters: Parameters<C>) -> Self {
        Self {
            tree: C::Tree::new(&parameters),
            parameters,
        }
    }

    /// Builds a new merkle tree with the given `leaves`.
    #[inline]
    pub fn from_leaves<'l, L>(parameters: Parameters<C>, leaves: L) -> Option<Self>
    where
        Leaf<C>: 'l,
        L: IntoIterator<Item = &'l Leaf<C>>,
    {
        Some(Self {
            tree: C::Tree::from_leaves(
                &parameters,
                leaves.into_iter().map(|l| parameters.digest(l)),
            )?,
            parameters,
        })
    }

    ///
    #[inline]
    pub fn parameters(&self) -> &Parameters<C> {
        &self.parameters
    }

    /// Returns the [`Root`] of the merkle tree.
    #[inline]
    pub fn root(&self) -> Root<C> {
        self.tree.root(&self.parameters)
    }

    /// Returns the [`Path`] to some element of the merkle tree given by the `query`.
    #[inline]
    pub fn path(
        &self,
        query: <C::Tree as Tree<C>>::Query,
    ) -> Result<Path<C>, <C::Tree as Tree<C>>::Error> {
        self.tree.path(&self.parameters, query)
    }

    /// Inserts `leaf` at the next avaiable leaf node of the tree, returning `false` if the
    /// leaf could not be inserted because the tree has exhausted its capacity.
    #[inline]
    pub fn append(&mut self, leaf: &Leaf<C>) -> bool {
        self.tree
            .append(&self.parameters, self.parameters.digest(leaf))
    }
}
