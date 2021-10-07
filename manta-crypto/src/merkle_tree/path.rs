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

//! Merkle Tree Paths

// TODO: Move some methods to a `raw` module for paths.

use crate::merkle_tree::{
    inner_tree::{InnerNode, InnerNodeIter},
    path_length, Configuration, InnerDigest, Leaf, LeafDigest, Node, Parameters, Parity, Root,
};
use alloc::vec::{self, Vec};
use core::{
    convert::{TryFrom, TryInto},
    fmt::Debug,
    hash::Hash,
    iter::FusedIterator,
    mem,
    ops::{Index, IndexMut},
    slice::SliceIndex,
};

pub(super) mod prelude {
    #[doc(inline)]
    pub use super::{CurrentPath, Path};
}

/// Merkle Tree Inner Path
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "InnerDigest<C>: Clone"),
    Debug(bound = "InnerDigest<C>: Debug"),
    Eq(bound = "InnerDigest<C>: Eq"),
    Hash(bound = "InnerDigest<C>: Hash"),
    PartialEq(bound = "InnerDigest<C>: PartialEq")
)]
pub struct InnerPath<C>
where
    C: Configuration + ?Sized,
{
    /// Leaf Index
    pub leaf_index: Node,

    /// Inner Digest Path
    ///
    /// Inner digests are stored from leaf to root, not including the root.
    pub path: Vec<InnerDigest<C>>,
}

impl<C> InnerPath<C>
where
    C: Configuration + ?Sized,
{
    /// Builds a new [`InnerPath`] from `leaf_index` and `path`.
    ///
    /// # Safety
    ///
    /// In order for paths to compute the correct root, they should always have a `path` with
    /// length given by [`path_length`].
    #[inline]
    pub fn new(leaf_index: Node, path: Vec<InnerDigest<C>>) -> Self {
        Self { leaf_index, path }
    }

    /// Checks if `self` could represent the [`CurrentInnerPath`] of some tree.
    #[inline]
    pub fn is_current(&self) -> bool {
        self.is_current_with(&Default::default())
    }

    /// Checks if `self` could represent the [`CurrentInnerPath`] of some tree, using `default`
    /// as the sentinel value.
    #[inline]
    pub fn is_current_with(&self, default: &InnerDigest<C>) -> bool {
        InnerNodeIter::from_leaf::<C>(self.leaf_index)
            .zip(self.path.iter())
            .all(move |(node, d)| match node.parity() {
                Parity::Left => d == default,
                Parity::Right => true,
            })
    }

    /// Computes the root of the merkle tree relative to `base` using `parameters`.
    #[inline]
    pub fn root_from_base(&self, parameters: &Parameters<C>, base: InnerDigest<C>) -> Root<C> {
        Self::fold(parameters, self.leaf_index, base, &self.path)
    }

    /// Computes the root of the merkle tree relative to `leaf_digest` and its `sibling_digest`
    /// using `parameters`.
    #[inline]
    pub fn root(
        &self,
        parameters: &Parameters<C>,
        leaf_digest: &LeafDigest<C>,
        sibling_digest: &LeafDigest<C>,
    ) -> Root<C> {
        self.root_from_base(
            parameters,
            self.leaf_index
                .join_leaves(parameters, leaf_digest, sibling_digest),
        )
    }

    /// Returns `true` if `self` is a witness to the fact that `leaf_digest` is stored in a
    /// merkle tree with the given `root` and `sibling_digest`.
    #[inline]
    pub fn verify_digest(
        &self,
        parameters: &Parameters<C>,
        root: &Root<C>,
        leaf_digest: &LeafDigest<C>,
        sibling_digest: &LeafDigest<C>,
    ) -> bool {
        root == &self.root(parameters, leaf_digest, sibling_digest)
    }

    /// Returns the folding algorithm for a path with `index` as its starting index.
    #[inline]
    fn fold_fn<'d>(
        parameters: &'d Parameters<C>,
        mut index: Node,
    ) -> impl 'd + FnMut(InnerDigest<C>, &'d InnerDigest<C>) -> InnerDigest<C> {
        move |acc, d| index.into_parent().join(parameters, &acc, d)
    }

    /// Folds `iter` into a root using the path folding algorithm for [`InnerPath`].
    #[inline]
    fn fold<'i, I>(
        parameters: &'i Parameters<C>,
        index: Node,
        base: InnerDigest<C>,
        iter: I,
    ) -> Root<C>
    where
        InnerDigest<C>: 'i,
        I: IntoIterator<Item = &'i InnerDigest<C>>,
    {
        Root(
            iter.into_iter()
                .fold(base, Self::fold_fn(parameters, index)),
        )
    }
}

impl<C> Default for InnerPath<C>
where
    C: Configuration + ?Sized,
{
    #[inline]
    fn default() -> Self {
        let path_length = path_length::<C>();
        let mut path = Vec::with_capacity(path_length);
        path.resize_with(path_length, InnerDigest::<C>::default);
        Self::new(Default::default(), path)
    }
}

impl<C> From<Path<C>> for InnerPath<C>
where
    C: Configuration + ?Sized,
{
    #[inline]
    fn from(path: Path<C>) -> Self {
        path.inner_path
    }
}

impl<C> From<CurrentInnerPath<C>> for InnerPath<C>
where
    C: Configuration + ?Sized,
{
    #[inline]
    fn from(path: CurrentInnerPath<C>) -> Self {
        InnerPath::new(path.leaf_index, path.into_iter().collect())
    }
}

impl<C, I> Index<I> for InnerPath<C>
where
    C: Configuration + ?Sized,
    I: SliceIndex<[InnerDigest<C>]>,
{
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        &self.path[index]
    }
}

impl<C, I> IndexMut<I> for InnerPath<C>
where
    C: Configuration + ?Sized,
    I: SliceIndex<[InnerDigest<C>]>,
{
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        &mut self.path[index]
    }
}

/// Merkle Tree Current Inner Path
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "InnerDigest<C>: Clone"),
    Debug(bound = "InnerDigest<C>: Debug"),
    Default(bound = ""),
    Eq(bound = "InnerDigest<C>: Eq"),
    Hash(bound = "InnerDigest<C>: Hash"),
    PartialEq(bound = "InnerDigest<C>: PartialEq")
)]
pub struct CurrentInnerPath<C>
where
    C: Configuration + ?Sized,
{
    /// Leaf Index
    pub leaf_index: Node,

    /// Inner Digest Path
    ///
    /// Inner digests are stored from leaf to root, not including the root.
    ///
    /// For [`CurrentInnerPath`], only non-default inner digests are stored in the `path`.
    pub path: Vec<InnerDigest<C>>,
}

impl<C> CurrentInnerPath<C>
where
    C: Configuration + ?Sized,
{
    /// Builds a new [`CurrentInnerPath`] from `leaf_index` and `path`.
    ///
    /// # Safety
    ///
    /// In order for paths to compute the correct root, they should always have a `path` with
    /// length given by [`path_length`]. For [`CurrentInnerPath`], we also have the invariant
    /// that any right-siblings on the path, which can only be a sentinel value, are not stored.
    /// This function assumes that this is the case for `path`.
    #[inline]
    pub fn new(leaf_index: Node, path: Vec<InnerDigest<C>>) -> Self {
        Self { leaf_index, path }
    }

    /// Builds a new [`CurrentInnerPath`] from an [`InnerPath`] without checking that `path`
    /// satisfies [`InnerPath::is_current`].
    #[inline]
    pub fn from_path_unchecked(path: InnerPath<C>) -> Self {
        Self::from_path_unchecked_with(path, &Default::default())
    }

    /// Builds a new [`CurrentInnerPath`] from an [`InnerPath`] without checking that `path`
    /// satisfies [`InnerPath::is_current_with`] against `default`.
    #[inline]
    pub fn from_path_unchecked_with(mut path: InnerPath<C>, default: &InnerDigest<C>) -> Self {
        path.path.retain(|d| d != default);
        Self::new(path.leaf_index, path.path)
    }

    /// Computes the root of the merkle tree relative to `base` using `parameters`.
    #[inline]
    pub fn root_from_base(&self, parameters: &Parameters<C>, base: InnerDigest<C>) -> Root<C> {
        Self::fold(
            parameters,
            0,
            self.leaf_index,
            base,
            &Default::default(),
            &self.path,
        )
    }

    /// Computes the root of the merkle tree relative to `leaf_digest` and its `sibling_digest`
    /// using `parameters`.
    #[inline]
    pub fn root(
        &self,
        parameters: &Parameters<C>,
        leaf_digest: &LeafDigest<C>,
        sibling_digest: &LeafDigest<C>,
    ) -> Root<C> {
        self.root_from_base(
            parameters,
            self.leaf_index
                .join_leaves(parameters, leaf_digest, sibling_digest),
        )
    }

    /// Returns `true` if `self` is a witness to the fact that `leaf_digest` is stored in a
    /// merkle tree with the given `root` and `sibling_digest`.
    #[inline]
    pub fn verify_digest(
        &self,
        parameters: &Parameters<C>,
        root: &Root<C>,
        leaf_digest: &LeafDigest<C>,
        sibling_digest: &LeafDigest<C>,
    ) -> bool {
        root == &self.root(parameters, leaf_digest, sibling_digest)
    }

    /// Returns an iterator over the elements of [`self.path`](Self::path) as [`InnerNode`]
    /// objects, yielding elements of the path if they are not default.
    #[inline]
    pub fn into_nodes(self) -> CurrentInnerPathNodeIter<C> {
        CurrentInnerPathNodeIter::new(self)
    }

    /// Computes the folding algorithm for a path with `index` as its starting index.
    #[inline]
    fn fold_fn<'d, D>(
        parameters: &'d Parameters<C>,
        index: Node,
        accumulator: &'d InnerDigest<C>,
        default: &'d InnerDigest<C>,
        digest: D,
    ) -> InnerDigest<C>
    where
        D: FnOnce() -> &'d InnerDigest<C>,
    {
        match index.parity() {
            Parity::Left => parameters.join(accumulator, default),
            Parity::Right => parameters.join(digest(), accumulator),
        }
    }

    /// Folds `iter` into a root using the path folding algorithm for [`CurrentInnerPath`].
    #[inline]
    fn fold<'i, I>(
        parameters: &'i Parameters<C>,
        depth: usize,
        mut index: Node,
        base: InnerDigest<C>,
        default: &'i InnerDigest<C>,
        iter: I,
    ) -> Root<C>
    where
        InnerDigest<C>: 'i,
        I: IntoIterator<Item = &'i InnerDigest<C>>,
    {
        let mut iter = iter.into_iter().peekable();
        Root((depth..path_length::<C>()).fold(base, |acc, _| {
            Self::fold_fn(parameters, index.into_parent(), &acc, default, || {
                iter.next().unwrap()
            })
        }))
    }

    /// Updates `self` to the next current path with `next_leaf_digest`, updating `leaf_digest`
    /// and `sibling_digest` as needed.
    #[inline]
    fn update(
        &mut self,
        parameters: &Parameters<C>,
        leaf_digest: &mut LeafDigest<C>,
        sibling_digest: &mut LeafDigest<C>,
        next_leaf_digest: LeafDigest<C>,
    ) -> Root<C> {
        let mut last_index = self.leaf_index;
        let mut index = self.leaf_index + 1;
        self.leaf_index = index;
        match index.parity() {
            Parity::Left => {
                let mut last_accumulator = parameters.join_leaves(
                    &mem::take(sibling_digest),
                    &mem::replace(leaf_digest, next_leaf_digest),
                );

                let mut accumulator = parameters.join_leaves(leaf_digest, sibling_digest);

                let default_inner_digest = Default::default();

                let mut i = 0;
                let mut depth = 0;
                while !Node::are_siblings(&last_index.into_parent(), &index.into_parent()) {
                    last_accumulator = Self::fold_fn(
                        parameters,
                        last_index,
                        &last_accumulator,
                        &default_inner_digest,
                        || {
                            let next = &self.path[i];
                            i += 1;
                            next
                        },
                    );
                    accumulator = parameters.join(&accumulator, &default_inner_digest);
                    depth += 1;
                }

                mem::drop(self.path.drain(1..i));

                self.path[0] = last_accumulator;
                accumulator = parameters.join(&self.path[0], &accumulator);

                Self::fold(
                    parameters,
                    depth + 1,
                    index,
                    accumulator,
                    &default_inner_digest,
                    &self.path[1..],
                )
            }
            Parity::Right => {
                *sibling_digest = mem::replace(leaf_digest, next_leaf_digest);
                self.root(parameters, leaf_digest, sibling_digest)
            }
        }
    }
}

impl<C> From<CurrentPath<C>> for CurrentInnerPath<C>
where
    C: Configuration + ?Sized,
{
    #[inline]
    fn from(path: CurrentPath<C>) -> Self {
        path.inner_path
    }
}

impl<C> TryFrom<InnerPath<C>> for CurrentInnerPath<C>
where
    C: Configuration + ?Sized,
{
    type Error = InnerPath<C>;

    #[inline]
    fn try_from(path: InnerPath<C>) -> Result<Self, Self::Error> {
        let default = Default::default();
        if path.is_current_with(&default) {
            Ok(CurrentInnerPath::from_path_unchecked_with(path, &default))
        } else {
            Err(path)
        }
    }
}

impl<C> IntoIterator for CurrentInnerPath<C>
where
    C: Configuration + ?Sized,
{
    type Item = InnerDigest<C>;

    type IntoIter = CurrentInnerPathIntoIter<C>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        Self::IntoIter {
            current_path_iter: self.path.into_iter(),
            node_iter: InnerNodeIter::from_leaf::<C>(self.leaf_index),
        }
    }
}

/// Owning Iterator for [`CurrentInnerPath`]
pub struct CurrentInnerPathIntoIter<C>
where
    C: Configuration + ?Sized,
{
    /// Current Path Iterator
    current_path_iter: vec::IntoIter<InnerDigest<C>>,

    /// Inner Node Iterator
    node_iter: InnerNodeIter,
}

impl<C> Iterator for CurrentInnerPathIntoIter<C>
where
    C: Configuration + ?Sized,
{
    type Item = InnerDigest<C>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        Some(
            self.node_iter
                .next()?
                .parity()
                .right_or_default(|| self.current_path_iter.next().unwrap()),
        )
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.node_iter.size_hint()
    }
}

impl<C> ExactSizeIterator for CurrentInnerPathIntoIter<C> where C: Configuration + ?Sized {}

impl<C> FusedIterator for CurrentInnerPathIntoIter<C> where C: Configuration + ?Sized {}

/// [`InnerNode`] Iterator for [`CurrentInnerPath`]
pub struct CurrentInnerPathNodeIter<C>
where
    C: Configuration + ?Sized,
{
    /// Current Path Iterator
    current_path_iter: vec::IntoIter<InnerDigest<C>>,

    /// Inner Node Iterator
    node_iter: InnerNodeIter,
}

impl<C> CurrentInnerPathNodeIter<C>
where
    C: Configuration + ?Sized,
{
    /// Builds a new [`CurrentInnerPathNodeIter`] from a [`CurrentInnerPath`].
    #[inline]
    pub fn new(path: CurrentInnerPath<C>) -> Self {
        Self {
            current_path_iter: path.path.into_iter(),
            node_iter: InnerNodeIter::from_leaf::<C>(path.leaf_index),
        }
    }
}

impl<C> Iterator for CurrentInnerPathNodeIter<C>
where
    C: Configuration + ?Sized,
{
    type Item = (InnerNode, Option<InnerDigest<C>>);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let node = self.node_iter.next()?;
        Some((
            node,
            node.parity()
                .right_or_default(|| Some(self.current_path_iter.next().unwrap())),
        ))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.node_iter.size_hint()
    }
}

impl<C> ExactSizeIterator for CurrentInnerPathNodeIter<C> where C: Configuration + ?Sized {}

impl<C> FusedIterator for CurrentInnerPathNodeIter<C> where C: Configuration + ?Sized {}

/// Merkle Tree Path
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "LeafDigest<C>: Clone, InnerDigest<C>: Clone"),
    Debug(bound = "LeafDigest<C>: Debug, InnerDigest<C>: Debug"),
    Default(bound = ""),
    Eq(bound = "LeafDigest<C>: Eq, InnerDigest<C>: Eq"),
    Hash(bound = "LeafDigest<C>: Hash, InnerDigest<C>: Hash"),
    PartialEq(bound = "LeafDigest<C>: PartialEq, InnerDigest<C>: PartialEq")
)]
pub struct Path<C>
where
    C: Configuration + ?Sized,
{
    /// Sibling Digest
    pub sibling_digest: LeafDigest<C>,

    /// Inner Path
    pub inner_path: InnerPath<C>,
}

impl<C> Path<C>
where
    C: Configuration + ?Sized,
{
    /// Builds a new [`Path`] from `sibling_digest`, `leaf_index`, and `path`.
    ///
    /// # Safety
    ///
    /// See [`InnerPath::new`] for the invariants on `path` assumed by this function.
    #[inline]
    pub fn new(sibling_digest: LeafDigest<C>, leaf_index: Node, path: Vec<InnerDigest<C>>) -> Self {
        Self::from_inner(sibling_digest, InnerPath::new(leaf_index, path))
    }

    /// Builds a new [`Path`] from `sibling_digest` and `inner_path`.
    #[inline]
    pub fn from_inner(sibling_digest: LeafDigest<C>, inner_path: InnerPath<C>) -> Self {
        Self {
            sibling_digest,
            inner_path,
        }
    }

    /// Returns the leaf index for this [`Path`].
    #[inline]
    pub fn leaf_index(&self) -> Node {
        self.inner_path.leaf_index
    }

    /// Checks if `self` could represent the [`CurrentPath`] of some tree.
    #[inline]
    pub fn is_current(&self) -> bool {
        self.is_current_with(&Default::default())
    }

    /// Checks if `self` could represent the [`CurrentPath`] of some tree, using `default` as the
    /// sentinel value.
    #[inline]
    pub fn is_current_with(&self, default: &InnerDigest<C>) -> bool {
        self.inner_path.is_current_with(default)
    }

    /// Computes the root of the merkle tree relative to `leaf_digest` using `parameters`.
    #[inline]
    pub fn root(&self, parameters: &Parameters<C>, leaf_digest: &LeafDigest<C>) -> Root<C> {
        self.inner_path
            .root(parameters, leaf_digest, &self.sibling_digest)
    }

    /// Returns `true` if `self` is a witness to the fact that `leaf_digest` is stored in a
    /// merkle tree with the given `root`.
    #[inline]
    pub fn verify_digest(
        &self,
        parameters: &Parameters<C>,
        root: &Root<C>,
        leaf_digest: &LeafDigest<C>,
    ) -> bool {
        self.inner_path
            .verify_digest(parameters, root, leaf_digest, &self.sibling_digest)
    }

    /// Returns `true` if `self` is a witness to the fact that `leaf` is stored in a merkle tree
    /// with the given `root`.
    #[inline]
    pub fn verify(&self, parameters: &Parameters<C>, root: &Root<C>, leaf: &Leaf<C>) -> bool {
        self.verify_digest(parameters, root, &parameters.digest(leaf))
    }
}

impl<C> From<CurrentPath<C>> for Path<C>
where
    C: Configuration + ?Sized,
{
    #[inline]
    fn from(path: CurrentPath<C>) -> Self {
        Self::from_inner(path.sibling_digest, path.inner_path.into())
    }
}

impl<C, I> Index<I> for Path<C>
where
    C: Configuration + ?Sized,
    I: SliceIndex<[InnerDigest<C>]>,
{
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        &self.inner_path[index]
    }
}

impl<C, I> IndexMut<I> for Path<C>
where
    C: Configuration + ?Sized,
    I: SliceIndex<[InnerDigest<C>]>,
{
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        &mut self.inner_path[index]
    }
}

/// Merkle Tree Current Path
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "LeafDigest<C>: Clone, InnerDigest<C>: Clone"),
    Debug(bound = "LeafDigest<C>: Debug, InnerDigest<C>: Debug"),
    Default(bound = ""),
    Eq(bound = "LeafDigest<C>: Eq, InnerDigest<C>: Eq"),
    Hash(bound = "LeafDigest<C>: Hash, InnerDigest<C>: Hash"),
    PartialEq(bound = "LeafDigest<C>: PartialEq, InnerDigest<C>: PartialEq")
)]
pub struct CurrentPath<C>
where
    C: Configuration + ?Sized,
{
    /// Sibling Digest
    pub sibling_digest: LeafDigest<C>,

    /// Current Inner Path
    pub inner_path: CurrentInnerPath<C>,
}

impl<C> CurrentPath<C>
where
    C: Configuration + ?Sized,
{
    /// Builds a new [`CurrentPath`] from `sibling_digest`, `leaf_index`, and `path`.
    ///
    /// # Safety
    ///
    /// See [`CurrentInnerPath::new`] for the invariants on `path` assumed by this function.
    #[inline]
    pub fn new(sibling_digest: LeafDigest<C>, leaf_index: Node, path: Vec<InnerDigest<C>>) -> Self {
        Self::from_inner(sibling_digest, CurrentInnerPath::new(leaf_index, path))
    }

    /// Builds a new [`CurrentPath`] from `sibling_digest` and `inner_path`.
    #[inline]
    pub fn from_inner(sibling_digest: LeafDigest<C>, inner_path: CurrentInnerPath<C>) -> Self {
        Self {
            sibling_digest,
            inner_path,
        }
    }

    /// Builds a new [`CurrentPath`] from a [`Path`] without checking that `path` satisfies
    /// [`Path::is_current`].
    #[inline]
    pub fn from_path_unchecked(path: Path<C>) -> Self {
        Self::from_path_unchecked_with(path, &Default::default())
    }

    /// Builds a new [`CurrentPath`] from a [`Path`] without checking that `path` satisfies
    /// [`Path::is_current_with`] against `default`.
    #[inline]
    pub fn from_path_unchecked_with(path: Path<C>, default: &InnerDigest<C>) -> Self {
        Self::from_inner(
            path.sibling_digest,
            CurrentInnerPath::from_path_unchecked_with(path.inner_path, default),
        )
    }

    /// Returns the leaf index for this [`CurrentPath`].
    #[inline]
    pub fn leaf_index(&self) -> Node {
        self.inner_path.leaf_index
    }

    /// Computes the root of the merkle tree relative to `leaf_digest` using `parameters`.
    #[inline]
    pub fn root(&self, parameters: &Parameters<C>, leaf_digest: &LeafDigest<C>) -> Root<C> {
        self.inner_path
            .root(parameters, leaf_digest, &self.sibling_digest)
    }

    /// Returns `true` if `self` is a witness to the fact that `leaf_digest` is stored in a
    /// merkle tree with the given `root`.
    #[inline]
    pub fn verify_digest(
        &self,
        parameters: &Parameters<C>,
        root: &Root<C>,
        leaf_digest: &LeafDigest<C>,
    ) -> bool {
        self.inner_path
            .verify_digest(parameters, root, leaf_digest, &self.sibling_digest)
    }

    /// Returns `true` if `self` is a witness to the fact that `leaf` is stored in a merkle tree
    /// with the given `root`.
    #[inline]
    pub fn verify(&self, parameters: &Parameters<C>, root: &Root<C>, leaf: &Leaf<C>) -> bool {
        self.verify_digest(parameters, root, &parameters.digest(leaf))
    }

    /// Updates the path to the next current path with `next`, updating `current`.
    #[inline]
    pub fn update(
        &mut self,
        parameters: &Parameters<C>,
        current: &mut LeafDigest<C>,
        next: LeafDigest<C>,
    ) -> Root<C> {
        self.inner_path
            .update(parameters, current, &mut self.sibling_digest, next)
    }
}

impl<C> TryFrom<Path<C>> for CurrentPath<C>
where
    C: Configuration + ?Sized,
{
    type Error = Path<C>;

    #[inline]
    fn try_from(path: Path<C>) -> Result<Self, Self::Error> {
        let Path {
            sibling_digest,
            inner_path,
        } = path;
        match inner_path.try_into() {
            Ok(inner_path) => Ok(Self::from_inner(sibling_digest, inner_path)),
            Err(inner_path) => Err(Path::from_inner(sibling_digest, inner_path)),
        }
    }
}

/* TODO: Compressed Path Implementation

/// Compressed Path
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "LeafDigest<C>: Clone, InnerDigest<C>: Clone"),
    Debug(bound = "LeafDigest<C>: Debug, InnerDigest<C>: Debug"),
    Eq(bound = "LeafDigest<C>: Eq, InnerDigest<C>: Eq"),
    Hash(bound = "LeafDigest<C>: Hash, InnerDigest<C>: Hash"),
    PartialEq(bound = "LeafDigest<C>: PartialEq, InnerDigest<C>: PartialEq")
)]
pub struct CompressedPath<C>
where
    C: Configuration + ?Sized,
{
    /// Leaf Index
    pub leaf_index: Node,

    /// Sibling Digest
    pub sibling_digest: LeafDigest<C>,

    /// Inner Path
    ///
    /// Inner digests are stored from leaf to root, not including the root.
    pub inner_path: Vec<InnerDigest<C>>,

    /// Sentinel Ranges
    pub sentinel_ranges: Vec<usize>,
}

impl<C> CompressedPath<C>
where
    C: Configuration + ?Sized,
{
    /// Builds a new [`CompressedPath`] from `leaf_index`, `sibling_digest`, `inner_path`, and
    /// `sentinel_ranges`.
    ///
    /// # Safety
    ///
    /// In order for paths to compute the correct root, they should always have an `inner_path`
    /// with length given by [`path_length`].
    ///
    /// For compressed paths, we need the `sentinel_ranges` to contain all the ranges which include
    /// the default inner hash, and then `inner_path` contains the non-default values. The total
    /// number of values represented in this way must equal the [`path_length`].
    #[inline]
    pub fn new(
        leaf_index: Node,
        sibling_digest: LeafDigest<C>,
        inner_path: Vec<InnerDigest<C>>,
        sentinel_ranges: Vec<usize>,
    ) -> Self {
        Self {
            leaf_index,
            sibling_digest,
            inner_path,
            sentinel_ranges,
        }
    }

    /// Uncompresses a path by re-inserting the default values into [`self.inner_path`] at the
    /// indices described by [`self.sentinel_ranges`].
    ///
    /// [`self.inner_path`]: Self::inner_path
    /// [`self.sentinel_ranges`]: Self::sentinel_ranges
    #[inline]
    pub fn uncompress(mut self) -> Path<C> {
        let path_length = path_length::<C>();
        self.inner_path.reserve(path_length);
        let mut start = 0;
        for (i, index) in self.sentinel_ranges.into_iter().enumerate() {
            if i % 2 == 0 {
                start = index;
            } else {
                self.inner_path
                    .splice(start..start, (start..index).map(|_| Default::default()));
            }
        }
        self.inner_path.resize_with(path_length, Default::default);
        Path::new(self.leaf_index, self.sibling_digest, self.inner_path)
    }
}

impl<C> Default for CompressedPath<C>
where
    C: Configuration + ?Sized,
{
    #[inline]
    fn default() -> Self {
        Self::new(
            Default::default(),
            Default::default(),
            Default::default(),
            vec![0, path_length::<C>()],
        )
    }
}

impl<C> From<Path<C>> for CompressedPath<C>
where
    C: Configuration + ?Sized,
{
    #[inline]
    fn from(path: Path<C>) -> Self {
        path.compress()
    }
}

impl<C> Path<C>
where
    C: Configuration + ?Sized,
{
    /// Compresses [`self.inner_path`] by removing all default values and saving only the positions
    /// in the path of those default values.
    ///
    /// [`self.inner_path`]: Self::inner_path
    #[inline]
    pub fn compress(self) -> CompressedPath<C> {
        let default = Default::default();
        let mut started = false;
        let mut sentinel_ranges = Vec::new();
        let inner_path = self
            .inner_path
            .into_iter()
            .enumerate()
            .filter_map(|(i, d)| {
                if d == default {
                    if !started {
                        sentinel_ranges.push(i);
                        started = true;
                    }
                    None
                } else {
                    if started {
                        sentinel_ranges.push(i);
                        started = false;
                    }
                    Some(d)
                }
            })
            .collect();
        sentinel_ranges.shrink_to_fit();
        CompressedPath::new(
            self.leaf_index,
            self.sibling_digest,
            inner_path,
            sentinel_ranges,
        )
    }
}

impl<C> From<CompressedPath<C>> for Path<C>
where
    C: Configuration + ?Sized,
{
    #[inline]
    fn from(path: CompressedPath<C>) -> Self {
        path.uncompress()
    }
}

*/
