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

//! Testing Framework

use crate::merkle_tree::{Configuration, Leaf, MerkleTree, Parameters, Tree, WithProofs};

/// Tests that a tree constructed with `parameters` can accept at least two leaves without
/// failing.
#[inline]
pub fn push_twice_to_empty_tree_succeeds<C, T>(
    parameters: Parameters<C>,
    lhs: &Leaf<C>,
    rhs: &Leaf<C>,
) -> Parameters<C>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
{
    let mut tree = MerkleTree::<C, T>::new(parameters);
    assert!(
        tree.push(lhs),
        "Trees always have a capacity of at least two."
    );
    assert!(
        tree.push(rhs),
        "Trees always have a capacity of at least two."
    );
    tree.into_parameters()
}

/// Tests path construction by checking that the path at the given `index` on `tree` is a valid
/// [`Path`](super::Path) for `leaf`.
#[inline]
pub fn assert_valid_path<C, T>(tree: &MerkleTree<C, T>, index: usize, leaf: &Leaf<C>)
where
    C: Configuration + ?Sized,
    T: Tree<C> + WithProofs<C>,
{
    assert!(
        tree.path(index)
            .expect("Only valid queries are accepted.")
            .verify(&tree.parameters, &tree.root(), leaf),
        "Path returned from tree was not valid."
    )
}
