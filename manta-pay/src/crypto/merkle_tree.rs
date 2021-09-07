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

//! Merkle Tree Implementation

// NOTE: Most if not all of the fallible interfaces in this file never actually fail. We use
//       faillible interfaces so that we don't have to depend explicitly on implementation
//       details of the `arkworks` project.

use crate::crypto::commitment::pedersen::PedersenWindow;
use alloc::vec::Vec;
use ark_crypto_primitives::{
    crh::pedersen::CRH,
    merkle_tree::{
        Config as MerkleTreeConfig, LeafParam, MerkleTree as ArkMerkleTree, Path as MerkleTreePath,
        TwoToOneDigest, TwoToOneParam,
    },
};
use ark_ed_on_bls12_381::EdwardsProjective;
use core::marker::PhantomData;
use manta_crypto::{
    as_bytes,
    set::{ContainmentProof, VerifiedSet, VerifyContainment},
    ConcatBytes,
};

/// Merkle Tree Root
pub type Root = TwoToOneDigest<MerkleTreeConfiguration>;

/// Merkle Tree Parameters
#[derive(Clone)]
pub struct Parameters {
    /// Leaf Hash Parameters
    leaf: LeafParam<MerkleTreeConfiguration>,

    /// Two-to-One Hash Parameters
    two_to_one: TwoToOneParam<MerkleTreeConfiguration>,
}

/// Merkle Tree Path
#[derive(Clone)]
pub struct Path<T> {
    /// Merkle Tree Parameters
    parameters: Parameters,

    /// Path
    path: MerkleTreePath<MerkleTreeConfiguration>,

    /// Marker
    __: PhantomData<T>,
}

impl<T> Path<T> {
    /// Builds a new [`Path`] from `parameters` and `path`.
    #[inline]
    fn new(parameters: Parameters, path: MerkleTreePath<MerkleTreeConfiguration>) -> Self {
        Self {
            parameters,
            path,
            __: PhantomData,
        }
    }
}

/// Merkle Tree
#[derive(Clone)]
pub struct MerkleTree<T> {
    /// Merkle Tree Parameters
    parameters: Parameters,

    /// Merkle Tree
    tree: ArkMerkleTree<MerkleTreeConfiguration>,

    /// Marker
    __: PhantomData<T>,
}

impl<T> MerkleTree<T>
where
    T: ConcatBytes,
{
    /// Builds a new [`MerkleTree`].
    ///
    /// # Panics
    ///
    /// The length of `leaves` must be a power of 2 or this function will panic.
    #[inline]
    pub fn new(parameters: &Parameters, leaves: &[T]) -> Option<Self> {
        Some(Self {
            tree: ArkMerkleTree::new(
                &parameters.leaf,
                &parameters.two_to_one,
                &leaves
                    .iter()
                    .map(move |leaf| as_bytes!(leaf))
                    .collect::<Vec<_>>(),
            )
            .ok()?,
            parameters: parameters.clone(),
            __: PhantomData,
        })
    }

    /// Computes the [`Root`] of the [`MerkleTree`] built from the `leaves`.
    #[inline]
    pub fn build_root(parameters: &Parameters, leaves: &[T]) -> Option<Root> {
        Some(Self::new(parameters, leaves)?.root())
    }

    /// Returns the [`Root`] of this [`MerkleTree`].
    #[inline]
    pub fn root(&self) -> Root {
        self.tree.root()
    }

    /// Builds a containment proof (i.e. merkle root and path) for the leaf at the given `index`.
    #[inline]
    pub fn get_containment_proof<S>(&self, index: usize) -> Option<ContainmentProof<S>>
    where
        S: VerifiedSet<Public = Root, Secret = Path<T>>,
    {
        Some(ContainmentProof::new(
            self.root(),
            Path::new(
                self.parameters.clone(),
                self.tree.generate_proof(index).ok()?,
            ),
        ))
    }
}

/// Merkle Tree Configuration
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MerkleTreeConfiguration;

impl MerkleTreeConfig for MerkleTreeConfiguration {
    type LeafHash = CRH<EdwardsProjective, PedersenWindow>;

    // TODO: On the arkworks development branch `CRH` was fixed to `TwoToOneCRH`.
    //       We will need to fix this in the next update.
    type TwoToOneHash = CRH<EdwardsProjective, PedersenWindow>;
}

impl<T> VerifyContainment<Root, T> for Path<T>
where
    T: ConcatBytes,
{
    #[inline]
    fn verify(&self, root: &Root, item: &T) -> bool {
        self.path
            .verify(
                &self.parameters.leaf,
                &self.parameters.two_to_one,
                root,
                &as_bytes!(item),
            )
            .expect("As of arkworks 0.3.0, this never fails.")
    }
}
