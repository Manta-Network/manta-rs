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

// TODO: We use the Pedersen commitment settings for `CRH` and `TwoToOneCRH`. We should write our
//       own `CRH` and `TwoToOneCRH` traits and then in the configuration we align them with the
//       Pedersen settings.

use crate::crypto::commitment::pedersen::{PedersenWindow, ProjectiveCurve};
use alloc::vec::Vec;
use ark_crypto_primitives::{
    crh::pedersen::CRH,
    merkle_tree::{
        Config as MerkleTreeConfig, LeafParam, MerkleTree as ArkMerkleTree, Path as MerkleTreePath,
        TwoToOneDigest, TwoToOneParam,
    },
};
use core::marker::PhantomData;
use manta_crypto::set::{ContainmentProof, VerifiedSet, VerifyContainment};
use manta_util::{as_bytes, Concat};

/// Merkle Tree Root
pub type Root<W, C> = TwoToOneDigest<MerkleTreeConfiguration<W, C>>;

/// Merkle Tree Parameters
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""))]
pub struct Parameters<W, C>
where
    W: PedersenWindow,
    C: ProjectiveCurve,
{
    /// Leaf Hash Parameters
    leaf: LeafParam<MerkleTreeConfiguration<W, C>>,

    /// Two-to-One Hash Parameters
    two_to_one: TwoToOneParam<MerkleTreeConfiguration<W, C>>,
}

/// Merkle Tree Path
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""))]
pub struct Path<W, C, T>
where
    W: PedersenWindow,
    C: ProjectiveCurve,
{
    /// Merkle Tree Parameters
    parameters: Parameters<W, C>,

    /// Path
    path: MerkleTreePath<MerkleTreeConfiguration<W, C>>,

    /// Type Parameter Marker
    __: PhantomData<T>,
}

impl<W, C, T> Path<W, C, T>
where
    W: PedersenWindow,
    C: ProjectiveCurve,
{
    /// Builds a new [`Path`] from `parameters` and `path`.
    #[inline]
    fn new(
        parameters: Parameters<W, C>,
        path: MerkleTreePath<MerkleTreeConfiguration<W, C>>,
    ) -> Self {
        Self {
            parameters,
            path,
            __: PhantomData,
        }
    }
}

/// Merkle Tree
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""))]
pub struct MerkleTree<W, C, T>
where
    W: PedersenWindow,
    C: ProjectiveCurve,
{
    /// Merkle Tree Parameters
    parameters: Parameters<W, C>,

    /// Merkle Tree
    tree: ArkMerkleTree<MerkleTreeConfiguration<W, C>>,

    /// Type Parameter Marker
    __: PhantomData<T>,
}

impl<W, C, T> MerkleTree<W, C, T>
where
    W: PedersenWindow,
    C: ProjectiveCurve,
    T: Concat<Item = u8>,
{
    /// Builds a new [`MerkleTree`].
    ///
    /// # Panics
    ///
    /// The length of `leaves` must be a power of 2 or this function will panic.
    #[inline]
    pub fn new(parameters: &Parameters<W, C>, leaves: &[T]) -> Option<Self> {
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
    pub fn build_root(parameters: &Parameters<W, C>, leaves: &[T]) -> Option<Root<W, C>> {
        Some(Self::new(parameters, leaves)?.root())
    }

    /// Returns the [`Root`] of this [`MerkleTree`].
    #[inline]
    pub fn root(&self) -> Root<W, C> {
        self.tree.root()
    }

    /// Builds a containment proof (i.e. merkle root and path) for the leaf at the given `index`.
    #[inline]
    pub fn get_containment_proof<S>(&self, index: usize) -> Option<ContainmentProof<S>>
    where
        S: VerifiedSet<Public = Root<W, C>, Secret = Path<W, C, T>>,
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
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MerkleTreeConfiguration<W, C>(PhantomData<(W, C)>)
where
    W: PedersenWindow,
    C: ProjectiveCurve;

impl<W, C> MerkleTreeConfig for MerkleTreeConfiguration<W, C>
where
    W: PedersenWindow,
    C: ProjectiveCurve,
{
    type LeafHash = CRH<C, W>;
    type TwoToOneHash = CRH<C, W>;
}

impl<W, C, T> VerifyContainment<Root<W, C>, T> for Path<W, C, T>
where
    W: PedersenWindow,
    C: ProjectiveCurve,
    T: Concat<Item = u8>,
{
    #[inline]
    fn verify(&self, root: &Root<W, C>, item: &T) -> bool {
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
