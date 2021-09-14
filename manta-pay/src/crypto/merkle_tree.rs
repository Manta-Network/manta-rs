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
use manta_crypto::set::{ContainmentProof, VerifiedSet};
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
    pub(crate) leaf: LeafParam<MerkleTreeConfiguration<W, C>>,

    /// Two-to-One Hash Parameters
    pub(crate) two_to_one: TwoToOneParam<MerkleTreeConfiguration<W, C>>,
}

/// Merkle Tree Path
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""))]
pub struct Path<W, C>
where
    W: PedersenWindow,
    C: ProjectiveCurve,
{
    /// Path
    pub(crate) path: MerkleTreePath<MerkleTreeConfiguration<W, C>>,
}

impl<W, C> Path<W, C>
where
    W: PedersenWindow,
    C: ProjectiveCurve,
{
    /// Builds a new [`Path`] from `path`.
    #[inline]
    fn new(path: MerkleTreePath<MerkleTreeConfiguration<W, C>>) -> Self {
        Self { path }
    }
}

/// Path Variable
pub struct PathVar<W, C>(PhantomData<(W, C)>)
where
    W: PedersenWindow,
    C: ProjectiveCurve;

/// Merkle Tree
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""))]
pub struct MerkleTree<W, C>
where
    W: PedersenWindow,
    C: ProjectiveCurve,
{
    /// Merkle Tree
    pub(crate) tree: ArkMerkleTree<MerkleTreeConfiguration<W, C>>,
}

impl<W, C> MerkleTree<W, C>
where
    W: PedersenWindow,
    C: ProjectiveCurve,
{
    /// Builds a new [`MerkleTree`].
    ///
    /// # Panics
    ///
    /// The length of `leaves` must be a power of 2 or this function will panic.
    #[inline]
    pub fn new<T>(parameters: &Parameters<W, C>, leaves: &[T]) -> Option<Self>
    where
        T: Concat<Item = u8>,
    {
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
        })
    }

    /// Computes the [`Root`] of the [`MerkleTree`] built from the `leaves`.
    #[inline]
    pub fn build_root<T>(parameters: &Parameters<W, C>, leaves: &[T]) -> Option<Root<W, C>>
    where
        T: Concat<Item = u8>,
    {
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
        S: VerifiedSet<Public = Root<W, C>, Secret = Path<W, C>>,
    {
        Some(ContainmentProof::new(
            self.root(),
            Path::new(self.tree.generate_proof(index).ok()?),
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
