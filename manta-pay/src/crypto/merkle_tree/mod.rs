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

//! Merkle Tree Implementations

// FIXME: Move to `manta_crypto::merkle_tree` implementation!

// NOTE:  This is meant to be a full implementation of the incremental merkle tree type suitable
//        for merging into arkworks itself. Therefore, even if we don't use all of the
//        functionality available in this module, we want to preserve the code anyway.
#[allow(dead_code)]
mod incremental;

use alloc::{vec, vec::Vec};
use ark_crypto_primitives::{
    crh::{TwoToOneCRH, CRH},
    merkle_tree::{Config, MerkleTree as ArkMerkleTree, Path as ArkPath, TwoToOneDigest},
};
use core::marker::PhantomData;
use manta_crypto::set::{ContainmentProof, VerifiedSet};
use manta_util::{as_bytes, rand::SizedRng, Concat};
use rand::{
    distributions::{Distribution, Standard},
    RngCore,
};

/// Merkle Tree Height Type
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Height(u16);

impl Height {
    /// Builds a Merkle Tree [`Height`] whenever `height >= 2`.
    #[inline]
    pub const fn new(height: u16) -> Self {
        let height = Self(height);
        height.inner();
        height
    }

    /// Returns the height as a `u16`.
    #[inline]
    pub const fn get(&self) -> u16 {
        self.0
    }

    /// Returns the inner height as a `u16`.
    #[inline]
    pub const fn inner(&self) -> u16 {
        self.0 - 2
    }
}

/// Merkle Tree Configuration
pub trait Configuration {
    /// Leaf Hash Type
    type LeafHash: CRH;

    /// Inner Hash Type
    type InnerHash: TwoToOneCRH;

    /// Merkle Tree Height
    const HEIGHT: Height;
}

/// Computes the Merkle Tree capacity given the `height`.
#[inline]
pub const fn capacity(height: Height) -> usize {
    2usize.pow(height.0 as u32)
}

/// Computes the necessary padding required to fill the capacity of a Merkle Tree with the
/// given `height`.
///
/// Returns `None` if `length` is larger than the capacity of the tree.
#[inline]
pub const fn padding_length(height: Height, length: usize) -> Option<usize> {
    let capacity = capacity(height);
    if length > capacity {
        return None;
    }
    Some(capacity - length)
}

/// Arkworks Configuration Converter
///
/// Given any `C: Configuration`, this struct can be used as `ArkConfigConverter<C>` instead of `C`
/// in places where we need an implementation of the arkworks [`Config`] trait.
///
/// This `struct` is meant only to be used in place of the type `C`, so any values of this `struct`
/// have no meaning.
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ArkConfigConverter<C>(PhantomData<C>)
where
    C: Configuration;

impl<C> Config for ArkConfigConverter<C>
where
    C: Configuration,
{
    type LeafHash = C::LeafHash;
    type TwoToOneHash = C::InnerHash;
}

/// Leaf Hash Type
type LeafHash<C> = <C as Configuration>::LeafHash;

/// Inner Hash Type
type InnerHash<C> = <C as Configuration>::InnerHash;

/// Leaf Hash Parameters Type
type LeafHashParameters<C> = <LeafHash<C> as CRH>::Parameters;

/// Inner Hash Parameters Type
type InnerHashParameters<C> = <InnerHash<C> as TwoToOneCRH>::Parameters;

/// Merkle Tree Parameters
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""))]
pub struct Parameters<C>
where
    C: Configuration,
{
    /// Leaf Hash Parameters
    pub leaf: LeafHashParameters<C>,

    /// Inner Hash Parameters
    pub inner: InnerHashParameters<C>,
}

impl<C> Parameters<C>
where
    C: Configuration,
{
    /// Builds a new [`Parameters`] from `leaf` and `inner` parameters.
    #[inline]
    pub fn new(leaf: LeafHashParameters<C>, inner: InnerHashParameters<C>) -> Self {
        Self { leaf, inner }
    }

    /// Verifies that `path` constitutes a proof that `item` is contained in the Merkle Tree
    /// with the given `root`.
    #[inline]
    pub fn verify<T>(&self, root: &Root<C>, path: &Path<C>, item: &T) -> bool
    where
        T: Concat<Item = u8>,
    {
        path.0
            .verify(&self.leaf, &self.inner, &root.0, &as_bytes!(item))
            .expect("As of arkworks 0.3.0, this never fails.")
    }
}

impl<C> Distribution<Parameters<C>> for Standard
where
    C: Configuration,
{
    #[inline]
    fn sample<R: RngCore + ?Sized>(&self, rng: &mut R) -> Parameters<C> {
        Parameters {
            leaf: LeafHash::<C>::setup(&mut SizedRng(rng))
                .expect("Sampling is not allowed to fail."),
            inner: InnerHash::<C>::setup(&mut SizedRng(rng))
                .expect("Sampling is not allowed to fail."),
        }
    }
}

/// Merkle Tree Root Inner Type
type RootInnerType<C> = TwoToOneDigest<ArkConfigConverter<C>>;

/// Merkle Tree Root
#[derive(derivative::Derivative)]
#[derivative(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Root<C>(RootInnerType<C>)
where
    C: Configuration;

/// Merkle Tree Path Inner Type
type PathInnerType<C> = ArkPath<ArkConfigConverter<C>>;

/// Merkle Tree Path
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""))]
pub struct Path<C>(PathInnerType<C>)
where
    C: Configuration;

/// Merkle Tree Inner Type
type MerkleTreeInnerType<C> = ArkMerkleTree<ArkConfigConverter<C>>;

/// Merkle Tree
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""))]
pub struct MerkleTree<C>(MerkleTreeInnerType<C>)
where
    C: Configuration;

impl<C> MerkleTree<C>
where
    C: Configuration,
{
    /// Builds a new [`MerkleTree`].
    #[inline]
    pub fn new<T>(parameters: &Parameters<C>, leaves: &[T]) -> Option<Self>
    where
        T: Concat<Item = u8>,
    {
        // FIXME: Add additional padding so we can be compatible with IMT.

        let leaves = leaves
            .iter()
            .map(move |leaf| as_bytes!(leaf))
            .collect::<Vec<_>>();

        Some(Self(
            ArkMerkleTree::new(&parameters.leaf, &parameters.inner, &leaves).ok()?,
        ))
    }

    /// Computes the [`Root`] of the [`MerkleTree`] built from the `leaves`.
    #[inline]
    pub fn new_root<T>(parameters: &Parameters<C>, leaves: &[T]) -> Option<Root<C>>
    where
        T: Concat<Item = u8>,
    {
        Some(Self::new(parameters, leaves)?.root())
    }

    /// Returns the capacity of this merkle tree.
    #[inline]
    pub fn capacity(&self) -> usize {
        capacity(C::HEIGHT)
    }

    /// Returns the height of this merkle tree.
    #[inline]
    pub fn height(&self) -> Height {
        C::HEIGHT
    }

    /// Returns the [`Root`] of this merkle tree.
    #[inline]
    pub fn root(&self) -> Root<C> {
        Root(self.0.root())
    }

    /// Builds a containment proof (i.e. merkle root and path) for the leaf at the given `index`.
    #[inline]
    pub fn get_containment_proof<S>(&self, index: usize) -> Option<ContainmentProof<S>>
    where
        S: VerifiedSet<Public = Root<C>, Secret = Path<C>>,
    {
        Some(ContainmentProof::new(
            self.root(),
            Path(self.0.generate_proof(index).ok()?),
        ))
    }
}

/// Incremental Merkle Tree
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""))]
pub struct IncrementalMerkleTree<C>(incremental::IncrementalMerkleTree<ArkConfigConverter<C>>)
where
    C: Configuration;

impl<C> IncrementalMerkleTree<C>
where
    C: Configuration,
{
    /// Builds a new [`IncrementalMerkleTree`].
    #[inline]
    pub fn new(parameters: &Parameters<C>) -> Self {
        Self(incremental::IncrementalMerkleTree::blank(
            &parameters.leaf,
            &parameters.inner,
            C::HEIGHT.0 as usize,
        ))
    }

    /// Returns the length of this incremental merkle tree.
    #[inline]
    pub fn len(&self) -> usize {
        todo!()
    }

    /// Returns `true` if this incremental merkle tree is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the capacity of this incremental merkle tree.
    #[inline]
    pub fn capacity(&self) -> usize {
        capacity(C::HEIGHT)
    }

    /// Returns the height of this incremental merkle tree.
    #[inline]
    pub fn height(&self) -> Height {
        C::HEIGHT
    }

    /// Appends an element to the incremental merkle tree, returning `false` if it has already
    /// reached its capacity and can no longer accept new elements.
    #[inline]
    pub fn append<T>(&mut self, leaf: &T) -> bool
    where
        T: Concat<Item = u8>,
    {
        let _ = leaf;
        todo!()
    }

    /// Returns the [`Root`] of this incremental merkle tree.
    #[inline]
    pub fn root(&self) -> Root<C> {
        Root(self.0.root().clone())
    }
}

/// Merkle Tree Constraint System Variables
pub mod constraint {
    use super::*;
    use crate::crypto::constraint::arkworks::{empty, full, ArkConstraintSystem};
    use ark_crypto_primitives::{
        crh::constraints::{CRHGadget, TwoToOneCRHGadget},
        merkle_tree::constraints::PathVar as ArkPathVar,
    };
    use ark_ff::Field;
    use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean, eq::EqGadget, uint8::UInt8};
    use ark_relations::ns;
    use manta_crypto::constraint::{
        reflection::HasAllocation, Allocation, Constant, Public, Secret, Variable,
    };

    /// Merkle Tree Constraint System Configuration
    pub trait Configuration: super::Configuration {
        /// Constraint Field Type
        type ConstraintField: Field;

        /// Leaf Hash Variable Type
        type LeafHashVar: CRHGadget<Self::LeafHash, Self::ConstraintField>;

        /// Inner Hash Variable Type
        type InnerHashVar: TwoToOneCRHGadget<Self::InnerHash, Self::ConstraintField>;
    }

    /// Constraint Field Type
    pub type ConstraintField<C> = <C as Configuration>::ConstraintField;

    /// Constraint System Type
    pub type ContraintSystem<C> = ArkConstraintSystem<ConstraintField<C>>;

    /// Leaf Hash Type
    type LeafHashVar<C> = <C as Configuration>::LeafHashVar;

    /// Inner Hash Type
    type InnerHashVar<C> = <C as Configuration>::InnerHashVar;

    /// Leaf Hash Parameters Type
    type LeafHashParametersVar<C> =
        <LeafHashVar<C> as CRHGadget<LeafHash<C>, ConstraintField<C>>>::ParametersVar;

    /// Inner Hash Parameters Type
    type InnerHashParametersVar<C> =
        <InnerHashVar<C> as TwoToOneCRHGadget<InnerHash<C>, ConstraintField<C>>>::ParametersVar;

    /// Merkle Tree Parameters Variable
    #[derive(derivative::Derivative)]
    #[derivative(Clone(bound = ""))]
    pub struct ParametersVar<C>
    where
        C: Configuration,
    {
        /// Leaf Hash Parameters Variable
        pub leaf: LeafHashParametersVar<C>,

        /// Inner Hash Parameters Variable
        pub inner: InnerHashParametersVar<C>,
    }

    impl<C> ParametersVar<C>
    where
        C: Configuration,
    {
        /// Builds a new [`ParametersVar`] from `leaf` and `inner` parameters.
        #[inline]
        pub fn new(leaf: LeafHashParametersVar<C>, inner: InnerHashParametersVar<C>) -> Self {
            Self { leaf, inner }
        }

        /// Verifies that `path` constitutes a proof that `item` is contained in the Merkle Tree
        /// with the given `root`.
        #[inline]
        pub fn verify(
            &self,
            root: &RootVar<C>,
            path: &PathVar<C>,
            item: &[UInt8<ConstraintField<C>>],
        ) -> Boolean<ConstraintField<C>> {
            path.0
                .verify_membership(&self.leaf, &self.inner, &root.0, &item)
                .expect("This is not allowed to fail.")
        }

        /// Asserts that `path` constitutes a proof that `item` is contained in the Merkle Tree
        /// with the given `root`.
        #[inline]
        pub fn assert_verified(
            &self,
            root: &RootVar<C>,
            path: &PathVar<C>,
            item: &[UInt8<ConstraintField<C>>],
        ) {
            self.verify(root, path, item)
                .enforce_equal(&Boolean::TRUE)
                .expect("This is not allowed to fail.")
        }
    }

    impl<C> Variable<ContraintSystem<C>> for ParametersVar<C>
    where
        C: Configuration,
    {
        type Type = Parameters<C>;

        type Mode = Constant;

        #[inline]
        fn new(
            cs: &mut ContraintSystem<C>,
            allocation: Allocation<Self::Type, Self::Mode>,
        ) -> Self {
            let (this, _) = allocation.into_known();
            ParametersVar::new(
                LeafHashParametersVar::<C>::new_constant(
                    ns!(cs.cs, "leaf hash parameter constant"),
                    &this.leaf,
                )
                .expect("Variable allocation is not allowed to fail."),
                InnerHashParametersVar::<C>::new_constant(
                    ns!(cs.cs, "two-to-one hash parameter constant"),
                    &this.inner,
                )
                .expect("Variable allocation is not allowed to fail."),
            )
        }
    }

    impl<C> HasAllocation<ContraintSystem<C>> for Parameters<C>
    where
        C: Configuration,
    {
        type Variable = ParametersVar<C>;
        type Mode = Constant;
    }

    /// Merkle Tree Root Variable Inner Type
    type RootVarInnerType<C> =
        <InnerHashVar<C> as TwoToOneCRHGadget<InnerHash<C>, ConstraintField<C>>>::OutputVar;

    /// Merkle Tree Root Variable
    #[derive(derivative::Derivative)]
    #[derivative(Clone)]
    pub struct RootVar<C>(RootVarInnerType<C>)
    where
        C: Configuration;

    impl<C> Variable<ContraintSystem<C>> for RootVar<C>
    where
        C: Configuration,
    {
        type Type = Root<C>;

        type Mode = Public;

        #[inline]
        fn new(
            cs: &mut ContraintSystem<C>,
            allocation: Allocation<Self::Type, Self::Mode>,
        ) -> Self {
            RootVar(
                match allocation.known() {
                    Some((this, _)) => AllocVar::<RootInnerType<C>, _>::new_input(
                        ns!(cs.cs, "merkle tree root public input"),
                        full(&this.0),
                    ),
                    _ => AllocVar::<RootInnerType<C>, _>::new_input(
                        ns!(cs.cs, "merkle tree root public input"),
                        empty::<RootInnerType<C>>,
                    ),
                }
                .expect("Variable allocation is not allowed to fail."),
            )
        }
    }

    impl<C> HasAllocation<ContraintSystem<C>> for Root<C>
    where
        C: Configuration,
    {
        type Variable = RootVar<C>;
        type Mode = Public;
    }

    /// Merkle Tree Path Variable Inner Type
    type PathVarInnerType<C> =
        ArkPathVar<ArkConfigConverter<C>, LeafHashVar<C>, InnerHashVar<C>, ConstraintField<C>>;

    /// Merkle Tree Path Variable
    pub struct PathVar<C>(PathVarInnerType<C>)
    where
        C: Configuration;

    impl<C> Variable<ContraintSystem<C>> for PathVar<C>
    where
        C: Configuration,
    {
        type Type = Path<C>;

        type Mode = Secret;

        #[inline]
        fn new(
            cs: &mut ContraintSystem<C>,
            allocation: Allocation<Self::Type, Self::Mode>,
        ) -> Self {
            PathVar(
                match allocation.known() {
                    Some((this, _)) => PathVarInnerType::new_witness(
                        ns!(cs.cs, "path variable secret witness"),
                        full(&this.0),
                    ),
                    _ => {
                        // FIXME: We can't use `empty` here. What do we do?
                        //
                        //   > The circuit we output must contain the height of the merkle tree
                        //     we are using for containment proofs. Since this is mandatory,
                        //     arkworks just forces you to build a path variable from a real path
                        //     even if you are just trying to build the circuit keys. So to solve
                        //     this, we need to find a way to mock the path of the correct height
                        //     (sample it from some distribution) so that when we create the
                        //     variable, it will have the necessary constraints to build the keys.
                        //
                        PathVarInnerType::new_witness(
                            ns!(cs.cs, "path variable secret witness"),
                            full(PathInnerType {
                                leaf_sibling_hash: Default::default(),
                                auth_path: vec![Default::default(); C::HEIGHT.inner() as usize],
                                leaf_index: Default::default(),
                            }),
                        )
                    }
                }
                .expect("Variable allocation is not allowed to fail."),
            )
        }
    }

    impl<C> HasAllocation<ContraintSystem<C>> for Path<C>
    where
        C: Configuration,
    {
        type Variable = PathVar<C>;
        type Mode = Secret;
    }
}
