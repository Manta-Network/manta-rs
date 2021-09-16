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

//! Basic Merkle Tree Implementation

// NOTE: Most if not all of the fallible interfaces in this file never actually fail. We use
//       faillible interfaces so that we don't have to depend explicitly on implementation
//       details of the `arkworks` project.

// TODO: We use the Pedersen commitment settings for `CRH` and `TwoToOneCRH`. We should write our
//       own `CRH` and `TwoToOneCRH` traits and then in the configuration we align them with the
//       Pedersen settings.

use crate::crypto::{
    commitment::pedersen::{PedersenWindow, ProjectiveCurve},
    constraint::{empty, full, ArkProofSystem},
};
use alloc::vec::Vec;
use ark_crypto_primitives::{
    crh::{
        constraints::{CRHGadget as CRHGadgetTrait, TwoToOneCRHGadget as TwoToOneCRHGadgetTrait},
        pedersen::{constraints::CRHGadget, CRH},
    },
    merkle_tree::{
        constraints::PathVar as ArkPathVar, Config, LeafParam as ArkLeafParam,
        MerkleTree as ArkMerkleTree, Path as ArkPath, TwoToOneDigest,
        TwoToOneParam as ArkTwoToOneParam,
    },
};
use ark_ff::Field;
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    groups::{CurveVar, GroupOpsBounds},
    uint8::UInt8,
};
use ark_relations::ns;
use core::marker::PhantomData;
use manta_crypto::{
    constraint::{reflection::HasAllocation, Allocation, Constant, Public, Secret, Variable},
    set::{ContainmentProof, VerifiedSet},
};
use manta_util::{as_bytes, Concat};

/// Constraint Field Type
pub type ConstraintField<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;

/// Proof System
type ProofSystem<C> = ArkProofSystem<ConstraintField<C>>;

/// Merkle Tree Configuration
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Configuration<W, C>(PhantomData<(W, C)>)
where
    W: PedersenWindow,
    C: ProjectiveCurve;

impl<W, C> Config for Configuration<W, C>
where
    W: PedersenWindow,
    C: ProjectiveCurve,
{
    type LeafHash = CRH<C, W>;
    type TwoToOneHash = CRH<C, W>;
}

/// Leaf Hash Parameters Type
type LeafParam<W, C> = ArkLeafParam<Configuration<W, C>>;

/// Two-to-One Hash Parameters Type
type TwoToOneParam<W, C> = ArkTwoToOneParam<Configuration<W, C>>;

/// Leaf Hash Parameters Variable
type LeafParamVar<W, C, GG> = <CRHGadget<C, GG, W> as CRHGadgetTrait<
    <Configuration<W, C> as Config>::LeafHash,
    ConstraintField<C>,
>>::ParametersVar;

/// Two-to-One Hash Parameters Variable
type TwoToOneParamVar<W, C, GG> = <CRHGadget<C, GG, W> as TwoToOneCRHGadgetTrait<
    <Configuration<W, C> as Config>::TwoToOneHash,
    ConstraintField<C>,
>>::ParametersVar;

/// Merkle Tree Parameters
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""))]
pub struct Parameters<W, C>
where
    W: PedersenWindow,
    C: ProjectiveCurve,
{
    /// Leaf Hash Parameters
    leaf: LeafParam<W, C>,

    /// Two-to-One Hash Parameters
    two_to_one: TwoToOneParam<W, C>,
}

impl<W, C> Parameters<W, C>
where
    W: PedersenWindow,
    C: ProjectiveCurve,
{
    /// Verifies that `path` constitutes a proof that `item` is contained in the Merkle Tree
    /// with the given `root`.
    #[inline]
    pub fn verify<T>(&self, root: &Root<W, C>, path: &Path<W, C>, item: &T) -> bool
    where
        T: Concat<Item = u8>,
    {
        path.0
            .verify(&self.leaf, &self.two_to_one, &root.0, &as_bytes!(item))
            .expect("As of arkworks 0.3.0, this never fails.")
    }
}

/// Merkle Tree Parameters Wrapper
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""))]
pub struct ParametersWrapper<W, C, GG>(Parameters<W, C>, PhantomData<GG>)
where
    W: PedersenWindow,
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintField<C>>,
    for<'g> &'g GG: GroupOpsBounds<'g, C, GG>;

impl<W, C, GG> ParametersWrapper<W, C, GG>
where
    W: PedersenWindow,
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintField<C>>,
    for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
{
    /// Verifies that `path` constitutes a proof that `item` is contained in the Merkle Tree
    /// with the given `root`.
    #[inline]
    pub fn verify<T>(
        &self,
        root: &RootWrapper<W, C, GG>,
        path: &PathWrapper<W, C, GG>,
        item: &T,
    ) -> bool
    where
        T: Concat<Item = u8>,
    {
        self.0.verify(&root.0, &path.0, item)
    }
}

/// Merkle Tree Parameters Variable
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""))]
pub struct ParametersVar<W, C, GG>
where
    W: PedersenWindow,
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintField<C>>,
    for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
{
    /// Leaf Hash Parameters Variable
    leaf: LeafParamVar<W, C, GG>,

    /// Two-to-One Hash Parameters Variable
    two_to_one: TwoToOneParamVar<W, C, GG>,
}

impl<W, C, GG> ParametersVar<W, C, GG>
where
    W: PedersenWindow,
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintField<C>>,
    for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
{
    /// Verifies that `path` constitutes a proof that `item` is contained in the Merkle Tree
    /// with the given `root`.
    #[inline]
    pub fn verify(
        &self,
        root: &RootVar<W, C, GG>,
        path: &PathVar<W, C, GG>,
        item: &[UInt8<ConstraintField<C>>],
    ) -> Boolean<ConstraintField<C>> {
        path.0
            .verify_membership(&self.leaf, &self.two_to_one, &root.0, &item)
            .expect("This is not allowed to fail.")
    }

    /// Asserts that `path` constitutes a proof that `item` is contained in the Merkle Tree
    /// with the given `root`.
    #[inline]
    pub fn assert_verified(
        &self,
        root: &RootVar<W, C, GG>,
        path: &PathVar<W, C, GG>,
        item: &[UInt8<ConstraintField<C>>],
    ) {
        self.verify(root, path, item)
            .enforce_equal(&Boolean::TRUE)
            .expect("This is not allowed to fail.")
    }
}

impl<W, C, GG> Variable<ProofSystem<C>> for ParametersVar<W, C, GG>
where
    W: PedersenWindow,
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintField<C>>,
    for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
{
    type Type = ParametersWrapper<W, C, GG>;

    type Mode = Constant;

    #[inline]
    fn new(ps: &mut ProofSystem<C>, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
        let (this, _) = allocation.into_known();
        ParametersVar {
            leaf: LeafParamVar::<W, _, _>::new_constant(
                ns!(ps.cs, "leaf hash parameter constant"),
                &this.0.leaf,
            )
            .expect("Variable allocation is not allowed to fail."),
            two_to_one: TwoToOneParamVar::<W, _, _>::new_constant(
                ns!(ps.cs, "two-to-one hash parameter constant"),
                &this.0.two_to_one,
            )
            .expect("Variable allocation is not allowed to fail."),
        }
    }
}

impl<W, C, GG> HasAllocation<ProofSystem<C>> for ParametersWrapper<W, C, GG>
where
    W: PedersenWindow,
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintField<C>>,
    for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
{
    type Variable = ParametersVar<W, C, GG>;

    type Mode = Constant;
}

/// Merkle Tree Root Inner Type
type RootInnerType<W, C> = TwoToOneDigest<Configuration<W, C>>;

/// Merkle Tree Root
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Root<W, C>(RootInnerType<W, C>)
where
    W: PedersenWindow,
    C: ProjectiveCurve;

/// Merkle Tree Root Wrapper
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct RootWrapper<W, C, GG>(Root<W, C>, PhantomData<GG>)
where
    W: PedersenWindow,
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintField<C>>,
    for<'g> &'g GG: GroupOpsBounds<'g, C, GG>;

/// Merkle Tree Root Variable
#[derive(derivative::Derivative)]
#[derivative(Clone)]
pub struct RootVar<W, C, GG>(GG, PhantomData<(W, C)>)
where
    W: PedersenWindow,
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintField<C>>,
    for<'g> &'g GG: GroupOpsBounds<'g, C, GG>;

impl<W, C, GG> Variable<ProofSystem<C>> for RootVar<W, C, GG>
where
    W: PedersenWindow,
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintField<C>>,
    for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
{
    type Type = RootWrapper<W, C, GG>;

    type Mode = Public;

    #[inline]
    fn new(ps: &mut ProofSystem<C>, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
        RootVar(
            match allocation.known() {
                Some((this, _)) => AllocVar::<RootInnerType<W, C>, _>::new_input(
                    ns!(ps.cs, "merkle tree root public input"),
                    full((this.0).0),
                ),
                _ => AllocVar::<RootInnerType<W, C>, _>::new_input(
                    ns!(ps.cs, "merkle tree root public input"),
                    empty::<RootInnerType<W, C>>,
                ),
            }
            .expect("Variable allocation is not allowed to fail."),
            PhantomData,
        )
    }
}

impl<W, C, GG> HasAllocation<ProofSystem<C>> for RootWrapper<W, C, GG>
where
    W: PedersenWindow,
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintField<C>>,
    for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
{
    type Variable = RootVar<W, C, GG>;
    type Mode = Public;
}

/// Merkle Tree Path Inner Type
type PathInnerType<W, C> = ArkPath<Configuration<W, C>>;

/// Merkle Tree Path
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""))]
pub struct Path<W, C>(PathInnerType<W, C>)
where
    W: PedersenWindow,
    C: ProjectiveCurve;

/// Merkle Tree Path Wrapper
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""))]
pub struct PathWrapper<W, C, GG>(Path<W, C>, PhantomData<GG>)
where
    W: PedersenWindow,
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintField<C>>,
    for<'g> &'g GG: GroupOpsBounds<'g, C, GG>;

/// Merkle Tree Path Variable Inner Type
type PathVarInnerType<W, C, GG> =
    ArkPathVar<Configuration<W, C>, CRHGadget<C, GG, W>, CRHGadget<C, GG, W>, ConstraintField<C>>;

/// Merkle Tree Path Variable
pub struct PathVar<W, C, GG>(PathVarInnerType<W, C, GG>)
where
    W: PedersenWindow,
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintField<C>>,
    for<'g> &'g GG: GroupOpsBounds<'g, C, GG>;

impl<W, C, GG> Variable<ProofSystem<C>> for PathVar<W, C, GG>
where
    W: PedersenWindow,
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintField<C>>,
    for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
{
    type Type = PathWrapper<W, C, GG>;

    type Mode = Secret;

    #[inline]
    fn new(ps: &mut ProofSystem<C>, allocation: Allocation<Self::Type, Self::Mode>) -> Self {
        PathVar(
            match allocation.known() {
                Some((this, _)) => PathVarInnerType::new_witness(ns!(ps.cs, ""), full(&(this.0).0)),
                _ => PathVarInnerType::new_witness(ns!(ps.cs, ""), empty::<PathInnerType<W, C>>),
            }
            .expect("Variable allocation is not allowed to fail."),
        )
    }
}

impl<W, C, GG> HasAllocation<ProofSystem<C>> for PathWrapper<W, C, GG>
where
    W: PedersenWindow,
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintField<C>>,
    for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
{
    type Variable = PathVar<W, C, GG>;
    type Mode = Secret;
}

/// Merkle Tree
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""))]
pub struct MerkleTree<W, C>(ArkMerkleTree<Configuration<W, C>>)
where
    W: PedersenWindow,
    C: ProjectiveCurve;

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
        Some(Self(
            ArkMerkleTree::new(
                &parameters.leaf,
                &parameters.two_to_one,
                &leaves
                    .iter()
                    .map(move |leaf| as_bytes!(leaf))
                    .collect::<Vec<_>>(),
            )
            .ok()?,
        ))
    }

    /// Builds a new [`MerkleTree`].
    ///
    /// # Panics
    ///
    /// The length of `leaves` must be a power of 2 or this function will panic.
    #[inline]
    pub fn from_wrapped<GG, T>(
        parameters: &ParametersWrapper<W, C, GG>,
        leaves: &[T],
    ) -> Option<Self>
    where
        GG: CurveVar<C, ConstraintField<C>>,
        for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
        T: Concat<Item = u8>,
    {
        Self::new(&parameters.0, leaves)
    }

    /// Computes the [`Root`] of the [`MerkleTree`] built from the `leaves`.
    #[inline]
    pub fn build_root<T>(parameters: &Parameters<W, C>, leaves: &[T]) -> Option<Root<W, C>>
    where
        T: Concat<Item = u8>,
    {
        Some(Self::new(parameters, leaves)?.root())
    }

    /// Computes the [`RootWrapper`] of the [`MerkleTree`] built from the `leaves`.
    #[inline]
    pub fn build_root_wrapped<GG, T>(
        parameters: &ParametersWrapper<W, C, GG>,
        leaves: &[T],
    ) -> Option<RootWrapper<W, C, GG>>
    where
        GG: CurveVar<C, ConstraintField<C>>,
        for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
        T: Concat<Item = u8>,
    {
        Self::build_root(&parameters.0, leaves).map(move |r| RootWrapper(r, PhantomData))
    }

    /// Returns the [`Root`] of this [`MerkleTree`].
    #[inline]
    pub fn root(&self) -> Root<W, C> {
        Root(self.0.root())
    }

    /// Returns the [`RootWrapper`] of this [`MerkleTree`].
    #[inline]
    pub fn root_wrapped<GG>(&self) -> RootWrapper<W, C, GG>
    where
        GG: CurveVar<C, ConstraintField<C>>,
        for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
    {
        RootWrapper(self.root(), PhantomData)
    }

    /// Computes the root and the path for the leaf at the given `index`.
    #[inline]
    fn compute_containment_proof(&self, index: usize) -> Option<(Root<W, C>, Path<W, C>)> {
        Some((self.root(), Path(self.0.generate_proof(index).ok()?)))
    }

    /// Builds a containment proof (i.e. merkle root and path) for the leaf at the given `index`.
    #[inline]
    pub fn get_containment_proof<S>(&self, index: usize) -> Option<ContainmentProof<S>>
    where
        S: VerifiedSet<Public = Root<W, C>, Secret = Path<W, C>>,
    {
        let (root, path) = self.compute_containment_proof(index)?;
        Some(ContainmentProof::new(root, path))
    }

    /// Builds a containment proof (i.e. merkle root and path) for the leaf at the given `index`.
    #[inline]
    pub fn get_wrapped_containment_proof<GG, S>(&self, index: usize) -> Option<ContainmentProof<S>>
    where
        GG: CurveVar<C, ConstraintField<C>>,
        for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
        S: VerifiedSet<Public = RootWrapper<W, C, GG>, Secret = PathWrapper<W, C, GG>>,
    {
        let (root, path) = self.compute_containment_proof(index)?;
        Some(ContainmentProof::new(
            RootWrapper(root, PhantomData),
            PathWrapper(path, PhantomData),
        ))
    }
}
