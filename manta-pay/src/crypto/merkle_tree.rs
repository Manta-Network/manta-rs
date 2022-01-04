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

//! Arkworks Merkle Tree Wrappers

// TODO: Move as much constraint code to `manta_crypto` as possible.

use alloc::{vec, vec::Vec};
use ark_crypto_primitives::{
    crh::{TwoToOneCRH, CRH},
    merkle_tree::Config,
};
use ark_ff::{to_bytes, ToBytes};
use core::marker::PhantomData;
use manta_crypto::{
    merkle_tree::{self, InnerHash, LeafHash},
    rand::{CryptoRng, RngCore, SizedRng},
};
use manta_util::{as_bytes, Concat};

/*
#[cfg(feature = "test")]
use manta_crypto::rand::Standard;
*/

/*
/// Arkworks Leaf Hash Converter
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LeafHashConverter<L, LH>(PhantomData<L>, PhantomData<LH>)
where
    L: Concat<Item = u8> + ?Sized,
    LH: CRH;

impl<L, LH> LeafHashConverter<L, LH>
where
    L: Concat<Item = u8> + ?Sized,
    LH: CRH,
{
    /// Sample leaf hash parameters using `rng`.
    #[inline]
    pub fn sample_parameters<R>(rng: &mut R) -> LH::Parameters
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        LH::setup(&mut SizedRng(rng))
            .expect("Leaf hash parameter generation is not allowed to fail.")
    }
}

impl<L, LH> LeafHash for LeafHashConverter<L, LH>
where
    L: Concat<Item = u8> + ?Sized,
    LH: CRH,
{
    type Leaf = L;

    type Parameters = LH::Parameters;

    type Output = LH::Output;

    #[inline]
    fn digest(parameters: &Self::Parameters, leaf: &Self::Leaf) -> Self::Output {
        LH::evaluate(parameters, &as_bytes!(leaf))
            .expect("Leaf digest computation is not allowed to fail.")
    }
}

/// Arkworks Inner Hash Converter
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InnerHashConverter<L, LH, IH>(PhantomData<L>, PhantomData<(LH, IH)>)
where
    L: Concat<Item = u8> + ?Sized,
    LH: CRH,
    IH: TwoToOneCRH;

impl<L, LH, IH> InnerHashConverter<L, LH, IH>
where
    L: Concat<Item = u8> + ?Sized,
    LH: CRH,
    IH: TwoToOneCRH,
{
    /// Sample inner hash parameters using `rng`.
    #[inline]
    pub fn sample_parameters<R>(rng: &mut R) -> IH::Parameters
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        IH::setup(&mut SizedRng(rng))
            .expect("Inner hash parameter generation is not allowed to fail.")
    }

    /// Evaluates the inner hash function for `IH` using `parameters`.
    #[inline]
    fn evaluate<T>(parameters: &IH::Parameters, lhs: &T, rhs: &T) -> IH::Output
    where
        T: ToBytes,
    {
        IH::evaluate(
            parameters,
            &to_bytes!(lhs).expect("Conversion to bytes is not allowed to fail."),
            &to_bytes!(rhs).expect("Conversion to bytes is not allowed to fail."),
        )
        .expect("Inner digest computation is not allowed to fail.")
    }
}

impl<L, LH, IH> InnerHash for InnerHashConverter<L, LH, IH>
where
    L: Concat<Item = u8> + ?Sized,
    LH: CRH,
    IH: TwoToOneCRH,
{
    type LeafHash = LeafHashConverter<L, LH>;

    type Parameters = IH::Parameters;

    type Output = IH::Output;

    #[inline]
    fn join(parameters: &Self::Parameters, lhs: &Self::Output, rhs: &Self::Output) -> Self::Output {
        Self::evaluate(parameters, lhs, rhs)
    }

    #[inline]
    fn join_leaves(
        parameters: &Self::Parameters,
        lhs: &<Self::LeafHash as LeafHash>::Output,
        rhs: &<Self::LeafHash as LeafHash>::Output,
    ) -> Self::Output {
        Self::evaluate(parameters, lhs, rhs)
    }
}

/// Arkworks Merkle Tree Configuration
pub trait Configuration {
    /// Leaf Type
    type Leaf: Concat<Item = u8> + ?Sized;

    /// Leaf Hash Type
    type LeafHash: CRH;

    /// Inner Hash Type
    type InnerHash: TwoToOneCRH;

    /// Merkle Tree Height Type
    type Height: Copy + Into<usize>;

    /// Merkle Tree Height
    const HEIGHT: Self::Height;
}

/// Configuration Converter
///
/// Given any `L` and [`C: Configuration`](Configuration), this struct can be used as
/// `ConfigConverter<L, C>` instead of `C` in places where we need an implementation of the
/// `arkworks` [`Config`] trait or the `manta_crypto` [`Configuration`](merkle_tree::Configuration)
/// trait.
///
/// This `struct` is meant only to be used in place of the type `C`, so any values of this `struct`
/// have no meaning.
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConfigConverter<C>(PhantomData<C>)
where
    C: Configuration;

impl<C> Configuration for ConfigConverter<C>
where
    C: Configuration,
{
    type Leaf = C::Leaf;
    type LeafHash = C::LeafHash;
    type InnerHash = C::InnerHash;

    const HEIGHT: usize = C::HEIGHT;
}

impl<C> merkle_tree::HashConfiguration for ConfigConverter<C>
where
    C: Configuration,
{
    type LeafHash = LeafHashConverter<C::Leaf, C::LeafHash>;
    type InnerHash = InnerHashConverter<C::Leaf, C::LeafHash, C::InnerHash>;
}

impl<C> merkle_tree::Configuration for ConfigConverter<C>
where
    C: Configuration,
{
    const HEIGHT: usize = C::HEIGHT;
}

impl<C> Config for ConfigConverter<C>
where
    C: Configuration,
{
    type LeafHash = C::LeafHash;
    type TwoToOneHash = C::InnerHash;
}

#[cfg(feature = "test")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "test")))]
impl<C> merkle_tree::test::HashParameterSampling for ConfigConverter<C>
where
    C: Configuration,
{
    type LeafHashParameterDistribution = Standard;

    type InnerHashParameterDistribution = Standard;

    #[inline]
    fn sample_leaf_hash_parameters<R>(
        distribution: Self::LeafHashParameterDistribution,
        rng: &mut R,
    ) -> merkle_tree::LeafHashParameters<Self>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let _ = distribution;
        <ConfigConverter<C> as merkle_tree::HashConfiguration>::LeafHash::sample_parameters(rng)
    }

    #[inline]
    fn sample_inner_hash_parameters<R>(
        distribution: Self::InnerHashParameterDistribution,
        rng: &mut R,
    ) -> merkle_tree::InnerHashParameters<Self>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let _ = distribution;
        <ConfigConverter<C> as merkle_tree::HashConfiguration>::InnerHash::sample_parameters(rng)
    }
}
*/

/* TODO:
/// Merkle Tree Constraint System Variables
pub mod constraint {
    use super::*;
    use crate::crypto::constraint::arkworks::{empty, full, R1CS};
    use ark_crypto_primitives::{
        crh::constraints::{CRHGadget, TwoToOneCRHGadget},
        merkle_tree::{constraints::PathVar as ArkPathVar, Path as ArkPath},
    };
    use ark_ff::{Field, ToConstraintField};
    use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean, eq::EqGadget, uint8::UInt8};
    use ark_relations::ns;
    use manta_crypto::{
        accumulator::Model,
        constraint::{Allocation, Constant, Public, Secret, Variable},
        merkle_tree::{Parameters, Path, Root},
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
    pub type ContraintSystem<C> = R1CS<ConstraintField<C>>;

    /// Leaf Hash Type
    pub type LeafHashVar<C> = <C as Configuration>::LeafHashVar;

    /// Inner Hash Type
    pub type InnerHashVar<C> = <C as Configuration>::InnerHashVar;

    /// Leaf Hash Parameters Type
    pub type LeafHashParametersVar<C> = <LeafHashVar<C> as CRHGadget<
        <C as super::Configuration>::LeafHash,
        ConstraintField<C>,
    >>::ParametersVar;

    /// Inner Hash Parameters Type
    pub type InnerHashParametersVar<C> = <InnerHashVar<C> as TwoToOneCRHGadget<
        <C as super::Configuration>::InnerHash,
        ConstraintField<C>,
    >>::ParametersVar;

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

        /// Verifies that `path` constitutes a proof that `leaf` is contained in the Merkle Tree
        /// with the given `root`.
        #[inline]
        pub fn verify(
            &self,
            root: &RootVar<C>,
            path: &PathVar<C>,
            leaf: &[UInt8<ConstraintField<C>>],
        ) -> Boolean<ConstraintField<C>> {
            path.0
                .verify_membership(&self.leaf, &self.inner, &root.0, &leaf)
                .expect("This is not allowed to fail.")
        }

        /// Asserts that `path` constitutes a proof that `leaf` is contained in the Merkle Tree
        /// with the given `root`.
        #[inline]
        pub fn assert_verified(
            &self,
            root: &RootVar<C>,
            path: &PathVar<C>,
            leaf: &[UInt8<ConstraintField<C>>],
        ) {
            self.verify(root, path, leaf)
                .enforce_equal(&Boolean::TRUE)
                .expect("This is not allowed to fail.");
        }
    }

    impl<C> Model<R1CS<ConstraintField<C>>> for ParametersVar<C>
    where
        C: Configuration,
    {
        type Item = [UInt8<ConstraintField<C>>];

        type Witness = PathVar<C>;

        type Output = RootVar<C>;

        type Verification = Boolean<ConstraintField<C>>;

        #[inline]
        fn verify(
            &self,
            item: &Self::Item,
            witness: &Self::Witness,
            output: &Self::Output,
        ) -> Self::Verification {
            self.verify(output, witness, item)
        }
    }

    impl<C> Variable<ContraintSystem<C>> for ParametersVar<C>
    where
        C: Configuration,
    {
        type Type = Parameters<ConfigConverter<C>>;

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

    /// Merkle Tree Root Inner Type
    type RootInnerType<C> = <<C as super::Configuration>::InnerHash as TwoToOneCRH>::Output;

    /// Merkle Tree Root Variable Inner Type
    type RootVarInnerType<C> = <InnerHashVar<C> as TwoToOneCRHGadget<
        <C as super::Configuration>::InnerHash,
        ConstraintField<C>,
    >>::OutputVar;

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
        type Type = Root<ConfigConverter<C>>;

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

    /// Extends the `input` vector by constraint field elements that make up `root`.
    #[inline]
    pub fn root_extend_input<C>(
        root: &Root<ConfigConverter<C>>,
        input: &mut Vec<ConstraintField<C>>,
    ) where
        C: Configuration,
        RootInnerType<C>: ToConstraintField<ConstraintField<C>>,
    {
        input.append(
            &mut root
                .0
                .to_field_elements()
                .expect("Conversion to constraint field elements is not allowed to fail."),
        );
    }

    /// Merkle Tree Path Inner Type
    type PathInnerType<C> = ArkPath<ConfigConverter<C>>;

    /// Merkle Tree Path Variable Inner Type
    type PathVarInnerType<C> =
        ArkPathVar<ConfigConverter<C>, LeafHashVar<C>, InnerHashVar<C>, ConstraintField<C>>;

    /// Merkle Tree Path Variable
    pub struct PathVar<C>(PathVarInnerType<C>)
    where
        C: Configuration;

    impl<C> PathVar<C>
    where
        C: Configuration,
    {
        /// Converts a [`Path`] to a [`PathInnerType`].
        #[inline]
        fn convert_path(path: &Path<ConfigConverter<C>>) -> PathInnerType<C> {
            PathInnerType {
                leaf_sibling_hash: path.sibling_digest.clone(),
                auth_path: path.inner_path.path.iter().rev().cloned().collect(),
                leaf_index: path.inner_path.leaf_index.0,
            }
        }

        /// Builds a default [`PathInnerType`] for use as an unknown variable value.
        #[inline]
        fn default_path() -> PathInnerType<C> {
            PathInnerType {
                leaf_sibling_hash: Default::default(),
                auth_path: vec![Default::default(); C::HEIGHT.into() - 2],
                leaf_index: Default::default(),
            }
        }
    }

    impl<C> Variable<ContraintSystem<C>> for PathVar<C>
    where
        C: Configuration,
    {
        type Type = Path<ConfigConverter<C>>;

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
                        full(&Self::convert_path(this)),
                    ),
                    _ => PathVarInnerType::new_witness(
                        ns!(cs.cs, "path variable secret witness"),
                        full(&Self::default_path()),
                    ),
                }
                .expect("Variable allocation is not allowed to fail."),
            )
        }
    }
}
*/
