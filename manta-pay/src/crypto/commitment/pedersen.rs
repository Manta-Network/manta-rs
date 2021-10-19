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

//! Arkworks Pedersen Commitment Implementation

use alloc::vec::Vec;
use ark_crypto_primitives::commitment::{
    pedersen::Commitment as ArkPedersenCommitment, CommitmentScheme as ArkCommitmentScheme,
};
use ark_ff::{bytes::ToBytes, UniformRand};
use manta_crypto::{
    commitment::CommitmentScheme,
    rand::{CryptoRng, Rand, RngCore, Sample, SizedRng, Standard},
};
use manta_util::{Concat, ConcatAccumulator};

/// Pedersen Window Parameters Trait
pub use ark_crypto_primitives::commitment::pedersen::Window as PedersenWindow;

pub use ark_ec::ProjectiveCurve;

/// Arkworks Pedersen Commitment Parameters
type ArkPedersenCommitmentParameters<W, C> =
    <ArkPedersenCommitment<C, W> as ArkCommitmentScheme>::Parameters;

/// Arkworks Pedersen Commitment Randomness
type ArkPedersenCommitmentRandomness<W, C> =
    <ArkPedersenCommitment<C, W> as ArkCommitmentScheme>::Randomness;

/// Arkworks Pedersen Commitment Output
type ArkPedersenCommitmentOutput<W, C> =
    <ArkPedersenCommitment<C, W> as ArkCommitmentScheme>::Output;

/// Pedersen Commitment Randomness
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = ""),
    Debug(bound = ""),
    Default(bound = ""),
    Eq(bound = ""),
    PartialEq(bound = "")
)]
pub struct PedersenCommitmentRandomness<W, C>(ArkPedersenCommitmentRandomness<W, C>)
where
    W: PedersenWindow,
    C: ProjectiveCurve;

impl<W, C> Sample for PedersenCommitmentRandomness<W, C>
where
    W: PedersenWindow,
    C: ProjectiveCurve,
{
    #[inline]
    fn sample<R>(distribution: Standard, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let _ = distribution;
        Self(ArkPedersenCommitmentRandomness::<W, _>::rand(rng))
    }
}

/// Pedersen Commitment Output
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = ""),
    Debug(bound = ""),
    Default(bound = ""),
    Eq(bound = ""),
    Hash(bound = ""),
    PartialEq(bound = "")
)]
pub struct PedersenCommitmentOutput<W, C>(ArkPedersenCommitmentOutput<W, C>)
where
    W: PedersenWindow,
    C: ProjectiveCurve;

impl<W, C> Concat for PedersenCommitmentOutput<W, C>
where
    W: PedersenWindow,
    C: ProjectiveCurve,
{
    type Item = u8;

    #[inline]
    fn concat<A>(&self, accumulator: &mut A)
    where
        A: ConcatAccumulator<Self::Item> + ?Sized,
    {
        // TODO: See if we can extend `ConcatAccumulator` to allow something like `Vec::append`,
        //       to improve the efficiency here.
        let mut buffer = Vec::new();
        self.0
            .write(&mut buffer)
            .expect("This does not fail. See the implementation of `Write` for `Vec`.");
        accumulator.extend(&buffer)
    }
}

/// Implementation of [`CommitmentScheme`] for Pedersen Commitments
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = ""))]
pub struct PedersenCommitment<W, C>(ArkPedersenCommitmentParameters<W, C>)
where
    W: PedersenWindow,
    C: ProjectiveCurve;

impl<W, C> PedersenCommitment<W, C>
where
    W: PedersenWindow,
    C: ProjectiveCurve,
{
    /// Pedersen Window Size
    pub const WINDOW_SIZE: usize = W::WINDOW_SIZE;

    /// Pedersen Window Count
    pub const NUM_WINDOWS: usize = W::NUM_WINDOWS;
}

impl<W, C> CommitmentScheme for PedersenCommitment<W, C>
where
    W: PedersenWindow,
    C: ProjectiveCurve,
{
    type Input = Vec<u8>;

    type Randomness = PedersenCommitmentRandomness<W, C>;

    type Output = PedersenCommitmentOutput<W, C>;

    #[inline]
    fn commit(&self, input: Self::Input, randomness: &Self::Randomness) -> Self::Output {
        PedersenCommitmentOutput(
            ArkPedersenCommitment::<_, W>::commit(&self.0, &input, &randomness.0)
                .expect("Failure outcomes are not accepted."),
        )
    }
}

impl<W, C> Sample for PedersenCommitment<W, C>
where
    W: PedersenWindow,
    C: ProjectiveCurve,
{
    #[inline]
    fn sample<R>(distribution: Standard, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let _ = distribution;
        Self(
            ArkPedersenCommitment::<_, W>::setup(&mut SizedRng(rng))
                .expect("Sampling is not allowed to fail."),
        )
    }
}

/// Pedersen Commitment Scheme Constraint System Implementation
pub mod constraint {
    use super::*;
    use crate::crypto::constraint::arkworks::{empty, full, ArkConstraintSystem};
    use ark_crypto_primitives::{
        commitment::pedersen::constraints::{CommGadget, ParametersVar, RandomnessVar},
        CommitmentGadget,
    };
    use ark_ff::{Field, ToConstraintField};
    use ark_r1cs_std::{
        alloc::AllocVar,
        groups::{CurveVar, GroupOpsBounds},
        uint8::UInt8,
    };
    use ark_relations::ns;
    use core::marker::PhantomData;
    use manta_crypto::constraint::{
        reflection::HasAllocation, types::Bool, Allocation, Constant, Equal, PublicOrSecret,
        Secret, Variable,
    };

    /// Constraint Field Type
    pub type ConstraintField<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;

    /// Constraint System Type
    pub type ConstraintSystem<C> = ArkConstraintSystem<ConstraintField<C>>;

    /// Input Buffer Type
    type InputBuffer<F> = Vec<UInt8<F>>;

    /// Pedersen Commitment Output Wrapper
    #[derive(derivative::Derivative)]
    #[derivative(
        Clone(bound = ""),
        Debug(bound = ""),
        Default(bound = ""),
        Eq(bound = ""),
        Hash(bound = ""),
        PartialEq(bound = "")
    )]
    pub struct PedersenCommitmentOutputWrapper<W, C, GG>(
        PedersenCommitmentOutput<W, C>,
        PhantomData<GG>,
    )
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
        GG: CurveVar<C, ConstraintField<C>>,
        for<'g> &'g GG: GroupOpsBounds<'g, C, GG>;

    impl<W, C, GG> From<PedersenCommitmentOutput<W, C>> for PedersenCommitmentOutputWrapper<W, C, GG>
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
        GG: CurveVar<C, ConstraintField<C>>,
        for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
    {
        #[inline]
        fn from(output: PedersenCommitmentOutput<W, C>) -> Self {
            Self(output, PhantomData)
        }
    }

    impl<W, C, GG> From<PedersenCommitmentOutputWrapper<W, C, GG>> for PedersenCommitmentOutput<W, C>
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
        GG: CurveVar<C, ConstraintField<C>>,
        for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
    {
        #[inline]
        fn from(wrapper: PedersenCommitmentOutputWrapper<W, C, GG>) -> Self {
            wrapper.0
        }
    }

    impl<W, C, GG> Concat for PedersenCommitmentOutputWrapper<W, C, GG>
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
        GG: CurveVar<C, ConstraintField<C>>,
        for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
    {
        type Item = u8;

        #[inline]
        fn concat<A>(&self, accumulator: &mut A)
        where
            A: ConcatAccumulator<Self::Item> + ?Sized,
        {
            self.0.concat(accumulator)
        }
    }

    /// Pedersen Commitment Scheme Wrapper
    #[derive(derivative::Derivative)]
    #[derivative(Clone(bound = ""))]
    pub struct PedersenCommitmentWrapper<W, C, GG>(PedersenCommitment<W, C>, PhantomData<GG>)
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
        GG: CurveVar<C, ConstraintField<C>>,
        for<'g> &'g GG: GroupOpsBounds<'g, C, GG>;

    impl<W, C, GG> PedersenCommitmentWrapper<W, C, GG>
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
        GG: CurveVar<C, ConstraintField<C>>,
        for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
    {
        /// Pedersen Window Size
        pub const WINDOW_SIZE: usize = W::WINDOW_SIZE;

        /// Pedersen Window Count
        pub const NUM_WINDOWS: usize = W::NUM_WINDOWS;
    }

    impl<W, C, GG> From<PedersenCommitment<W, C>> for PedersenCommitmentWrapper<W, C, GG>
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
        GG: CurveVar<C, ConstraintField<C>>,
        for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
    {
        #[inline]
        fn from(commitment_scheme: PedersenCommitment<W, C>) -> Self {
            Self(commitment_scheme, PhantomData)
        }
    }

    impl<W, C, GG> From<PedersenCommitmentWrapper<W, C, GG>> for PedersenCommitment<W, C>
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
        GG: CurveVar<C, ConstraintField<C>>,
        for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
    {
        #[inline]
        fn from(wrapper: PedersenCommitmentWrapper<W, C, GG>) -> Self {
            wrapper.0
        }
    }

    impl<W, C, GG> CommitmentScheme for PedersenCommitmentWrapper<W, C, GG>
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
        GG: CurveVar<C, ConstraintField<C>>,
        for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
    {
        type Input = <PedersenCommitment<W, C> as CommitmentScheme>::Input;

        type Randomness = <PedersenCommitment<W, C> as CommitmentScheme>::Randomness;

        type Output = PedersenCommitmentOutputWrapper<W, C, GG>;

        #[inline]
        fn commit(&self, input: Self::Input, randomness: &Self::Randomness) -> Self::Output {
            self.0.commit(input, randomness).into()
        }
    }

    impl<W, C, GG, D> Sample<D> for PedersenCommitmentWrapper<W, C, GG>
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
        GG: CurveVar<C, ConstraintField<C>>,
        for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
        PedersenCommitment<W, C>: Sample<D>,
    {
        #[inline]
        fn sample<R>(distribution: D, rng: &mut R) -> PedersenCommitmentWrapper<W, C, GG>
        where
            R: CryptoRng + RngCore + ?Sized,
        {
            Self(rng.sample(distribution), PhantomData)
        }
    }

    /// Pedersen Commitment Randomness Variable
    #[derive(derivative::Derivative)]
    #[derivative(Clone(bound = ""))]
    pub struct PedersenCommitmentRandomnessVar<W, C>(
        RandomnessVar<ConstraintField<C>>,
        PhantomData<W>,
    )
    where
        W: PedersenWindow,
        C: ProjectiveCurve;

    impl<W, C> Variable<ConstraintSystem<C>> for PedersenCommitmentRandomnessVar<W, C>
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
    {
        type Type = PedersenCommitmentRandomness<W, C>;

        type Mode = Secret;

        #[inline]
        fn new(
            cs: &mut ConstraintSystem<C>,
            allocation: Allocation<Self::Type, Self::Mode>,
        ) -> Self {
            // SAFETY: We can use `empty` here because `RandomnessVar` has an internal default and
            //         so its allocation never fails.
            Self(
                match allocation.known() {
                    Some((this, _)) => RandomnessVar::new_witness(
                        ns!(cs.cs, "pedersen commitment randomness secret witness"),
                        full(&this.0),
                    ),
                    _ => RandomnessVar::new_witness(
                        ns!(cs.cs, "pedersen commitment randomness secret witness"),
                        empty::<ArkPedersenCommitmentRandomness<W, C>>,
                    ),
                }
                .expect("Variable allocation is not allowed to fail."),
                PhantomData,
            )
        }
    }

    impl<W, C> HasAllocation<ConstraintSystem<C>> for PedersenCommitmentRandomness<W, C>
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
    {
        type Variable = PedersenCommitmentRandomnessVar<W, C>;
        type Mode = Secret;
    }

    /// Pedersen Commitment Output Variable
    #[derive(derivative::Derivative)]
    #[derivative(Clone(bound = ""))]
    pub struct PedersenCommitmentOutputVar<W, C, GG>(GG, PhantomData<(W, C)>)
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
        GG: CurveVar<C, ConstraintField<C>>,
        for<'g> &'g GG: GroupOpsBounds<'g, C, GG>;

    impl<W, C, GG> PedersenCommitmentOutputVar<W, C, GG>
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
        GG: CurveVar<C, ConstraintField<C>>,
        for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
    {
        /// Builds a new [`PedersenCommitmentOutputVar`] from `output_var`.
        #[inline]
        fn new(output_var: GG) -> Self {
            Self(output_var, PhantomData)
        }
    }

    impl<W, C, GG> Concat for PedersenCommitmentOutputVar<W, C, GG>
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
        GG: CurveVar<C, ConstraintField<C>>,
        for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
    {
        type Item = UInt8<ConstraintField<C>>;

        #[inline]
        fn concat<A>(&self, accumulator: &mut A)
        where
            A: ConcatAccumulator<Self::Item> + ?Sized,
        {
            accumulator.extend(&self.0.to_bytes().expect("This is not allowed to fail."))
        }
    }

    impl<W, C, GG> Variable<ConstraintSystem<C>> for PedersenCommitmentOutputVar<W, C, GG>
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
        GG: CurveVar<C, ConstraintField<C>>,
        for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
    {
        type Type = PedersenCommitmentOutputWrapper<W, C, GG>;

        type Mode = PublicOrSecret;

        #[inline]
        fn new(
            cs: &mut ConstraintSystem<C>,
            allocation: Allocation<Self::Type, Self::Mode>,
        ) -> Self {
            Self(
                match allocation {
                    Allocation::Known(this, PublicOrSecret::Public) => {
                        AllocVar::<ArkPedersenCommitmentOutput<W, C>, _>::new_input(
                            ns!(cs.cs, "pedersen commitment output public input"),
                            full(&(this.0).0),
                        )
                    }
                    Allocation::Known(this, PublicOrSecret::Secret) => {
                        AllocVar::<ArkPedersenCommitmentOutput<W, C>, _>::new_witness(
                            ns!(cs.cs, "pedersen commitment output secret witness"),
                            full(&(this.0).0),
                        )
                    }
                    Allocation::Unknown(PublicOrSecret::Public) => GG::new_input(
                        ns!(cs.cs, "pedersen commitment output public input"),
                        empty::<ArkPedersenCommitmentOutput<W, C>>,
                    ),
                    Allocation::Unknown(PublicOrSecret::Secret) => GG::new_witness(
                        ns!(cs.cs, "pedersen commitment output secret witness"),
                        empty::<ArkPedersenCommitmentOutput<W, C>>,
                    ),
                }
                .expect("Variable allocation is not allowed to fail."),
                PhantomData,
            )
        }
    }

    impl<W, C, GG> HasAllocation<ConstraintSystem<C>> for PedersenCommitmentOutputWrapper<W, C, GG>
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
        GG: CurveVar<C, ConstraintField<C>>,
        for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
    {
        type Variable = PedersenCommitmentOutputVar<W, C, GG>;
        type Mode = PublicOrSecret;
    }

    impl<W, C, GG> Equal<ConstraintSystem<C>> for PedersenCommitmentOutputVar<W, C, GG>
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
        GG: CurveVar<C, ConstraintField<C>>,
        for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
    {
        #[inline]
        fn eq(cs: &mut ConstraintSystem<C>, lhs: &Self, rhs: &Self) -> Bool<ConstraintSystem<C>> {
            let _ = cs;
            lhs.0
                .is_eq(&rhs.0)
                .expect("Equality checking is not allowed to fail.")
        }
    }

    impl<W, C> PedersenCommitmentOutput<W, C>
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
    {
        /// Extends the `input` vector by constraint field elements that make up `self`.
        #[inline]
        pub fn extend_input(&self, input: &mut Vec<ConstraintField<C>>)
        where
            C::Affine: ToConstraintField<ConstraintField<C>>,
        {
            input.append(
                &mut self
                    .0
                    .to_field_elements()
                    .expect("Conversion to constraint field elements is not allowed to fail."),
            )
        }
    }

    impl<W, C, GG> PedersenCommitmentOutputWrapper<W, C, GG>
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
        GG: CurveVar<C, ConstraintField<C>>,
        for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
    {
        /// Extends the `input` vector by constraint field elements that make up `self`.
        #[inline]
        pub fn extend_input(&self, input: &mut Vec<ConstraintField<C>>)
        where
            C::Affine: ToConstraintField<ConstraintField<C>>,
        {
            self.0.extend_input(input)
        }
    }

    /// Pedersen Commitment Scheme Variable
    #[derive(derivative::Derivative)]
    #[derivative(Clone(bound = ""))]
    pub struct PedersenCommitmentVar<W, C, GG>(ParametersVar<C, GG>, PhantomData<W>)
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
        GG: CurveVar<C, ConstraintField<C>>,
        for<'g> &'g GG: GroupOpsBounds<'g, C, GG>;

    impl<W, C, GG> Variable<ConstraintSystem<C>> for PedersenCommitmentVar<W, C, GG>
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
        GG: CurveVar<C, ConstraintField<C>>,
        for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
    {
        type Type = PedersenCommitmentWrapper<W, C, GG>;

        type Mode = Constant;

        #[inline]
        fn new(
            cs: &mut ConstraintSystem<C>,
            allocation: Allocation<Self::Type, Self::Mode>,
        ) -> Self {
            let (this, _) = allocation.into_known();
            Self(
                ParametersVar::new_constant(
                    ns!(cs.cs, "pedersen commitment paramters constant"),
                    &(this.0).0,
                )
                .expect("Variable allocation is not allowed to fail."),
                PhantomData,
            )
        }
    }

    impl<W, C, GG> HasAllocation<ConstraintSystem<C>> for PedersenCommitmentWrapper<W, C, GG>
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
        GG: CurveVar<C, ConstraintField<C>>,
        for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
    {
        type Variable = PedersenCommitmentVar<W, C, GG>;
        type Mode = Constant;
    }

    impl<W, C, GG> CommitmentScheme for PedersenCommitmentVar<W, C, GG>
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
        GG: CurveVar<C, ConstraintField<C>>,
        for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
    {
        type Input = InputBuffer<ConstraintField<C>>;

        type Randomness = PedersenCommitmentRandomnessVar<W, C>;

        type Output = PedersenCommitmentOutputVar<W, C, GG>;

        #[inline]
        fn commit(&self, input: Self::Input, randomness: &Self::Randomness) -> Self::Output {
            PedersenCommitmentOutputVar::new(
                CommGadget::<_, _, W>::commit(&self.0, &input, &randomness.0)
                    .expect("Failure outcomes are not accepted."),
            )
        }
    }
}
