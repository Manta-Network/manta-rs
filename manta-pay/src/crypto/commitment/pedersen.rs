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
use ark_ff::bytes::ToBytes;
use manta_crypto::commitment::CommitmentScheme;
use manta_util::{Concat, ConcatAccumulator};

/// Pedersen Window Parameters Trait
// TODO: Remove this comment once `arkworks` writes their own.
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
        accumulator.extend(&buffer);
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
    type InputBuffer = Vec<u8>;

    type Randomness = PedersenCommitmentRandomness<W, C>;

    type Output = PedersenCommitmentOutput<W, C>;

    #[inline]
    fn commit(&self, input: Self::InputBuffer, randomness: &Self::Randomness) -> Self::Output {
        // FIXME: Make a note about the failure properties of commitment schemes.
        PedersenCommitmentOutput(
            ArkPedersenCommitment::<_, W>::commit(&self.0, &input, &randomness.0)
                .expect("Failure outcomes are not accepted."),
        )
    }
}

/// Pedersen Commitment Scheme Constraint System Implementation
pub mod constraint {
    use super::*;
    use crate::crypto::constraint::ArkProofSystem;
    use ark_crypto_primitives::{
        commitment::pedersen::constraints::{CommGadget, ParametersVar, RandomnessVar},
        CommitmentGadget,
    };
    use ark_ff::Field;
    use ark_r1cs_std::{
        groups::{CurveVar, GroupOpsBounds},
        uint8::UInt8,
    };
    use core::marker::PhantomData;
    use manta_crypto::constraint::{
        Alloc, AllocEq, Allocation, Bool, Constant, PublicOrSecret, Secret, Var, Variable,
    };

    /// Constraint Field Type
    pub type ConstraintField<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;

    /// Proof System Type
    type ProofSystem<C> = ArkProofSystem<ConstraintField<C>>;

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
        type InputBuffer = <PedersenCommitment<W, C> as CommitmentScheme>::InputBuffer;

        type Randomness = <PedersenCommitment<W, C> as CommitmentScheme>::Randomness;

        type Output = PedersenCommitmentOutputWrapper<W, C, GG>;

        #[inline]
        fn commit(&self, input: Self::InputBuffer, randomness: &Self::Randomness) -> Self::Output {
            self.0.commit(input, randomness).into()
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

    impl<W, C> Variable<ProofSystem<C>> for PedersenCommitmentRandomnessVar<W, C>
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
    {
        type Mode = Secret;
        type Type = PedersenCommitmentRandomness<W, C>;
    }

    impl<W, C> Alloc<ProofSystem<C>> for PedersenCommitmentRandomness<W, C>
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
    {
        type Mode = Secret;

        type Variable = PedersenCommitmentRandomnessVar<W, C>;

        #[inline]
        fn variable<'t>(
            ps: &mut ProofSystem<C>,
            allocation: impl Into<Allocation<'t, Self, ProofSystem<C>>>,
        ) -> Self::Variable
        where
            Self: 't,
        {
            todo!()
        }
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
            accumulator.extend(&self.0.to_bytes().expect("This is not allowed to fail."));
        }
    }

    impl<W, C, GG> Variable<ProofSystem<C>> for PedersenCommitmentOutputVar<W, C, GG>
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
        GG: CurveVar<C, ConstraintField<C>>,
        for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
    {
        type Mode = PublicOrSecret;
        type Type = PedersenCommitmentOutputWrapper<W, C, GG>;
    }

    impl<W, C, GG> Alloc<ProofSystem<C>> for PedersenCommitmentOutputWrapper<W, C, GG>
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
        GG: CurveVar<C, ConstraintField<C>>,
        for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
    {
        type Mode = PublicOrSecret;

        type Variable = PedersenCommitmentOutputVar<W, C, GG>;

        #[inline]
        fn variable<'t>(
            ps: &mut ProofSystem<C>,
            allocation: impl Into<Allocation<'t, Self, ProofSystem<C>>>,
        ) -> Self::Variable
        where
            Self: 't,
        {
            todo!()
        }
    }

    impl<W, C, GG> AllocEq<ProofSystem<C>> for PedersenCommitmentOutputWrapper<W, C, GG>
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
        GG: CurveVar<C, ConstraintField<C>>,
        for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
    {
        #[inline]
        fn eq(
            ps: &mut ProofSystem<C>,
            lhs: &Var<Self, ProofSystem<C>>,
            rhs: &Var<Self, ProofSystem<C>>,
        ) -> Bool<ProofSystem<C>> {
            todo!()
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

    impl<W, C, GG> Variable<ProofSystem<C>> for PedersenCommitmentVar<W, C, GG>
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
        GG: CurveVar<C, ConstraintField<C>>,
        for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
    {
        type Mode = Constant;
        type Type = PedersenCommitmentWrapper<W, C, GG>;
    }

    impl<W, C, GG> Alloc<ArkProofSystem<ConstraintField<C>>> for PedersenCommitmentWrapper<W, C, GG>
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
        GG: CurveVar<C, ConstraintField<C>>,
        for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
    {
        type Mode = Constant;

        type Variable = PedersenCommitmentVar<W, C, GG>;

        #[inline]
        fn variable<'t>(
            ps: &mut ProofSystem<C>,
            allocation: impl Into<Allocation<'t, Self, ProofSystem<C>>>,
        ) -> Self::Variable
        where
            Self: 't,
        {
            match allocation.into() {
                Allocation::Known(this, _) => {
                    // FIXME: `this.parameters.new_constant(ps)`
                    let _ = (ps, this);
                    todo!()
                }
                _ => unreachable!(
                    "Since we use a constant allocation mode, we always know the variable value."
                ),
            }
        }
    }

    impl<W, C, GG> CommitmentScheme for PedersenCommitmentVar<W, C, GG>
    where
        W: PedersenWindow,
        C: ProjectiveCurve,
        GG: CurveVar<C, ConstraintField<C>>,
        for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
    {
        type InputBuffer = InputBuffer<ConstraintField<C>>;

        type Randomness = PedersenCommitmentRandomnessVar<W, C>;

        type Output = PedersenCommitmentOutputVar<W, C, GG>;

        #[inline]
        fn commit(&self, input: Self::InputBuffer, randomness: &Self::Randomness) -> Self::Output {
            PedersenCommitmentOutputVar::new(
                CommGadget::<_, _, W>::commit(&self.0, &input, &randomness.0)
                    .expect("Failure outcomes are not accepted."),
            )
        }
    }
}
