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

//! Blake2s PRF Implementation

use ark_crypto_primitives::prf::{Blake2s as ArkBlake2s, PRF};
use manta_crypto::PseudorandomFunctionFamily;
use manta_util::{Concat, ConcatAccumulator};

/// Blake2s Pseudorandom Function Family
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Blake2s;

/// Blake2s Pseudorandom Function Family Seed
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Blake2sSeed(pub(crate) <ArkBlake2s as PRF>::Seed);

impl AsMut<[u8]> for Blake2sSeed {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl Concat for Blake2sSeed {
    type Item = u8;

    #[inline]
    fn concat<A>(&self, accumulator: &mut A)
    where
        A: ConcatAccumulator<Self::Item> + ?Sized,
    {
        self.0.concat(accumulator)
    }
}

impl From<Blake2sSeed> for [u8; 32] {
    #[inline]
    fn from(seed: Blake2sSeed) -> Self {
        seed.0
    }
}

/// Blake2s Pseudorandom Function Family Input
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Blake2sInput(<ArkBlake2s as PRF>::Input);

impl Concat for Blake2sInput {
    type Item = u8;

    #[inline]
    fn concat<A>(&self, accumulator: &mut A)
    where
        A: ConcatAccumulator<Self::Item> + ?Sized,
    {
        self.0.concat(accumulator)
    }
}

/// Blake2s Pseudorandom Function Family Output
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Blake2sOutput(<ArkBlake2s as PRF>::Output);

impl Concat for Blake2sOutput {
    type Item = u8;

    #[inline]
    fn concat<A>(&self, accumulator: &mut A)
    where
        A: ConcatAccumulator<Self::Item> + ?Sized,
    {
        self.0.concat(accumulator)
    }
}

impl PseudorandomFunctionFamily for Blake2s {
    type Seed = Blake2sSeed;

    type Input = Blake2sInput;

    type Output = Blake2sOutput;

    #[inline]
    fn evaluate(seed: &Self::Seed, input: &Self::Input) -> Self::Output {
        Blake2sOutput(
            ArkBlake2s::evaluate(&seed.0, &input.0)
                .expect("As of arkworks 0.3.0, this never fails."),
        )
    }

    #[inline]
    fn evaluate_zero(seed: &Self::Seed) -> Self::Output {
        Self::evaluate(seed, &Default::default())
    }
}

/// Blake2s PRF Constraint System Implementations
pub mod constraint {
    use super::*;
    use crate::crypto::constraint::{empty, full, ByteArrayVar};
    use ark_crypto_primitives::{
        prf::blake2s::constraints::Blake2sGadget as ArkBlake2sVar, PRFGadget,
    };
    use ark_ff::PrimeField;
    use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, uint8::UInt8, ToBytesGadget};
    use ark_relations::ns;
    use core::marker::PhantomData;
    use manta_crypto::constraint::{
        reflection::HasAllocation, types::Bool, Allocation, Constant, Equal, PublicOrSecret,
        Secret, Variable,
    };

    /// Constraint System Type
    pub use crate::crypto::constraint::ArkConstraintSystem as ConstraintSystem;

    /// Blake2s Pseudorandom Function Family Seed Variable
    #[derive(derivative::Derivative)]
    #[derivative(Clone)]
    pub struct Blake2sSeedVar<F>(ByteArrayVar<F, 32>)
    where
        F: PrimeField;

    impl<F> Concat for Blake2sSeedVar<F>
    where
        F: PrimeField,
    {
        type Item = UInt8<F>;

        #[inline]
        fn concat<A>(&self, accumulator: &mut A)
        where
            A: ConcatAccumulator<Self::Item> + ?Sized,
        {
            self.0.concat(accumulator)
        }
    }

    impl<F> Variable<ConstraintSystem<F>> for Blake2sSeedVar<F>
    where
        F: PrimeField,
    {
        type Type = Blake2sSeed;

        type Mode = Secret;

        #[inline]
        fn new(
            cs: &mut ConstraintSystem<F>,
            allocation: Allocation<Self::Type, Self::Mode>,
        ) -> Self {
            Self(allocation.map_allocate(cs, move |this| this.0))
        }
    }

    impl<F> HasAllocation<ConstraintSystem<F>> for Blake2sSeed
    where
        F: PrimeField,
    {
        type Variable = Blake2sSeedVar<F>;
        type Mode = Secret;
    }

    /// Blake2s Pseudorandom Function Family Input Variable
    #[derive(derivative::Derivative)]
    #[derivative(Clone)]
    pub struct Blake2sInputVar<F>(ByteArrayVar<F, 32>)
    where
        F: PrimeField;

    impl<F> Concat for Blake2sInputVar<F>
    where
        F: PrimeField,
    {
        type Item = UInt8<F>;

        #[inline]
        fn concat<A>(&self, accumulator: &mut A)
        where
            A: ConcatAccumulator<Self::Item> + ?Sized,
        {
            self.0.concat(accumulator)
        }
    }

    impl<F> Variable<ConstraintSystem<F>> for Blake2sInputVar<F>
    where
        F: PrimeField,
    {
        type Type = Blake2sInput;

        type Mode = Secret;

        #[inline]
        fn new(
            cs: &mut ConstraintSystem<F>,
            allocation: Allocation<Self::Type, Self::Mode>,
        ) -> Self {
            Self(allocation.map_allocate(cs, move |this| this.0))
        }
    }

    impl<F> HasAllocation<ConstraintSystem<F>> for Blake2sInput
    where
        F: PrimeField,
    {
        type Variable = Blake2sInputVar<F>;
        type Mode = Secret;
    }

    /// Blake2s Pseudorandom Function Family Output Variable Inner Type
    type Blake2sOutputVarInnerType<F> = <ArkBlake2sVar as PRFGadget<ArkBlake2s, F>>::OutputVar;

    /// Blake2s Pseudorandom Function Family Output Variable
    #[derive(derivative::Derivative)]
    #[derivative(Clone)]
    pub struct Blake2sOutputVar<F>(Blake2sOutputVarInnerType<F>)
    where
        F: PrimeField;

    impl<F> Concat for Blake2sOutputVar<F>
    where
        F: PrimeField,
    {
        type Item = UInt8<F>;

        #[inline]
        fn concat<A>(&self, accumulator: &mut A)
        where
            A: ConcatAccumulator<Self::Item> + ?Sized,
        {
            accumulator.extend(&self.0.to_bytes().expect("This is not allowed to fail."));
        }
    }

    impl<F> Variable<ConstraintSystem<F>> for Blake2sOutputVar<F>
    where
        F: PrimeField,
    {
        type Type = Blake2sOutput;

        type Mode = PublicOrSecret;

        #[inline]
        fn new(
            cs: &mut ConstraintSystem<F>,
            allocation: Allocation<Self::Type, Self::Mode>,
        ) -> Self {
            // SAFETY: We can use `empty` here because `Blake2sOutputVarInnerType` has an internal
            //         default and so its allocation never fails.
            Self(
                match allocation {
                    Allocation::Known(this, mode) => match mode {
                        PublicOrSecret::Public => Blake2sOutputVarInnerType::new_input(
                            ns!(cs.cs, "blake2s output public input"),
                            full(this.0),
                        ),
                        PublicOrSecret::Secret => Blake2sOutputVarInnerType::new_witness(
                            ns!(cs.cs, "blake2s output secret witness"),
                            full(this.0),
                        ),
                    },
                    Allocation::Unknown(mode) => match mode {
                        PublicOrSecret::Public => Blake2sOutputVarInnerType::new_input(
                            ns!(cs.cs, "blake2s output public input"),
                            empty::<<ArkBlake2s as PRF>::Output>,
                        ),
                        PublicOrSecret::Secret => Blake2sOutputVarInnerType::new_witness(
                            ns!(cs.cs, "blake2s output secret witness"),
                            empty::<<ArkBlake2s as PRF>::Output>,
                        ),
                    },
                }
                .expect("Variable allocation is not allowed to fail."),
            )
        }
    }

    impl<F> HasAllocation<ConstraintSystem<F>> for Blake2sOutput
    where
        F: PrimeField,
    {
        type Variable = Blake2sOutputVar<F>;
        type Mode = PublicOrSecret;
    }

    impl<F> Equal<ConstraintSystem<F>> for Blake2sOutputVar<F>
    where
        F: PrimeField,
    {
        #[inline]
        fn eq(cs: &mut ConstraintSystem<F>, lhs: &Self, rhs: &Self) -> Bool<ConstraintSystem<F>> {
            let _ = cs;
            lhs.0
                .is_eq(&rhs.0)
                .expect("Equality checking is not allowed to fail.")
        }
    }

    /// Blake2s Pseudorandom Function Family Variable
    #[derive(derivative::Derivative)]
    #[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct Blake2sVar<F>(PhantomData<F>)
    where
        F: PrimeField;

    impl<F> Variable<ConstraintSystem<F>> for Blake2sVar<F>
    where
        F: PrimeField,
    {
        type Type = Blake2s;

        type Mode = Constant;

        #[inline]
        fn new(
            cs: &mut ConstraintSystem<F>,
            allocation: Allocation<Self::Type, Self::Mode>,
        ) -> Self {
            let _ = (cs, allocation);
            Default::default()
        }
    }

    impl<F> HasAllocation<ConstraintSystem<F>> for Blake2s
    where
        F: PrimeField,
    {
        type Variable = Blake2sVar<F>;
        type Mode = Constant;
    }

    impl<F> PseudorandomFunctionFamily for Blake2sVar<F>
    where
        F: PrimeField,
    {
        type Seed = Blake2sSeedVar<F>;
        type Input = Blake2sInputVar<F>;
        type Output = Blake2sOutputVar<F>;

        #[inline]
        fn evaluate(seed: &Self::Seed, input: &Self::Input) -> Self::Output {
            // FIXME: Make a note about the failure properties of PRFs.
            Blake2sOutputVar(
                ArkBlake2sVar::evaluate(seed.0.as_ref(), input.0.as_ref())
                    .expect("Failure outcomes are not accepted."),
            )
        }

        #[inline]
        fn evaluate_zero(seed: &Self::Seed) -> Self::Output {
            // FIXME: This is super hacky! Find a more sustainable way to do this.
            Self::evaluate(
                seed,
                &Blake2sInputVar(ByteArrayVar::allocate(
                    &seed.0.constraint_system_ref(),
                    Allocation::Known(&[0; 32], Secret.into()),
                )),
            )
        }
    }
}
