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
}

/// Blake2s PRF Constraint System Implementations
pub mod constraint {
    use super::*;
    use crate::crypto::constraint::{ArkProofSystem as ProofSystem, ByteArrayVar};
    use alloc::vec::Vec;
    use ark_crypto_primitives::{
        prf::blake2s::constraints::Blake2sGadget as ArkBlake2sVar, PRFGadget,
    };
    use ark_ff::PrimeField;
    use ark_r1cs_std::{uint8::UInt8, ToBytesGadget};
    use core::marker::PhantomData;
    use manta_crypto::constraint::{
        Alloc, AllocEq, Allocation, Bool, Constant, PublicOrSecret, Secret, Var, Variable,
    };

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

    impl<F> Variable<ProofSystem<F>> for Blake2sSeedVar<F>
    where
        F: PrimeField,
    {
        type Mode = Secret;
        type Type = Blake2sSeed;
    }

    impl<F> Alloc<ProofSystem<F>> for Blake2sSeed
    where
        F: PrimeField,
    {
        type Mode = Secret;

        type Variable = Blake2sSeedVar<F>;

        #[inline]
        fn variable<'t>(
            ps: &mut ProofSystem<F>,
            allocation: impl Into<Allocation<'t, Self, ProofSystem<F>>>,
        ) -> Self::Variable
        where
            Self: 't,
        {
            // FIXME: implement
            let _ = (ps, allocation);
            todo!()
        }
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

    impl<F> Default for Blake2sInputVar<F>
    where
        F: PrimeField,
    {
        #[inline]
        fn default() -> Self {
            // TODO: Should be secret values!
            todo!()
        }
    }

    impl<F> Variable<ProofSystem<F>> for Blake2sInputVar<F>
    where
        F: PrimeField,
    {
        type Mode = Secret;
        type Type = Blake2sInput;
    }

    impl<F> Alloc<ProofSystem<F>> for Blake2sInput
    where
        F: PrimeField,
    {
        type Mode = Secret;

        type Variable = Blake2sInputVar<F>;

        #[inline]
        fn variable<'t>(
            ps: &mut ProofSystem<F>,
            allocation: impl Into<Allocation<'t, Self, ProofSystem<F>>>,
        ) -> Self::Variable
        where
            Self: 't,
        {
            // FIXME: implement
            let _ = (ps, allocation);
            todo!()
        }
    }

    /// Blake2s Pseudorandom Function Family Output Variable
    #[derive(derivative::Derivative)]
    #[derivative(Clone)]
    pub struct Blake2sOutputVar<F>(<ArkBlake2sVar as PRFGadget<ArkBlake2s, F>>::OutputVar)
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

    impl<F> Variable<ProofSystem<F>> for Blake2sOutputVar<F>
    where
        F: PrimeField,
    {
        type Mode = PublicOrSecret;
        type Type = Blake2sOutput;
    }

    impl<F> Alloc<ProofSystem<F>> for Blake2sOutput
    where
        F: PrimeField,
    {
        type Mode = PublicOrSecret;

        type Variable = Blake2sOutputVar<F>;

        #[inline]
        fn variable<'t>(
            ps: &mut ProofSystem<F>,
            allocation: impl Into<Allocation<'t, Self, ProofSystem<F>>>,
        ) -> Self::Variable
        where
            Self: 't,
        {
            // FIXME: implement
            let _ = (ps, allocation);
            todo!()
        }
    }

    impl<F> AllocEq<ProofSystem<F>> for Blake2sOutput
    where
        F: PrimeField,
    {
        #[inline]
        fn eq(
            ps: &mut ProofSystem<F>,
            lhs: &Var<Self, ProofSystem<F>>,
            rhs: &Var<Self, ProofSystem<F>>,
        ) -> Bool<ProofSystem<F>> {
            todo!()
        }
    }

    /// Blake2s Pseudorandom Function Family Variable
    #[derive(derivative::Derivative)]
    #[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct Blake2sVar<F>(PhantomData<F>)
    where
        F: PrimeField;

    impl<F> Variable<ProofSystem<F>> for Blake2sVar<F>
    where
        F: PrimeField,
    {
        type Mode = Constant;
        type Type = Blake2s;
    }

    impl<F> Alloc<ProofSystem<F>> for Blake2s
    where
        F: PrimeField,
    {
        type Mode = Constant;

        type Variable = Blake2sVar<F>;

        #[inline]
        fn variable<'t>(
            ps: &mut ProofSystem<F>,
            allocation: impl Into<Allocation<'t, Self, ProofSystem<F>>>,
        ) -> Self::Variable {
            let _ = (ps, allocation);
            Default::default()
        }
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
    }
}
