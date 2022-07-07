// Copyright 2019-2022 Manta Network.
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

//! Round Constants Generation

use crate::crypto::hash::poseidon::{lfsr::LinearFeedbackShiftRegister, Field, FieldGeneration};
use alloc::vec::Vec;
use core::iter;
use manta_crypto::rand::{CryptoRng, Rand, RngCore, Sample};

/// Additive Round Constants for Poseidon Hash.
pub struct AdditiveRoundConstants<F>
where
    F: Field,
{
    constants: Vec<F>,
}

impl<F> AdditiveRoundConstants<F>
where
    F: Field,
{
    /// Builds a new [`AdditiveRoundConstants`] from `constants`.
    pub fn new(constants: Vec<F>) -> Self {
        Self { constants }
    }
}

impl<D, F> Sample<D> for AdditiveRoundConstants<F>
where
    D: Clone,
    F: Field + Sample<D>,
{
    #[inline]
    fn sample<R>(distribution: D, rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self::new(rng.sample_iter(core::iter::repeat(distribution)).collect())
    }
}

/// Samples field elements of type `F` from an iterator over random
/// bits `iter` with rejection sampling.
#[inline]
#[deprecated] // TODO: implement `Sample<D>` for field using rejection sampling.
pub fn sample_field_element<F, I>(iter: I) -> F
where
    F: FieldGeneration,
    I: IntoIterator<Item = bool>,
{
    let mut iter = iter.into_iter();
    loop {
        let bits = iter.by_ref().take(F::MODULUS_BITS).collect::<Vec<_>>();
        if let Some(f) = F::try_from_bits_be(&bits) {
            return f;
        }
    }
}

/// Generates the [`GrainLFSR`] for the parameter configuration of a field
/// with `modulus_bits` and a Poseidon configuration with `width`, `full_rounds`,
/// and `partial_rounds`.
#[inline]
pub fn generate_lfsr(
    modulus_bits: usize,
    width: usize,
    full_rounds: usize,
    partial_rounds: usize,
) -> LinearFeedbackShiftRegister {
    LinearFeedbackShiftRegister::from_seed([
        (2, 1),
        (4, 0),
        (12, modulus_bits as u128),
        (12, width as u128),
        (10, full_rounds as u128),
        (10, partial_rounds as u128),
        (30, 0b111111111111111111111111111111u128),
    ])
}

/// Generates the round constants for Poseidon by sampling
/// `width * (full_rounds + partial_rounds)`-many field elements
/// using [`sample_field_element`].
#[inline]
#[deprecated] // TODO: generate round constants using `Sample` trait.
pub fn generate_round_constants<F>(
    width: usize,
    full_rounds: usize,
    partial_rounds: usize,
) -> Vec<F>
where
    F: FieldGeneration,
{
    let mut lfsr = generate_lfsr(F::MODULUS_BITS, width, full_rounds, partial_rounds);
    iter::from_fn(|| Some(sample_field_element(&mut lfsr)))
        .take(width * (full_rounds + partial_rounds))
        .collect()
}

/// Testing Suite
#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::constraint::arkworks::Fp;
    use ark_bls12_381::Fr;
    use ark_ff::field_new;

    /// Checks if [`GrainLFSR`] is consistent with hardcoded outputs from the `sage` script found at
    /// <https://github.com/Manta-Network/Plonk-Prototype/tree/poseidon_hash_clean> with the
    /// following parameters:
    ///
    /// ```shell
    /// sage generate_parameters_grain_deterministic.sage 1 0 255 3 8 55 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    /// ```
    #[test]
    fn grain_lfsr_is_consistent() {
        let mut lfsr = generate_lfsr(255, 3, 8, 55);
        assert_eq!(
            sample_field_element::<Fp<Fr>, _>(&mut lfsr),
            Fp(field_new!(
                Fr,
                "41764196652518280402801918994067134807238124178723763855975902025540297174931"
            ))
        );
        assert_eq!(
            sample_field_element::<Fp<Fr>, _>(&mut lfsr),
            Fp(field_new!(
                Fr,
                "12678502092746318913289523392430826887011664085277767208266352862540971998250"
            ))
        );
    }
}
