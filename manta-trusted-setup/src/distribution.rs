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

//! Distribution

use ark_ec::{short_weierstrass_jacobian::GroupAffine, ProjectiveCurve, SWModelParameters};
use ark_ff::{UniformRand, Zero};
use ark_std::rand::{distributions::Standard, Rng};
use manta_crypto::rand::{CryptoRng, Distribution, RngCore};

/// Sampling Trait
pub trait Sample<D = ()>: Sized {
    /// Returns a random value of type `Self`, sampled according to the given `distribution`,
    /// generated from the `rng`.
    fn sample<R>(distribution: D, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized;

    /// Returns a random value of type `Self`, sampled according to the default distribution of
    /// type `D`, generated from the `rng`.
    #[inline]
    fn gen<R>(rng: &mut R) -> Self
    where
        D: Default,
        R: CryptoRng + RngCore + ?Sized,
    {
        Self::sample(Default::default(), rng)
    }
}

impl<P, D> Sample<D> for GroupAffine<P>
where
    P: SWModelParameters,
    P::BaseField: Sample<D>,
    D: Clone,
    bool: Sample<D>,
{
    fn sample<R>(distribution: D, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        loop {
            let x = P::BaseField::sample(distribution.clone(), rng);
            let greatest = <bool as Sample<D>>::sample(distribution.clone(), rng);
            if let Some(p) = Self::get_point_from_x(x, greatest) {
                let p = p.scale_by_cofactor();
                if !p.is_zero() {
                    return p.into_affine();
                }
            }
        }
    }
}

/// A distribution to replicate random sampling as it was done
/// during the Sapling ceremony, which used `rand v. 0.4`.
#[derive(Copy, Clone, Default)]
pub struct SaplingDistribution;

impl Distribution<bool> for SaplingDistribution {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> bool {
        (rng.next_u32() as u8) & 1 == 1
    }
}

impl Distribution<ark_bls12_381::Fq2> for SaplingDistribution {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> ark_bls12_381::Fq2 {
        ark_bls12_381::Fq2::new(rng.sample(self), rng.sample(self))
    }
}

impl Distribution<ark_bls12_381::Fq> for SaplingDistribution {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> ark_bls12_381::Fq {
        use ark_ff::{fields::Fp384, FpParameters};

        loop {
            let mut tmp: ark_ff::BigInteger384 = rng.sample(self);

            // Mask away the unused bits at the beginning.
            tmp.as_mut()[5] &= 0xffffffffffffffff >> ark_bls12_381::FqParameters::REPR_SHAVE_BITS;

            if tmp < ark_bls12_381::FqParameters::MODULUS {
                return Fp384::new(tmp);
            }
        }
    }
}

// For phase2 `contribute` you're providing an rng, not the scalar itself. So since
// that sampling happens under the hood you have to implement Sample for the scalar field
impl Distribution<ark_bls12_381::Fr> for SaplingDistribution {
    // TODO: You could do this more similarly to above,
    // but there's actually no need to make phase2 match their distribution
    // The question is how many unused bits to throw away for this field
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> ark_bls12_381::Fr {
        rng.sample(Standard)
    }
}

impl Distribution<ark_ff::BigInteger384> for SaplingDistribution {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> ark_ff::BigInteger384 {
        ark_ff::BigInteger384([
            rng.sample(self),
            rng.sample(self),
            rng.sample(self),
            rng.sample(self),
            rng.sample(self),
            rng.sample(self),
        ])
    }
}

impl Distribution<u64> for SaplingDistribution {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> u64 {
        ((rng.next_u32() as u64) << 32) | (rng.next_u32() as u64)
    }
}

/// Implementing Sample for the base field of G1
impl Sample<SaplingDistribution> for ark_bls12_381::Fq {
    fn sample<R>(distribution: SaplingDistribution, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        distribution.sample(rng)
    }
}

/// Implementing Sample for the base field of G1
impl Sample for ark_bls12_381::Fq {
    fn sample<R>(_: (), rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Self::rand(rng)
    }
}

/// Implementing Sample for the base field of G2
impl Sample<SaplingDistribution> for ark_bls12_381::Fq2 {
    fn sample<R>(distribution: SaplingDistribution, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        distribution.sample(rng)
    }
}

/// Implementing Sample for the base field of G2
impl Sample for ark_bls12_381::Fq2 {
    fn sample<R>(_: (), rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Self::rand(rng)
    }
}

impl Sample<SaplingDistribution> for ark_bls12_381::Fr {
    fn sample<R>(distribution: SaplingDistribution, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        distribution.sample(rng)
    }
}

impl Sample for ark_bls12_381::Fr {
    fn sample<R>(_: (), rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Self::rand(rng)
    }
}

impl Sample for bool {
    fn sample<R>(_: (), rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        rng.next_u32() as u8 & 1 == 1
    }
}

impl Sample<SaplingDistribution> for bool {
    fn sample<R>(distribution: SaplingDistribution, rng: &mut R) -> Self
        where
            R: CryptoRng + RngCore + ?Sized,
    {
        distribution.sample(rng)
    }
}
