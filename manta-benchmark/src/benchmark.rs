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

//! Benchmark trait

use crate::ecc;
use ark_ec::{AffineCurve, ProjectiveCurve};
use criterion::{black_box, measurement::Measurement, BenchmarkGroup};
use manta_crypto::{
    arkworks::{
        ff::{Field, UniformRand},
        glv::{AffineCurveExt, GLVParameters},
    },
    rand::RngCore,
};
use num_bigint::{BigInt, BigUint};
use std::{
    fs::File,
    io::{BufRead, BufReader},
    str::FromStr,
};

/// Benchmark trait
pub trait Benchmark {
    /// Benchmark Name
    const NAME: &'static str;

    /// Benchmark Output Type
    type Output;

    /// Benchmark Parameters
    type Parameters;

    /// Setup Function
    fn setup<R>(rng: &mut R, parameters: Self::Parameters) -> Self
    where
        R: RngCore + ?Sized;

    /// Benchmark Function
    fn benchmark(&self) -> Self::Output;

    /// Benchmark Definition Function
    #[inline]
    fn define_benchmark<M>(&self, group: &mut BenchmarkGroup<M>)
    where
        M: Measurement,
    {
        group.bench_function(Self::NAME, |b| b.iter(|| black_box(self.benchmark())));
    }
}

/// GLV Multiplication Setup
pub struct GLVMutiplicationSetup<C>
where
    C: AffineCurveExt,
{
    /// GLV Parameters
    glv: GLVParameters<C>,

    /// Scalar
    scalar: C::ScalarField,

    /// Curve Point
    point: C,
}

impl<C> Benchmark for GLVMutiplicationSetup<C>
where
    C: AffineCurveExt,
{
    const NAME: &'static str = "GLV scalar multiplication";

    type Parameters = &'static str;

    type Output = C;

    #[inline]
    fn setup<R>(rng: &mut R, parameters: Self::Parameters) -> Self
    where
        R: RngCore + ?Sized,
    {
        let scalar = C::ScalarField::rand(rng);
        let point = C::Projective::rand(rng).into_affine();
        let file = File::open(parameters).expect("Could not open file.");
        let reader = BufReader::new(file);
        let mut glv_strings: Vec<String> = Vec::with_capacity(5);
        for parameter in reader.lines() {
            glv_strings.push(parameter.unwrap());
        }
        let glv_parameters: Vec<&str> = glv_strings.iter().map(|s| &s[..]).collect();
        let beta = C::BaseField::from_random_bytes(
            &glv_parameters[0].parse::<BigUint>().unwrap().to_bytes_le(),
        )
        .unwrap();
        let base_v1 = (
            BigInt::from_str(glv_parameters[1]).unwrap(),
            BigInt::from_str(glv_parameters[2]).unwrap(),
        );
        let base_v2 = (
            BigInt::from_str(glv_parameters[3]).unwrap(),
            BigInt::from_str(glv_parameters[4]).unwrap(),
        );
        let glv = GLVParameters::<C>::new_unchecked(beta, base_v1, base_v2);
        Self { glv, scalar, point }
    }

    #[inline]
    fn benchmark(&self) -> Self::Output {
        self.glv.scalar_mul(&self.point, &self.scalar)
    }
}

/// Scalar Multiplication Setup
pub struct ScalarAffineSetup<C>
where
    C: AffineCurve,
{
    /// Scalar
    scalar: C::ScalarField,

    /// Curve Point
    point: C,
}

impl<C> Benchmark for ScalarAffineSetup<C>
where
    C: AffineCurve,
{
    const NAME: &'static str = "Scalar multiplication";

    type Parameters = ();

    type Output = C;

    #[inline]
    fn setup<R>(rng: &mut R, parameters: Self::Parameters) -> Self
    where
        R: RngCore + ?Sized,
    {
        let _ = parameters;
        let scalar = C::ScalarField::rand(rng);
        let point = C::Projective::rand(rng).into_affine();
        Self { scalar, point }
    }

    #[inline]
    fn benchmark(&self) -> Self::Output {
        ecc::affine_scalar_mul(&self.point, self.scalar).into_affine()
    }
}
