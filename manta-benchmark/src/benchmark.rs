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

use ark_ec::ProjectiveCurve;
use criterion::{black_box, measurement::Measurement, BenchmarkGroup};
use manta_crypto::{
    arkworks::{
        ff::UniformRand,
        glv::{AffineCurveExt, GLVParameters, HasGLV},
    },
    rand::RngCore,
};
use std::marker::PhantomData;

/// Benchmark trait
pub trait Benchmark {
    /// Benchmark Name
    const NAME: &'static str;

    /// Benchmark Output Type
    type Output;

    /// Benchmark Parameters
    type Parameters;

    /// Generates a randomized instance of `Self` from `parameters`.
    fn setup<R>(rng: &mut R, parameters: Self::Parameters) -> Self
    where
        R: RngCore + ?Sized;

    /// A function of `self` which will be benchmarked.
    fn benchmark(&self) -> Self::Output;

    /// Defines a benchmark from `benchmark`.
    #[inline]
    fn define_benchmark<M>(&self, group: &mut BenchmarkGroup<M>)
    where
        M: Measurement,
    {
        group.bench_function(Self::NAME, |b| b.iter(|| black_box(self.benchmark())));
    }
}

/// GLV Multiplication Setup
pub struct GLVMutiplicationSetup<C, M>
where
    C: AffineCurveExt + HasGLV<M>,
{
    /// GLV Parameters
    glv_parameters: GLVParameters<C>,

    /// Scalar
    scalar: C::ScalarField,

    /// Curve Point
    point: C,

    /// Type Parameter Marker
    __: PhantomData<M>,
}

impl<C, T> Benchmark for GLVMutiplicationSetup<C, T>
where
    C: AffineCurveExt + HasGLV<T>,
{
    const NAME: &'static str = "GLV scalar multiplication";

    type Parameters = ();
    type Output = C;

    #[inline]
    fn setup<R>(rng: &mut R, (): Self::Parameters) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self {
            glv_parameters: C::glv_parameters(),
            scalar: C::ScalarField::rand(rng),
            point: C::Projective::rand(rng).into_affine(),
            __: PhantomData,
        }
    }

    #[inline]
    fn benchmark(&self) -> Self::Output {
        self.glv_parameters
            .scalar_mul(&black_box(self.point), &black_box(self.scalar))
    }
}
