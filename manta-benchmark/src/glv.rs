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

use crate::Benchmark;
use core::marker::PhantomData;
use criterion::black_box;
use manta_crypto::{
    arkworks::{
        ec::{AffineCurveExt, ProjectiveCurve},
        ff::UniformRand,
        glv::{GLVParameters, HasGLV},
    },
    rand::RngCore,
};

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

impl<C, M> Benchmark for GLVMutiplicationSetup<C, M>
where
    C: AffineCurveExt + HasGLV<M>,
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
