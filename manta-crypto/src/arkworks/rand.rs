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

//! Arkworks Random Sampling Backends

use crate::{
    arkworks::{
        ec::{
            models::{
                short_weierstrass_jacobian, twisted_edwards_extended, SWModelParameters,
                TEModelParameters,
            },
            AffineCurve, ProjectiveCurve,
        },
        ff::{Fp256, Fp320, Fp384, Fp448, Fp64, Fp768, Fp832, UniformRand},
    },
    rand::{RngCore, Sample},
};

/// Builds a [`Sample`] implementation for `$projective` and `$affine` curves over the `$P` model.
macro_rules! sample_curve {
    ($P:tt, $trait:tt, $projective:path, $affine:path $(,)?) => {
        impl<$P> Sample for $projective
        where
            $P: $trait,
        {
            #[inline]
            fn sample<R>(_: (), rng: &mut R) -> Self
            where
                R: RngCore + ?Sized,
            {
                Self::rand(rng)
            }
        }

        impl<$P> Sample for $affine
        where
            $P: $trait,
        {
            #[inline]
            fn sample<R>(distribution: (), rng: &mut R) -> Self
            where
                R: RngCore + ?Sized,
            {
                <Self as AffineCurve>::Projective::sample(distribution, rng).into_affine()
            }
        }
    };
}

sample_curve!(
    P,
    SWModelParameters,
    short_weierstrass_jacobian::GroupProjective<P>,
    short_weierstrass_jacobian::GroupAffine<P>,
);

sample_curve!(
    P,
    TEModelParameters,
    twisted_edwards_extended::GroupProjective<P>,
    twisted_edwards_extended::GroupAffine<P>,
);

/// Builds a [`Sample`] implementation for all the `$fp` types.
macro_rules! sample_fp {
    ($($fp:tt),* $(,)?) => {
        $(
            impl<P> Sample for $fp<P>
            where
                $fp<P>: UniformRand,
            {
                #[inline]
                fn sample<R>(_: (), rng: &mut R) -> Self
                where
                    R: RngCore + ?Sized,
                {
                    Self::rand(rng)
                }
            }
        )*
    };
}

sample_fp!(Fp64, Fp256, Fp320, Fp384, Fp448, Fp768, Fp832);
