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

//! Pairing

use crate::arkworks::{
    ec::{AffineCurve, PairingEngine},
    ff::PrimeField,
};
use core::iter;

/// Pairing Configuration
pub trait Pairing {
    /// Underlying Scalar Field
    type Scalar: PrimeField;

    /// First Group of the Pairing
    type G1: AffineCurve<ScalarField = Self::Scalar> + Into<Self::G1Prepared>;

    /// First Group Pairing-Prepared Point
    type G1Prepared;

    /// Second Group of the Pairing
    type G2: AffineCurve<ScalarField = Self::Scalar> + Into<Self::G2Prepared>;

    /// Second Group Pairing-Prepared Point
    type G2Prepared;

    /// Pairing Engine Type
    type Pairing: PairingEngine<
        G1Affine = Self::G1,
        G2Affine = Self::G2,
        G1Prepared = Self::G1Prepared,
        G2Prepared = Self::G2Prepared,
    >;

    /// Returns the base G1 generator for this configuration.
    fn g1_prime_subgroup_generator() -> Self::G1;

    /// Returns the base G2 generator for this configuration.
    fn g2_prime_subgroup_generator() -> Self::G2;
}

/// Pair from a [`PairingEngine`]
pub type Pair<P> = (
    <P as PairingEngine>::G1Prepared,
    <P as PairingEngine>::G2Prepared,
);

/// Pairing Engine Extension
pub trait PairingEngineExt: PairingEngine {
    /// Evaluates the pairing function on `pair`.
    #[inline]
    fn eval(pair: &Pair<Self>) -> Self::Fqk {
        Self::product_of_pairings(iter::once(pair))
    }

    /// Checks if `lhs` and `rhs` evaluate to the same point under the pairing function.
    #[inline]
    fn has_same(lhs: &Pair<Self>, rhs: &Pair<Self>) -> bool {
        Self::eval(lhs) == Self::eval(rhs)
    }

    /// Checks if `lhs` and `rhs` evaluate to the same point under the pairing function, returning
    /// `Some` with prepared points if the pairing outcome is the same. This function checks if
    /// there exists an `r` such that `(r * lhs.0 == rhs.0) && (lhs.1 == r * rhs.1)`.
    #[inline]
    fn same<L1, L2, R1, R2>(lhs: (L1, L2), rhs: (R1, R2)) -> Option<(Pair<Self>, Pair<Self>)>
    where
        L1: Into<Self::G1Prepared>,
        L2: Into<Self::G2Prepared>,
        R1: Into<Self::G1Prepared>,
        R2: Into<Self::G2Prepared>,
    {
        let lhs = (lhs.0.into(), lhs.1.into());
        let rhs = (rhs.0.into(), rhs.1.into());
        Self::has_same(&lhs, &rhs).then_some((lhs, rhs))
    }

    /// Checks if the ratio of `(lhs.0, lhs.1)` from `G1` is the same as the ratio of
    /// `(lhs.0, lhs.1)` from `G2`.
    #[inline]
    fn same_ratio<L1, L2, R1, R2>(lhs: (L1, R1), rhs: (L2, R2)) -> bool
    where
        L1: Into<Self::G1Prepared>,
        L2: Into<Self::G2Prepared>,
        R1: Into<Self::G1Prepared>,
        R2: Into<Self::G2Prepared>,
    {
        Self::has_same(&(lhs.0.into(), rhs.1.into()), &(lhs.1.into(), rhs.0.into()))
    }
}

impl<E> PairingEngineExt for E where E: PairingEngine {}

/// Generates the `G2Prepared` and `G2PreparedRef` structures for serialization compatibility
/// with arkworks canonical serialization.
macro_rules! pairing_impl {
    ($params:ident) => {
        /// Line Evaluation Coefficients
        pub type EllCoeff<F> = (F, F, F);

        /// G2 Prepared Point
        #[derive(derivative::Derivative, CanonicalSerialize, CanonicalDeserialize)]
        #[derivative(Clone, Default, Debug, Eq, PartialEq)]
        pub struct G2Prepared<P>
        where
            P: $params,
        {
            /// Coefficients
            pub ell_coeffs: Vec<EllCoeff<Fp2<P::Fp2Params>>>,

            /// Infinity Flag
            pub infinity: bool,
        }

        impl<P> From<g2::G2Prepared<P>> for G2Prepared<P>
        where
            P: $params,
        {
            #[inline]
            fn from(point: g2::G2Prepared<P>) -> Self {
                Self {
                    ell_coeffs: point.ell_coeffs,
                    infinity: point.infinity,
                }
            }
        }

        impl<P> From<G2Prepared<P>> for g2::G2Prepared<P>
        where
            P: $params,
        {
            #[inline]
            fn from(point: G2Prepared<P>) -> Self {
                Self {
                    ell_coeffs: point.ell_coeffs,
                    infinity: point.infinity,
                }
            }
        }

        /// G2 Prepared Point Reference
        #[derive(derivative::Derivative)]
        #[derivative(Debug, Eq, PartialEq)]
        pub struct G2PreparedRef<'p, P>(pub &'p g2::G2Prepared<P>)
        where
            P: $params;

        impl<'p, P> CanonicalSerialize for G2PreparedRef<'p, P>
        where
            P: $params,
        {
            #[inline]
            fn serialize<W>(&self, mut writer: W) -> Result<(), SerializationError>
            where
                W: Write,
            {
                let g2::G2Prepared {
                    ell_coeffs,
                    infinity,
                } = &self.0;
                ell_coeffs.serialize(&mut writer)?;
                infinity.serialize(&mut writer)?;
                Ok(())
            }

            #[inline]
            fn serialized_size(&self) -> usize {
                let g2::G2Prepared {
                    ell_coeffs,
                    infinity,
                } = &self.0;
                ell_coeffs.serialized_size() + infinity.serialized_size()
            }

            #[inline]
            fn serialize_uncompressed<W>(&self, mut writer: W) -> Result<(), SerializationError>
            where
                W: Write,
            {
                let g2::G2Prepared {
                    ell_coeffs,
                    infinity,
                } = &self.0;
                ell_coeffs.serialize_uncompressed(&mut writer)?;
                infinity.serialize_uncompressed(&mut writer)?;
                Ok(())
            }

            #[inline]
            fn serialize_unchecked<W>(&self, mut writer: W) -> Result<(), SerializationError>
            where
                W: Write,
            {
                let g2::G2Prepared {
                    ell_coeffs,
                    infinity,
                } = &self.0;
                ell_coeffs.serialize_unchecked(&mut writer)?;
                infinity.serialize_unchecked(&mut writer)?;
                Ok(())
            }

            #[inline]
            fn uncompressed_size(&self) -> usize {
                let g2::G2Prepared {
                    ell_coeffs,
                    infinity,
                } = &self.0;
                ell_coeffs.uncompressed_size() + infinity.uncompressed_size()
            }
        }

        impl<'p, P> From<&'p g2::G2Prepared<P>> for G2PreparedRef<'p, P>
        where
            P: $params,
        {
            #[inline]
            fn from(point: &'p g2::G2Prepared<P>) -> Self {
                Self(point)
            }
        }

        impl<'p, P> From<G2PreparedRef<'p, P>> for &'p g2::G2Prepared<P>
        where
            P: $params,
        {
            #[inline]
            fn from(point: G2PreparedRef<'p, P>) -> Self {
                point.0
            }
        }

        impl<'p, P> HasSerialization<'p> for g2::G2Prepared<P>
        where
            P: $params,
        {
            type Serialize = G2PreparedRef<'p, P>;
        }

        impl<P> HasDeserialization for g2::G2Prepared<P>
        where
            P: $params,
        {
            type Deserialize = G2Prepared<P>;
        }
    };
}

#[cfg(feature = "bn254")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "bn254")))]
/// BLS12 Utilities
pub mod bls12 {
    use crate::arkworks::{
        codec::{HasDeserialization, HasSerialization},
        ec::models::bls12::{g2, Bls12Parameters},
        ff::Fp2,
        serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write},
    };
    use alloc::vec::Vec;

    pairing_impl!(Bls12Parameters);
}

#[cfg(feature = "bls12_381")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "bls12_381")))]
/// Bn254 Utilities
pub mod bn254 {
    use crate::arkworks::{
        codec::{HasDeserialization, HasSerialization},
        ec::models::bn::{g2, BnParameters},
        ff::Fp2,
        serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write},
    };
    use alloc::vec::Vec;

    pairing_impl!(BnParameters);
}

/// Testing Framework
#[cfg(feature = "test")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "test")))]
pub mod test {
    use super::*;
    use crate::arkworks::ec::ProjectiveCurve;

    /// Asserts that `g1` and `g1*scalar` are in the same ratio as `g2` and `g2*scalar`.
    #[inline]
    pub fn assert_valid_pairing_ratio<E>(g1: E::G1Affine, g2: E::G2Affine, scalar: E::Fr)
    where
        E: PairingEngine,
    {
        assert!(E::same(
            (g1, g2.mul(scalar).into_affine()),
            (g1.mul(scalar).into_affine(), g2)
        )
        .is_some());
    }
}
