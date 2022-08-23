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

//! Pairing Engine Utilities

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

/// BLS12 Utilities
pub mod bls12 {
    use crate::crypto::constraint::arkworks::codec::{HasDeserialization, HasSerialization};
    use alloc::vec::Vec;
    use manta_crypto::arkworks::{
        ec::models::bls12::{g2, Bls12Parameters},
        ff::Fp2,
        serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write},
    };

    pairing_impl!(Bls12Parameters);
}

/// Bn254 Utilities
pub mod bn254 {
    use crate::crypto::constraint::arkworks::codec::{HasDeserialization, HasSerialization};
    use alloc::vec::Vec;
    use manta_crypto::arkworks::{
        ec::models::bn::{g2, BnParameters},
        ff::Fp2,
        serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write},
    };

    pairing_impl!(BnParameters);
}
