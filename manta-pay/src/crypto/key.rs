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

//! Cryptographic Key Primitive Implementations

use blake2::{Blake2s, Digest};
use core::marker::PhantomData;
use manta_crypto::key::KeyDerivationFunction;
use manta_util::into_array_unchecked;

/// Blake2s KDF
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Blake2sKdf<T>(PhantomData<T>)
where
    T: AsRef<[u8]>;

impl<T> KeyDerivationFunction for Blake2sKdf<T>
where
    T: AsRef<[u8]>,
{
    type Key = T;

    type Output = [u8; 32];

    #[inline]
    fn derive(&self, secret: Self::Key, compiler: &mut ()) -> Self::Output {
        let _ = compiler;
        let mut hasher = Blake2s::new();
        hasher.update(secret.as_ref());
        hasher.update(b"manta kdf instantiated with blake2s hash function");
        into_array_unchecked(hasher.finalize())
    }
}

///
#[cfg(feature = "arkworks")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "arkworks")))]
pub mod arkworks {
    use super::*;
    use crate::crypto::constraint::arkworks::R1CS;
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_ff::{Field, PrimeField};
    use ark_r1cs_std::{
        fields::fp::FpVar,
        groups::{CurveVar, GroupOpsBounds},
        ToBitsGadget,
    };
    use manta_crypto::key::KeyAgreementScheme;

    ///
    type ConstraintField<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;

    /// Elliptic Curve Diffie Hellman Protocol
    pub struct EllipticCurveDiffieHellman<C>
    where
        C: ProjectiveCurve,
    {
        ///
        pub generator: C,
    }

    impl<C> KeyAgreementScheme for EllipticCurveDiffieHellman<C>
    where
        C: ProjectiveCurve,
    {
        type SecretKey = C::ScalarField;

        type PublicKey = C;

        type SharedSecret = C;

        #[inline]
        fn derive(&self, secret_key: &Self::SecretKey, compiler: &mut ()) -> Self::PublicKey {
            self.derive_owned(*secret_key, compiler)
        }

        #[inline]
        fn derive_owned(&self, secret_key: Self::SecretKey, compiler: &mut ()) -> Self::PublicKey {
            let _ = compiler;
            self.generator.mul(secret_key.into_repr())
        }

        #[inline]
        fn agree(
            &self,
            secret_key: &Self::SecretKey,
            public_key: &Self::PublicKey,
            compiler: &mut (),
        ) -> Self::SharedSecret {
            self.agree_owned(*secret_key, *public_key, compiler)
        }

        #[inline]
        fn agree_owned(
            &self,
            secret_key: Self::SecretKey,
            mut public_key: Self::PublicKey,
            compiler: &mut (),
        ) -> Self::SharedSecret {
            let _ = compiler;
            public_key *= secret_key;
            public_key
        }
    }

    /* TODO:
    impl<C, GG> KeyAgreementScheme<R1CS<ConstraintField<C>>> for EllipticCurveDiffieHellman<C, GG>
    where
        C: ProjectiveCurve,
        GG: CurveVar<C, ConstraintField<C>>,
    {
        type SecretKey = FpVar<C::ScalarField>;

        type PublicKey = GG;

        type SharedSecret = GG;

        #[inline]
        fn derive(
            compiler: &mut R1CS<ConstraintField<C>>,
            secret_key: &Self::SecretKey,
        ) -> Self::PublicKey {
            /* TODO:
            let _ = compiler;
            GG::prime_subgroup_generator().mul(secret_key)
            */
            todo!()
        }

        #[inline]
        fn agree(
            compiler: &mut R1CS<ConstraintField<C>>,
            secret_key: &Self::SecretKey,
            public_key: &Self::PublicKey,
        ) -> Self::SharedSecret {
            /* TODO:
            let _ = compiler;
            public_key
                .scalar_mul_le(
                    FpVar::<ConstraintField<C>>::from(secret_key)
                        .to_bits_le()
                        .expect("")
                        .iter(),
                )
                .expect("")
            */
            todo!()
        }
    }
    */
}
