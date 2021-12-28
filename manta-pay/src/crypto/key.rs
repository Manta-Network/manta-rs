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

#[cfg(feature = "arkworks")]
use {
    crate::crypto::constraint::arkworks::R1CS,
    ark_ec::{AffineCurve, ProjectiveCurve},
    ark_ff::Field,
    ark_r1cs_std::fields::fp::FpVar,
    ark_r1cs_std::groups::{CurveVar, GroupOpsBounds},
    ark_r1cs_std::ToBitsGadget,
    manta_crypto::key::KeyAgreementScheme,
};

/// Blake2s KDF
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
    fn derive(compiler: &mut (), secret: Self::Key) -> Self::Output {
        let _ = compiler;
        let mut hasher = Blake2s::new();
        hasher.update(secret.as_ref());
        hasher.update(b"manta kdf instantiated with blake2s hash function");
        into_array_unchecked(hasher.finalize())
    }
}

///
#[cfg(feature = "arkworks")]
type ConstraintField<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;

/// Elliptic Curve Diffie Hellman Protocol
#[cfg(feature = "arkworks")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "arkworks")))]
pub struct EllipticCurveDiffieHellman<C, GG>(PhantomData<(C, GG)>)
where
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintField<C>>,
    for<'g> &'g GG: GroupOpsBounds<'g, C, GG>;

#[cfg(feature = "arkworks")]
impl<C, GG> KeyAgreementScheme for EllipticCurveDiffieHellman<C, GG>
where
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintField<C>>,
    for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
{
    type SecretKey = C::ScalarField;

    type PublicKey = C;

    type SharedSecret = C;

    #[inline]
    fn derive(compiler: &mut (), secret_key: &Self::SecretKey) -> Self::PublicKey {
        Self::derive_owned(compiler, *secret_key)
    }

    #[inline]
    fn derive_owned(compiler: &mut (), secret_key: Self::SecretKey) -> Self::PublicKey {
        let _ = compiler;
        C::Affine::prime_subgroup_generator().mul(secret_key)
    }

    #[inline]
    fn agree(
        compiler: &mut (),
        secret_key: &Self::SecretKey,
        public_key: &Self::PublicKey,
    ) -> Self::SharedSecret {
        Self::agree_owned(compiler, *secret_key, *public_key)
    }

    #[inline]
    fn agree_owned(
        compiler: &mut (),
        secret_key: Self::SecretKey,
        mut public_key: Self::PublicKey,
    ) -> Self::SharedSecret {
        let _ = compiler;
        public_key *= secret_key;
        public_key
    }
}

#[cfg(feature = "arkworks")]
impl<C, GG> KeyAgreementScheme<R1CS<ConstraintField<C>>> for EllipticCurveDiffieHellman<C, GG>
where
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintField<C>>,
    for<'g> &'g GG: GroupOpsBounds<'g, C, GG>,
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
