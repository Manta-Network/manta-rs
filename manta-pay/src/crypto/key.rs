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

use ark_ec::{AffineCurve, ProjectiveCurve};
use blake2::{Blake2s, Digest};
use core::marker::PhantomData;
use manta_crypto::key::{KeyAgreementScheme, KeyDerivationFunction};
use manta_util::into_array_unchecked;

/// Elliptic Curve Diffie Hellman Protocol
pub struct EllipticCurveDiffieHellman<C>(PhantomData<C>)
where
    C: ProjectiveCurve;

impl<C> KeyAgreementScheme for EllipticCurveDiffieHellman<C>
where
    C: ProjectiveCurve,
{
    type SecretKey = C::ScalarField;

    type PublicKey = C;

    type SharedSecret = C;

    #[inline]
    fn derive(secret_key: &Self::SecretKey) -> Self::PublicKey {
        Self::derive_owned(*secret_key)
    }

    #[inline]
    fn derive_owned(secret_key: Self::SecretKey) -> Self::PublicKey {
        C::Affine::prime_subgroup_generator().mul(secret_key)
    }

    #[inline]
    fn agree(secret_key: &Self::SecretKey, public_key: &Self::PublicKey) -> Self::SharedSecret {
        Self::agree_owned(*secret_key, *public_key)
    }

    #[inline]
    fn agree_owned(secret_key: Self::SecretKey, public_key: Self::PublicKey) -> Self::SharedSecret {
        public_key *= secret_key;
        public_key
    }
}

/// Blake2s KDF
pub struct Blake2sKdf;

impl<T> KeyDerivationFunction<T, [u8; 32]> for Blake2sKdf
where
    T: AsRef<[u8]>,
{
    #[inline]
    fn derive(secret: T) -> [u8; 32] {
        let mut hasher = Blake2s::new();
        hasher.update(secret.as_ref());
        hasher.update(b"manta kdf instantiated with blake2s hash function");
        into_array_unchecked(hasher.finalize())
    }
}
