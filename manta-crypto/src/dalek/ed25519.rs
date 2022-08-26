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

//! Dalek Cryptography `ed25519` Backend

use crate::{
    rand::{CryptoRng, Rand, RngCore},
    signature::{
        self, RandomnessType, Sign, SignatureType, SigningKeyType, Verify, VerifyingKeyType,
    },
};
use core::marker::PhantomData;
use manta_util::AsBytes;

pub use ed25519_dalek::*;

/// Converts `bytes` into a [`SecretKey`].
#[inline]
pub fn secret_key_from_bytes(bytes: [u8; SECRET_KEY_LENGTH]) -> SecretKey {
    match SecretKey::from_bytes(&bytes) {
        Ok(secret_key) => secret_key,
        _ => {
            unreachable!("We are guaranteed the correct number of bytes from `SECRET_KEY_LENGTH`.")
        }
    }
}

/// Clones the `secret_key` by serializing and then deserializing.
#[inline]
pub fn clone_secret_key(secret_key: &SecretKey) -> SecretKey {
    secret_key_from_bytes(secret_key.to_bytes())
}

/// Generates a [`Keypair`] from `secret_key`.
#[inline]
pub fn keypair(secret_key: &SecretKey) -> Keypair {
    Keypair {
        public: secret_key.into(),
        secret: clone_secret_key(secret_key),
    }
}

/// Generates a [`SecretKey`] from `rng`.
#[inline]
pub fn generate_secret_key<R>(rng: &mut R) -> SecretKey
where
    R: CryptoRng + RngCore,
{
    secret_key_from_bytes(rng.gen())
}

/// Generates a [`Keypair`] from `rng`.
#[inline]
pub fn generate_keypair<R>(rng: &mut R) -> Keypair
where
    R: CryptoRng + RngCore,
{
    let secret_key = generate_secret_key(rng);
    Keypair {
        public: (&secret_key).into(),
        secret: secret_key,
    }
}

/// Edwards Curve Signature Scheme for the `Curve25519` Elliptic Curve
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Ed25519<M>(PhantomData<M>);

impl<M> MessageType for Ed25519<M> {
    type Message = M;
}

impl<M> RandomnessType for Ed25519<M> {
    /// The `ed25519_dalek` crate provides randomness internally so we set it as `()` here.
    type Randomness = ();
}

impl<M> SignatureType for Ed25519<M> {
    type Signature = Signature;
}

impl<M> SigningKeyType for Ed25519<M> {
    type SigningKey = SecretKey;
}

impl<M> VerifyingKeyType for Ed25519<M> {
    type VerifyingKey = PublicKey;
}

impl<M> Sign for Ed25519<M>
where
    M: AsBytes,
{
    #[inline]
    fn sign(
        &self,
        signing_key: &Self::SigningKey,
        randomness: &Self::Randomness,
        message: &Self::Message,
        compiler: &mut (),
    ) -> Self::Signature {
        let _ = (randomness, compiler);
        keypair(signing_key).sign(&message.as_bytes())
    }
}

impl<M> Verify for Ed25519<M>
where
    M: AsBytes,
{
    type Verification = Result<(), SignatureError>;

    #[inline]
    fn verify(
        &self,
        verifying_key: &Self::VerifyingKey,
        message: &Self::Message,
        signature: &Self::Signature,
        compiler: &mut (),
    ) -> Self::Verification {
        let _ = compiler;
        verifying_key.verify(&message.as_bytes(), signature)
    }
}
