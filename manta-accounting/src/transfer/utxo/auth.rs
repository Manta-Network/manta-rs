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

//! Authorization

use manta_crypto::{
    rand::{CryptoRng, RngCore},
    signature::{self, SigningKeyType},
};

/// Authorization Key
pub trait AuthorizationKeyType {
    /// Authorization Key Type
    type AuthorizationKey;
}

/// Authorization Key Type
pub type AuthorizationKey<T> = <T as AuthorizationKeyType>::AuthorizationKey;

/// Randomness
pub trait RandomnessType {
    /// Randomness Type
    type Randomness;
}

/// Randomness Type
pub type Randomness<T> = <T as RandomnessType>::Randomness;

/// Authorization
pub struct Authorization<T>
where
    T: AuthorizationKeyType + RandomnessType + ?Sized,
{
    /// Authorization Key
    pub authorization_key: T::AuthorizationKey,

    /// Randomness
    pub randomness: T::Randomness,
}

impl<T> Authorization<T>
where
    T: AuthorizationKeyType + RandomnessType + ?Sized,
{
    /// Builds a new [`Authorization`] from `authorization_key` and `randomness`.
    #[inline]
    pub fn new(authorization_key: T::AuthorizationKey, randomness: T::Randomness) -> Self {
        Self {
            authorization_key,
            randomness,
        }
    }

    /// Randomizes `self.authorization_key` using `self.randomness` under the given `parameters`.
    #[inline]
    pub fn randomize<COM>(&self, parameters: &T, compiler: &mut COM) -> T::AuthorizationKey
    where
        T: Randomize<T::AuthorizationKey, COM>,
    {
        parameters.randomize(&self.authorization_key, &self.randomness, compiler)
    }

    ///
    #[inline]
    pub fn into_proof<COM>(self, parameters: &T, compiler: &mut COM) -> AuthorizationProof<T>
    where
        T: Randomize<T::AuthorizationKey, COM>,
    {
        AuthorizationProof {
            randomized_authorization_key: self.randomize(parameters, compiler),
            authorization: self,
        }
    }
}

/// Authorization Proof
pub struct AuthorizationProof<T>
where
    T: AuthorizationKeyType + RandomnessType + ?Sized,
{
    /// Authorization
    pub authorization: Authorization<T>,

    /// Randomized Authorization Key
    pub randomized_authorization_key: T::AuthorizationKey,
}

impl<T> AuthorizationProof<T>
where
    T: AuthorizationKeyType + RandomnessType + ?Sized,
{
    ///
    #[inline]
    pub fn verify(&self, parameters: &T, signing_key: &T::SigningKey) -> bool
    where
        T: Verify,
    {
        parameters.verify(
            signing_key,
            &self.authorization.authorization_key,
            &self.authorization.randomness,
            &self.randomized_authorization_key,
        )
    }
}

/// Randomize
pub trait Randomize<T, COM = ()>: RandomnessType {
    /// Randomizes `value` with `randomness`.
    fn randomize(&self, value: &T, randomness: &Self::Randomness, compiler: &mut COM) -> T;
}

/// Authorization Generation
pub trait Generate: AuthorizationKeyType + RandomnessType + SigningKeyType {
    /// Generates an authorization for `signing_key`.
    fn generate<R>(&self, signing_key: &Self::SigningKey, rng: &mut R) -> Authorization<Self>
    where
        R: CryptoRng + RngCore + ?Sized;
}

/// Authorization Verification
pub trait Verify: AuthorizationKeyType + RandomnessType + SigningKeyType {
    ///
    fn verify(
        &self,
        signing_key: &Self::SigningKey,
        authorization_key: &Self::AuthorizationKey,
        randomness: &Self::Randomness,
        randomized_authorization_key: &Self::AuthorizationKey,
    ) -> bool;
}

/*
/// Signs `message` by first verifiying the `authorization_proof` and using it to generate the
/// signing key from `authorization_key`.
#[inline]
pub fn sign<S>(
    scheme: &S,
    authorization_key: &S::AuthorizationKey,
    authorization_proof: &AuthorizationProof<S>,
    randomized_authorization: &S::Authorization,
    signing_randomness: &signature::Randomness<S>,
    message: &S::Message,
) -> Option<S::Signature>
where
    S: Randomize<S::AuthorizationKey> + signature::Sign<SigningKey = S::AuthorizationKey> + Verify,
{
    if scheme.verify(
        authorization_key,
        authorization_proof,
        randomized_authorization,
    ) {
        Some(scheme.sign(
            &scheme.randomize(authorization_key, &authorization_proof.randomness, &mut ()),
            signing_randomness,
            message,
            &mut (),
        ))
    } else {
        None
    }
}
*/
