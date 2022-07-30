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

use core::{fmt::Debug, hash::Hash};
use manta_crypto::{
    constraint::ProofSystemInput,
    eclair::{
        self,
        alloc::{
            mode::{Derived, Public, Secret},
            Allocate, Allocator, Constant, Variable,
        },
        bool::AssertEq,
    },
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
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "T::AuthorizationKey: Clone, T::Randomness: Clone"),
    Copy(bound = "T::AuthorizationKey: Copy, T::Randomness: Copy"),
    Debug(bound = "T::AuthorizationKey: Debug, T::Randomness: Debug"),
    Default(bound = "T::AuthorizationKey: Default, T::Randomness: Default"),
    Eq(bound = "T::AuthorizationKey: Eq, T::Randomness: Eq"),
    Hash(bound = "T::AuthorizationKey: Hash, T::Randomness: Hash"),
    PartialEq(bound = "T::AuthorizationKey: PartialEq, T::Randomness: PartialEq")
)]
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

    /// Converts `self` into a complete [`AuthorizationProof`] under the given `parameters`.
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

impl<T, COM> Variable<Secret, COM> for Authorization<T>
where
    T: AuthorizationKeyType + RandomnessType + Constant<COM> + ?Sized,
    AuthorizationKey<T>: Variable<Secret, COM, Type = AuthorizationKey<T::Type>>,
    Randomness<T>: Variable<Secret, COM, Type = Randomness<T::Type>>,
    T::Type: AuthorizationKeyType + RandomnessType,
{
    type Type = Authorization<T::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self::new(compiler.allocate_unknown(), compiler.allocate_unknown())
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(
            this.authorization_key.as_known(compiler),
            this.randomness.as_known(compiler),
        )
    }
}

/// Authorization Proof
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "Authorization<T>: Clone, T::AuthorizationKey: Clone"),
    Copy(bound = "Authorization<T>: Copy, T::AuthorizationKey: Copy"),
    Debug(bound = "Authorization<T>: Debug, T::AuthorizationKey: Debug"),
    Default(bound = "Authorization<T>: Default, T::AuthorizationKey: Default"),
    Eq(bound = "Authorization<T>: Eq, T::AuthorizationKey: Eq"),
    Hash(bound = "Authorization<T>: Hash, T::AuthorizationKey: Hash"),
    PartialEq(bound = "Authorization<T>: PartialEq, T::AuthorizationKey: PartialEq")
)]
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
    /// Builds a new [`AuthorizationProof`] from `authorization` and `randomized_authorization_key`.
    #[inline]
    pub fn new(
        authorization: Authorization<T>,
        randomized_authorization_key: T::AuthorizationKey,
    ) -> Self {
        Self {
            authorization,
            randomized_authorization_key,
        }
    }

    /// Asserts that `self` is a valid [`AuthorizationProof`].
    #[inline]
    pub fn assert_valid<COM>(&self, parameters: &T, compiler: &mut COM)
    where
        T: Randomize<T::AuthorizationKey, COM>,
        T::AuthorizationKey: eclair::cmp::PartialEq<T::AuthorizationKey, COM>,
        COM: AssertEq,
    {
        let randomized_authorization_key = self.authorization.randomize(parameters, compiler);
        compiler.assert_eq(
            &randomized_authorization_key,
            &self.randomized_authorization_key,
        )
    }

    /// Verifies that `self` was generated with the `signing_key`.
    #[inline]
    pub fn verify_construction(&self, parameters: &T, signing_key: &T::SigningKey) -> bool
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

    /// Extends proof public input with `self`.
    #[inline]
    pub fn extend_input<P>(&self, input: &mut P::Input)
    where
        P: ProofSystemInput<T::AuthorizationKey>,
    {
        P::extend(input, &self.randomized_authorization_key)
    }

    /// Extracts the ledger posting data from `self`.
    #[inline]
    pub fn into_post(self) -> T::AuthorizationKey {
        self.randomized_authorization_key
    }
}

impl<T, COM> Variable<Derived, COM> for AuthorizationProof<T>
where
    T: AuthorizationKeyType + RandomnessType + Constant<COM> + ?Sized,
    AuthorizationKey<T>: Variable<Secret, COM, Type = AuthorizationKey<T::Type>>
        + Variable<Public, COM, Type = AuthorizationKey<T::Type>>,
    Randomness<T>: Variable<Secret, COM, Type = Randomness<T::Type>>,
    T::Type: AuthorizationKeyType + RandomnessType,
{
    type Type = AuthorizationProof<T::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self::new(
            compiler.allocate_unknown(),
            compiler.allocate_unknown::<Public, _>(),
        )
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(
            this.authorization.as_known(compiler),
            this.randomized_authorization_key
                .as_known::<Public, _>(compiler),
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
    /// Verifies that `authorization_key`, `randomness`, and `randomized_authorization_key` were
    /// generated correctly using `signing_key`.
    fn verify(
        &self,
        signing_key: &Self::SigningKey,
        authorization_key: &Self::AuthorizationKey,
        randomness: &Self::Randomness,
        randomized_authorization_key: &Self::AuthorizationKey,
    ) -> bool;
}

/// Sign Result
///
/// This is the return type of the [`sign`] method.
pub type SignResult<S, E> = Result<
    (
        <S as signature::SignatureType>::Signature,
        <S as signature::MessageType>::Message,
    ),
    E,
>;

/// Signs `message` by first verifiying that the `authorization_proof` was created using
/// `signing_key` and using it to generate the signing key from `signing_key`.
#[inline]
pub fn sign<S, F, E>(
    scheme: &S,
    signing_key: &S::SigningKey,
    authorization_proof: AuthorizationProof<S>,
    signing_randomness: &signature::Randomness<S>,
    assign_authorization_key: F,
) -> Option<SignResult<S, E>>
where
    F: FnOnce(S::AuthorizationKey) -> Result<S::Message, E>,
    S: Verify + Randomize<S::SigningKey> + signature::Sign,
{
    if authorization_proof.verify_construction(scheme, signing_key) {
        match assign_authorization_key(authorization_proof.randomized_authorization_key) {
            Ok(message) => Some(Ok((
                scheme.sign(
                    &scheme.randomize(
                        signing_key,
                        &authorization_proof.authorization.randomness,
                        &mut (),
                    ),
                    signing_randomness,
                    &message,
                    &mut (),
                ),
                message,
            ))),
            Err(err) => Some(Err(err)),
        }
    } else {
        None
    }
}
