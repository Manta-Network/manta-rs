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
use eclair::alloc::{mode::Derived, Allocate, Allocator, Constant, Variable};
use openzl_util::{
    codec::{Encode, Write},
    convert::Field,
    rand::RngCore,
};

#[cfg(feature = "serde")]
use openzl_util::serde::{Deserialize, Serialize};

/// Spending Key
pub trait SpendingKeyType {
    /// Spending Key Type
    type SpendingKey;
}

/// Spending Key Type
pub type SpendingKey<T> = <T as SpendingKeyType>::SpendingKey;

/// Authorization Context
pub trait AuthorizationContextType {
    /// Authorization Context Type
    type AuthorizationContext;
}

/// Authorization Context Type
pub type AuthorizationContext<T> = <T as AuthorizationContextType>::AuthorizationContext;

/// Authorization Key
pub trait AuthorizationKeyType {
    /// Authorization Key Type
    type AuthorizationKey;
}

/// Authorization Key Type
pub type AuthorizationKey<T> = <T as AuthorizationKeyType>::AuthorizationKey;

/// Authorization Proof
pub trait AuthorizationProofType: AuthorizationKeyType {
    /// Authorization Proof Type
    type AuthorizationProof: Field<Self::AuthorizationKey>;
}

/// Authorization Proof Type
pub type AuthorizationProof<T> = <T as AuthorizationProofType>::AuthorizationProof;

/// Signing Key
pub trait SigningKeyType {
    /// Signing Key Type
    type SigningKey;
}

/// Signing Key Type
pub type SigningKey<T> = <T as SigningKeyType>::SigningKey;

/// Signature
pub trait SignatureType {
    /// Signature Type
    type Signature;
}

/// Signature Type
pub type Signature<T> = <T as SignatureType>::Signature;

/// Authorization Context Derivation
pub trait DeriveContext: AuthorizationContextType + SpendingKeyType {
    /// Derives the authorization context from the `spending_key`.
    fn derive_context(&self, spending_key: &Self::SpendingKey) -> Self::AuthorizationContext;
}

/// Authorization Context Proving
pub trait ProveAuthorization:
    AuthorizationContextType + AuthorizationProofType + SpendingKeyType
{
    /// Generates a proof that `authorization_context` is derived from `spending_key` correctly.
    fn prove<R>(
        &self,
        spending_key: &Self::SpendingKey,
        authorization_context: &Self::AuthorizationContext,
        rng: &mut R,
    ) -> Self::AuthorizationProof
    where
        R: RngCore + ?Sized;
}

/// Authorization Context Verification
pub trait VerifyAuthorization:
    AuthorizationContextType + AuthorizationProofType + SpendingKeyType
{
    /// Verifies that `authorization_context` is derived from `spending_key` using
    /// `authorization_proof`.
    fn verify(
        &self,
        spending_key: &Self::SpendingKey,
        authorization_context: &Self::AuthorizationContext,
        authorization_proof: &Self::AuthorizationProof,
    ) -> bool;

    /// Verifies that `authorization` is derived from `spending_key` using its inner authorization
    /// proof.
    #[inline]
    fn verify_from(
        &self,
        spending_key: &Self::SpendingKey,
        authorization: &Authorization<Self>,
    ) -> bool {
        authorization.verify(self, spending_key)
    }
}

/// Authorization Assertion
pub trait AssertAuthorized<COM = ()>: AuthorizationContextType + AuthorizationProofType {
    /// Asserts that `authorization_context` corresponds to `authorization_proof`.
    fn assert_authorized(
        &self,
        authorization_context: &Self::AuthorizationContext,
        authorization_proof: &Self::AuthorizationProof,
        compiler: &mut COM,
    );
}

/// Signing Key Derivation
pub trait DeriveSigningKey:
    AuthorizationContextType + AuthorizationProofType + SigningKeyType + SpendingKeyType
{
    /// Derives the signing key from `spending_key`, `authorization_context`, and the
    /// `authorization_proof`.
    fn derive_signing_key(
        &self,
        spending_key: &Self::SpendingKey,
        authorization_context: &Self::AuthorizationContext,
        authorization_proof: &Self::AuthorizationProof,
    ) -> Self::SigningKey;
}

/// Signing
pub trait Sign<M>: SignatureType + SigningKeyType {
    /// Signs `message` with the `signing_key`.
    fn sign<R>(&self, signing_key: &Self::SigningKey, message: &M, rng: &mut R) -> Self::Signature
    where
        R: RngCore + ?Sized;
}

/// Signature Verification
pub trait VerifySignature<M>: AuthorizationKeyType + SignatureType {
    /// Verifies that `signature` is a valid signature of `message` under `authorization_key`.
    fn verify(
        &self,
        authorization_key: &Self::AuthorizationKey,
        message: &M,
        signature: &Self::Signature,
    ) -> bool;
}

/// Authorization
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "T::AuthorizationContext: Deserialize<'de>, T::AuthorizationProof: Deserialize<'de>",
            serialize = "T::AuthorizationContext: Serialize, T::AuthorizationProof: Serialize",
        ),
        crate = "openzl_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "T::AuthorizationContext: Clone, T::AuthorizationProof: Clone"),
    Copy(bound = "T::AuthorizationContext: Copy, T::AuthorizationProof: Copy"),
    Debug(bound = "T::AuthorizationContext: Debug, T::AuthorizationProof: Debug"),
    Default(bound = "T::AuthorizationContext: Default, T::AuthorizationProof: Default"),
    Eq(bound = "T::AuthorizationContext: Eq, T::AuthorizationProof: Eq"),
    Hash(bound = "T::AuthorizationContext: Hash, T::AuthorizationProof: Hash"),
    PartialEq(bound = "T::AuthorizationContext: PartialEq, T::AuthorizationProof: PartialEq")
)]
pub struct Authorization<T>
where
    T: AuthorizationContextType + AuthorizationProofType + ?Sized,
{
    /// Authorization Context
    pub context: T::AuthorizationContext,

    /// Authorization Proof
    pub proof: T::AuthorizationProof,
}

impl<T> Authorization<T>
where
    T: AuthorizationContextType + AuthorizationProofType + ?Sized,
{
    /// Builds a new [`Authorization`] from `context` and `proof`.
    #[inline]
    pub fn new(context: T::AuthorizationContext, proof: T::AuthorizationProof) -> Self {
        Self { context, proof }
    }

    /// Builds a new [`Authorization`] from `parameters` and `spending_key`.
    #[inline]
    pub fn from_spending_key<R>(parameters: &T, spending_key: &T::SpendingKey, rng: &mut R) -> Self
    where
        T: DeriveContext + ProveAuthorization,
        R: RngCore + ?Sized,
    {
        let context = parameters.derive_context(spending_key);
        let proof = parameters.prove(spending_key, &context, rng);
        Self::new(context, proof)
    }

    /// Verifies that `self` is derived from `spending_key`.
    #[inline]
    pub fn verify(&self, parameters: &T, spending_key: &T::SpendingKey) -> bool
    where
        T: VerifyAuthorization,
    {
        parameters.verify(spending_key, &self.context, &self.proof)
    }

    /// Asserts that `self.context` corresponds to `self.proof`.
    #[inline]
    pub fn assert_authorized<COM>(&self, parameters: &T, compiler: &mut COM)
    where
        T: AssertAuthorized<COM>,
    {
        parameters.assert_authorized(&self.context, &self.proof, compiler)
    }
}

impl<T> Field<T::AuthorizationKey> for Authorization<T>
where
    T: AuthorizationContextType + AuthorizationProofType + ?Sized,
{
    #[inline]
    fn get(&self) -> &T::AuthorizationKey {
        Field::get(&self.proof)
    }

    #[inline]
    fn get_mut(&mut self) -> &mut T::AuthorizationKey {
        Field::get_mut(&mut self.proof)
    }

    #[inline]
    fn into(self) -> T::AuthorizationKey {
        Field::into(self.proof)
    }
}

impl<T, C, P, COM> Variable<Derived<(C, P)>, COM> for Authorization<T>
where
    T: AuthorizationContextType + AuthorizationProofType + Constant<COM> + ?Sized,
    T::Type: AuthorizationContextType + AuthorizationProofType,
    AuthorizationContext<T>: Variable<C, COM, Type = AuthorizationContext<T::Type>>,
    AuthorizationProof<T>: Variable<P, COM, Type = AuthorizationProof<T::Type>>,
{
    type Type = Authorization<T::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self::new(compiler.allocate_unknown(), compiler.allocate_unknown())
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(
            this.context.as_known(compiler),
            this.proof.as_known(compiler),
        )
    }
}

/// Signs `message` with the signing key generated by `spending_key` and `authorization`, checking
/// if `authorization` is valid for the `spending_key`.
#[inline]
pub fn sign<T, M, R>(
    parameters: &T,
    spending_key: &T::SpendingKey,
    authorization: Authorization<T>,
    message: &M,
    rng: &mut R,
) -> Option<AuthorizationSignature<T>>
where
    T: VerifyAuthorization + DeriveSigningKey + Sign<M>,
    R: RngCore + ?Sized,
{
    if authorization.verify(parameters, spending_key) {
        Some(AuthorizationSignature::generate(
            parameters,
            spending_key,
            authorization,
            message,
            rng,
        ))
    } else {
        None
    }
}

/// Authorization Signature
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "T::AuthorizationKey: Deserialize<'de>, T::Signature: Deserialize<'de>",
            serialize = "T::AuthorizationKey: Serialize, T::Signature: Serialize",
        ),
        crate = "openzl_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "T::AuthorizationKey: Clone, T::Signature: Clone"),
    Copy(bound = "T::AuthorizationKey: Copy, T::Signature: Copy"),
    Debug(bound = "T::AuthorizationKey: Debug, T::Signature: Debug"),
    Default(bound = "T::AuthorizationKey: Default, T::Signature: Default"),
    Eq(bound = "T::AuthorizationKey: Eq, T::Signature: Eq"),
    Hash(bound = "T::AuthorizationKey: Hash, T::Signature: Hash"),
    PartialEq(bound = "T::AuthorizationKey: PartialEq, T::Signature: PartialEq")
)]
pub struct AuthorizationSignature<T>
where
    T: AuthorizationKeyType + SignatureType,
{
    /// Authorization Key
    pub authorization_key: T::AuthorizationKey,

    /// Signature
    pub signature: T::Signature,
}

impl<T> AuthorizationSignature<T>
where
    T: AuthorizationKeyType + SignatureType,
{
    /// Builds a new [`AuthorizationSignature`] from `authorization_key` and `signature` without
    /// checking that the `authorization_key` is the correct key for `signature`.
    #[inline]
    pub fn new_unchecked(authorization_key: T::AuthorizationKey, signature: T::Signature) -> Self {
        Self {
            authorization_key,
            signature,
        }
    }

    /// Generates a new [`AuthorizationSignature`] by signing `message` with `spending_key` and
    /// `authorization`.
    #[inline]
    pub fn generate<M, R>(
        parameters: &T,
        spending_key: &T::SpendingKey,
        authorization: Authorization<T>,
        message: &M,
        rng: &mut R,
    ) -> Self
    where
        T: DeriveSigningKey + Sign<M>,
        R: RngCore + ?Sized,
    {
        let signature = parameters.sign(
            &parameters.derive_signing_key(
                spending_key,
                &authorization.context,
                &authorization.proof,
            ),
            message,
            rng,
        );
        Self::new_unchecked(Field::into(authorization), signature)
    }

    /// Verifies that `message` is commited to with `self` as the [`AuthorizationSignature`].
    #[inline]
    pub fn verify<M>(&self, parameters: &T, message: &M) -> bool
    where
        T: VerifySignature<M>,
    {
        parameters.verify(&self.authorization_key, message, &self.signature)
    }
}

impl<T> Encode for AuthorizationSignature<T>
where
    T: AuthorizationKeyType + SignatureType,
    T::AuthorizationKey: Encode,
    T::Signature: Encode,
{
    #[inline]
    fn encode<W>(&self, mut writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.authorization_key.encode(&mut writer)?;
        self.signature.encode(&mut writer)?;
        Ok(())
    }
}

/// Testing Framework
#[cfg(feature = "test")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "test")))]
pub mod test {
    use super::*;

    /// Verifies that the signature generated by `spending_key` for `message` is correct and
    /// corresponds to a valid authorization.
    #[inline]
    pub fn signature_correctness<T, M, R>(
        parameters: &T,
        spending_key: &T::SpendingKey,
        message: &M,
        rng: &mut R,
    ) -> bool
    where
        T: DeriveContext
            + DeriveSigningKey
            + ProveAuthorization
            + Sign<M>
            + VerifyAuthorization
            + VerifySignature<M>,
        R: RngCore + ?Sized,
    {
        let authorization = Authorization::from_spending_key(parameters, spending_key, rng);
        let signature = sign(parameters, spending_key, authorization, message, rng)
            .expect("Unable to sign message.");
        signature.verify(parameters, message)
    }
}
