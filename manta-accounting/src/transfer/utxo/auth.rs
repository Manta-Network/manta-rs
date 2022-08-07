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
    eclair::{
        self,
        alloc::{
            mode::{Derived, Public, Secret},
            Allocate, Allocator, Constant, Variable,
        },
        bool::AssertEq,
    },
    rand::RngCore,
};

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
    type AuthorizationProof: AsRef<Self::AuthorizationKey> + Into<Self::AuthorizationKey>;
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

/// Derivation Authorization
pub trait DeriveAuthorization:
    AuthorizationContextType + AuthorizationProofType + SpendingKeyType
{
    ///
    fn derive<R>(
        &self,
        spending_key: &Self::SpendingKey,
        rng: &mut R,
    ) -> (Self::AuthorizationContext, Self::AuthorizationProof)
    where
        R: RngCore + ?Sized;

    ///
    #[inline]
    fn derive_into<R>(&self, spending_key: &Self::SpendingKey, rng: &mut R) -> Authorization<Self>
    where
        R: RngCore + ?Sized,
    {
        Authorization::from_spending_key(self, spending_key, rng)
    }
}

///
pub trait VerifyAuthorization:
    AuthorizationContextType + AuthorizationProofType + SpendingKeyType
{
    ///
    fn verify(
        &self,
        spending_key: &Self::SpendingKey,
        authorization_context: &Self::AuthorizationContext,
        authorization_proof: &Self::AuthorizationProof,
    ) -> bool;

    ///
    #[inline]
    fn verify_from(
        &self,
        spending_key: &Self::SpendingKey,
        authorization: &Authorization<Self>,
    ) -> bool {
        authorization.verify(self, spending_key)
    }
}

///
pub trait AssertAuthorized<COM = ()>: AuthorizationContextType + AuthorizationProofType {
    ///
    fn assert_authorized(
        &self,
        authorization_context: &Self::AuthorizationContext,
        authorization_proof: &Self::AuthorizationProof,
        compiler: &mut COM,
    );
}

///
pub trait DeriveSigningKey:
    AuthorizationContextType + AuthorizationProofType + SigningKeyType + SpendingKeyType
{
    ///
    fn derive(
        &self,
        spending_key: &Self::SpendingKey,
        authorization_context: &Self::AuthorizationContext,
        authorization_proof: &Self::AuthorizationProof,
    ) -> Self::SigningKey;
}

///
pub trait Sign<M>: SignatureType + SigningKeyType {
    ///
    fn sign<R>(&self, signing_key: &Self::SigningKey, message: &M, rng: &mut R) -> Self::Signature
    where
        R: RngCore + ?Sized;
}

///
pub trait VerifySignature<M>: AuthorizationKeyType + SignatureType {
    ///
    fn verify(
        &self,
        authorization_key: &Self::AuthorizationKey,
        signature: &Self::Signature,
        message: &M,
    ) -> bool;
}

/// Authorization
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
    ///
    #[inline]
    pub fn new(context: T::AuthorizationContext, proof: T::AuthorizationProof) -> Self {
        Self { context, proof }
    }

    ///
    #[inline]
    pub fn from_spending_key<R>(parameters: &T, spending_key: &T::SpendingKey, rng: &mut R) -> Self
    where
        T: DeriveAuthorization,
        R: RngCore + ?Sized,
    {
        let (context, proof) = parameters.derive(spending_key, rng);
        Self::new(context, proof)
    }

    ///
    #[inline]
    pub fn verify(&self, parameters: &T, spending_key: &T::SpendingKey) -> bool
    where
        T: VerifyAuthorization,
    {
        parameters.verify(spending_key, &self.context, &self.proof)
    }

    ///
    #[inline]
    pub fn assert_authorized<COM>(&self, parameters: &T, compiler: &mut COM)
    where
        T: AssertAuthorized<COM>,
    {
        parameters.assert_authorized(&self.context, &self.proof, compiler)
    }

    ///
    #[inline]
    pub fn authorization_key(&self) -> &T::AuthorizationKey {
        self.proof.as_ref()
    }

    ///
    #[inline]
    pub fn into_authorization_key(self) -> T::AuthorizationKey {
        self.proof.into()
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

///
#[inline]
pub fn sign<T, M, R>(
    parameters: &T,
    spending_key: &T::SpendingKey,
    authorization: &Authorization<T>,
    message: &M,
    rng: &mut R,
) -> Option<T::Signature>
where
    T: VerifyAuthorization + DeriveSigningKey + Sign<M>,
    R: RngCore + ?Sized,
{
    if authorization.verify(parameters, spending_key) {
        Some(parameters.sign(
            &parameters.derive(spending_key, &authorization.context, &authorization.proof),
            message,
            rng,
        ))
    } else {
        None
    }
}
