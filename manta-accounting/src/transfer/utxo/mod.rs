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

//! UTXO Protocols
//!
//! The current protocol is referred to by [`protocol`] and older protocols are marked by their
//! version number. The [`VERSION`] number can be queried for the current protocol and can be used
//! to select the protocol version. The transfer protocol is built up from a given [`Mint`] and
//! [`Spend`] implementation.

use core::{fmt::Debug, hash::Hash, marker::PhantomData, ops::Deref};
use manta_crypto::{
    accumulator::{self, ItemHashFunction, MembershipProof},
    constraint::{Allocate, Allocator, Constant, Derived, ProofSystemInput, Var, Variable},
    signature::Sign,
};

pub mod v1;

#[doc(inline)]
pub use v1 as protocol;

/// Current UTXO Protocol Version
pub const VERSION: u8 = protocol::VERSION;

/// Authority
pub trait AuthorityType {
    /// Authority Type
    type Authority;
}

/// Authority Type
pub type Authority<T> = <T as AuthorityType>::Authority;

/// Authorization
pub trait AuthorizationType {
    /// Authorization Type
    type Authorization;
}

/// Authorization Type
pub type Authorization<T> = <T as AuthorizationType>::Authorization;

/// Authorization Proof
pub struct AuthorizationProof<T>
where
    T: AuthorityType + AuthorizationType,
{
    /// Authority
    pub authority: T::Authority,

    /// Authorization
    pub authorization: T::Authorization,
}

impl<T> AuthorizationProof<T>
where
    T: AuthorityType + AuthorizationType,
{
    /// Builds a new [`AuthorizationProof`] from `authority` and `authorization`.
    #[inline]
    pub fn new(authority: T::Authority, authorization: T::Authorization) -> Self {
        Self {
            authority,
            authorization,
        }
    }

    /// Extends proof public input with `self`.
    #[inline]
    pub fn extend_input<P>(&self, input: &mut P::Input)
    where
        P: ProofSystemInput<T::Authorization>,
    {
        P::extend(input, &self.authorization)
    }

    /// Asserts that `self` is a valid [`AuthorizationProof`] according to `authorization_scheme`.
    #[inline]
    pub fn assert_valid<COM>(&self, authorization_scheme: &T, compiler: &mut COM)
    where
        T: Authorize<COM>,
    {
        authorization_scheme.assert_authorized(&self.authority, &self.authorization, compiler)
    }
}

impl<T, M, N, COM> Variable<Derived<(M, N)>, COM> for AuthorizationProof<T>
where
    T: AuthorityType + AuthorizationType + Constant<COM>,
    T::Authority: Variable<M, COM>,
    T::Authorization: Variable<N, COM>,
    T::Type: AuthorityType<Authority = Var<T::Authority, M, COM>>
        + AuthorizationType<Authorization = Var<T::Authorization, N, COM>>,
{
    type Type = AuthorizationProof<T::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self::new(compiler.allocate_unknown(), compiler.allocate_unknown())
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(
            this.authority.as_known(compiler),
            this.authorization.as_known(compiler),
        )
    }
}

/// Authorize
pub trait Authorize<COM = ()>: AuthorityType + AuthorizationType {
    /// Asserts that `authority` produces the correct `authorization`.
    fn assert_authorized(
        &self,
        authority: &Self::Authority,
        authorization: &Self::Authorization,
        compiler: &mut COM,
    );
}

/// Authorization Verification
pub trait VerifyAuthorization: AuthorizationType {
    /// Verifying Key
    type VerifyingKey;

    /// Verifies that `authorization` is well-formed with `verifying_key`.
    fn verify_authorization(
        &self,
        verifying_key: &Self::VerifyingKey,
        authorization: &Self::Authorization,
    ) -> bool;
}

/// Verifies the `authorization` with `signing_key` and then signs the `message` if the verification
/// passed.
#[inline]
pub fn sign_authorization<S>(
    signature_scheme: &S,
    signing_key: &S::SigningKey,
    authorization: &S::Authorization,
    randomness: &S::Randomness,
    message: &S::Message,
) -> Option<S::Signature>
where
    S: Sign + VerifyAuthorization<VerifyingKey = S::SigningKey>,
{
    if signature_scheme.verify_authorization(signing_key, authorization) {
        Some(signature_scheme.sign(signing_key, randomness, message, &mut ()))
    } else {
        None
    }
}

/// Asset
pub trait AssetType {
    /// Asset Type
    type Asset;
}

/// Asset Type
pub type Asset<T> = <T as AssetType>::Asset;

/// Unspent Transaction Output
pub trait UtxoType {
    /// Unspent Transaction Output Type
    type Utxo;
}

/// Unspent Transaction Output Type
pub type Utxo<T> = <T as UtxoType>::Utxo;

/// UTXO Minting
pub trait Mint<COM = ()>: AssetType + UtxoType {
    /// Mint Secret Type
    type Secret;

    /// UTXO Note Type
    type Note;

    /// Returns the asset inside of `utxo` asserting that `secret`, `utxo`, and `note` are
    /// well-formed.
    fn well_formed_asset(
        &self,
        secret: &Self::Secret,
        utxo: &Self::Utxo,
        note: &Self::Note,
        compiler: &mut COM,
    ) -> Self::Asset;
}

/// Note Type
pub type Note<M, COM = ()> = <M as Mint<COM>>::Note;

/// UTXO Spending
pub trait Spend<COM = ()>:
    Authorize<COM> + ItemHashFunction<Self::Utxo, COM> + AssetType + UtxoType
{
    /// UTXO Accumulator Model Type
    type UtxoAccumulatorModel: accumulator::Model<COM, Item = Self::Item>;

    /// Spend Secret Type
    type Secret;

    /// Nullifier Type
    type Nullifier;

    /// Asserts that the two nullifiers, `lhs` and `rhs`, are equal.
    fn assert_equal_nullifiers(
        &self,
        lhs: &Self::Nullifier,
        rhs: &Self::Nullifier,
        compiler: &mut COM,
    );

    /// Returns the asset and its nullifier inside of `utxo` asserting that `secret` and `utxo` are
    /// well-formed and that `utxo_membership_proof` is a valid proof.
    fn well_formed_asset(
        &self,
        utxo_accumulator_model: &Self::UtxoAccumulatorModel,
        authority: &Self::Authority,
        secret: &Self::Secret,
        utxo: &Self::Utxo,
        utxo_membership_proof: &UtxoMembershipProof<Self, COM>,
        compiler: &mut COM,
    ) -> (Self::Asset, Self::Nullifier);

    /// Returns the nullifier inside of `utxo` asserting that `secret` and `utxo` are well-formed
    /// and that `utxo_membership_proof` is a valid proof.
    ///
    /// # Implementation Note
    ///
    /// By default this method calls [`well_formed_asset`] and projects out the nullifier from the
    /// tuple. An implementation of this method should be given whenever computing _only_ the
    /// nullifier is more efficient than this default.
    ///
    /// [`well_formed_asset`]: Self::well_formed_asset
    #[inline]
    fn well_formed_nullifier(
        &self,
        utxo_accumulator_model: &Self::UtxoAccumulatorModel,
        authority: &Self::Authority,
        secret: &Self::Secret,
        utxo: &Self::Utxo,
        utxo_membership_proof: &UtxoMembershipProof<Self, COM>,
        compiler: &mut COM,
    ) -> Self::Nullifier {
        self.well_formed_asset(
            utxo_accumulator_model,
            authority,
            secret,
            utxo,
            utxo_membership_proof,
            compiler,
        )
        .1
    }
}

/// UTXO Accumulator Model Type
pub type UtxoAccumulatorModel<S, COM = ()> = <S as Spend<COM>>::UtxoAccumulatorModel;

/// UTXO Accumulator Item Type
pub type UtxoAccumulatorItem<S, COM = ()> =
    <UtxoAccumulatorModel<S, COM> as accumulator::Types>::Item;

/// UTXO Accumulator Witness Type
pub type UtxoAccumulatorWitness<S, COM = ()> =
    <UtxoAccumulatorModel<S, COM> as accumulator::Types>::Witness;

/// UTXO Accumulator Output Type
pub type UtxoAccumulatorOutput<S, COM = ()> =
    <UtxoAccumulatorModel<S, COM> as accumulator::Types>::Output;

/// UTXO Membership Proof Type
pub type UtxoMembershipProof<S, COM = ()> = MembershipProof<UtxoAccumulatorModel<S, COM>, COM>;

/// Nullifier Type
pub type Nullifier<S, COM = ()> = <S as Spend<COM>>::Nullifier;

/// Full Parameters Owned
///
/// This `struct` uses a lifetime marker to tie it down to a particular instance of
/// [`FullParametersRef`] during allocation.
pub struct FullParameters<'p, P, COM = ()>
where
    P: Mint<COM> + Spend<COM>,
{
    /// Base Parameters
    pub base: P,

    /// UTXO Accumulator Model
    pub utxo_accumulator_model: P::UtxoAccumulatorModel,

    /// Type Parameter Marker
    __: PhantomData<&'p ()>,
}

impl<'p, P, COM> FullParameters<'p, P, COM>
where
    P: Mint<COM> + Spend<COM>,
{
    /// Builds a new [`FullParameters`] from `base` and `utxo_accumulator_model`.
    #[inline]
    pub fn new(base: P, utxo_accumulator_model: P::UtxoAccumulatorModel) -> Self {
        Self {
            base,
            utxo_accumulator_model,
            __: PhantomData,
        }
    }
}

impl<'p, P, COM> Constant<COM> for FullParameters<'p, P, COM>
where
    P: Mint<COM> + Spend<COM> + Constant<COM>,
    P::UtxoAccumulatorModel: Constant<COM, Type = UtxoAccumulatorModel<P::Type>>,
    P::Type: 'p + Mint + Spend,
    UtxoAccumulatorModel<P::Type>: 'p,
{
    type Type = FullParametersRef<'p, P::Type>;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(
            this.base.as_constant(compiler),
            this.utxo_accumulator_model.as_constant(compiler),
        )
    }
}

/// Full Parameters Reference
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = ""),
    Debug(bound = "P: Debug, P::UtxoAccumulatorModel: Debug"),
    Eq(bound = "P: Eq, P::UtxoAccumulatorModel: Eq"),
    Hash(bound = "P: Hash, P::UtxoAccumulatorModel: Hash"),
    PartialEq(bound = "P: PartialEq, P::UtxoAccumulatorModel: PartialEq")
)]
pub struct FullParametersRef<'p, P, COM = ()>
where
    P: Mint<COM> + Spend<COM>,
{
    /// Base Parameters
    pub base: &'p P,

    /// UTXO Accumulator Model
    pub utxo_accumulator_model: &'p P::UtxoAccumulatorModel,
}

impl<'p, P, COM> FullParametersRef<'p, P, COM>
where
    P: Mint<COM> + Spend<COM>,
{
    /// Builds a new [`FullParametersRef`] from `base` and `utxo_accumulator_model`.
    #[inline]
    pub fn new(base: &'p P, utxo_accumulator_model: &'p P::UtxoAccumulatorModel) -> Self {
        Self {
            base,
            utxo_accumulator_model,
        }
    }
}

impl<'p, P, COM> AsRef<P> for FullParametersRef<'p, P, COM>
where
    P: Mint<COM> + Spend<COM>,
{
    #[inline]
    fn as_ref(&self) -> &P {
        self.base
    }
}

impl<'p, P, COM> Deref for FullParametersRef<'p, P, COM>
where
    P: Mint<COM> + Spend<COM>,
{
    type Target = P;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.base
    }
}
