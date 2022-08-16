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

//! Key Agreement Schemes

/// Secret Key
pub trait SecretKeyType {
    /// Secret Key Type
    type SecretKey;
}

impl<T> SecretKeyType for &T
where
    T: SecretKeyType,
{
    type SecretKey = T::SecretKey;
}

/// Secret Key Type
pub type SecretKey<T> = <T as SecretKeyType>::SecretKey;

/// Ephemeral Secret Key
pub trait EphemeralSecretKeyType {
    /// Ephemeral Secret Key Type
    type EphemeralSecretKey;
}

impl<T> EphemeralSecretKeyType for &T
where
    T: EphemeralSecretKeyType,
{
    type EphemeralSecretKey = T::EphemeralSecretKey;
}

/// Ephemeral Secret Key Type
pub type EphemeralSecretKey<T> = <T as EphemeralSecretKeyType>::EphemeralSecretKey;

/// Public Key
pub trait PublicKeyType {
    /// Public Key Type
    type PublicKey;
}

impl<T> PublicKeyType for &T
where
    T: PublicKeyType,
{
    type PublicKey = T::PublicKey;
}

/// Public Key Type
pub type PublicKey<T> = <T as PublicKeyType>::PublicKey;

/// Ephemeral Public Key
pub trait EphemeralPublicKeyType {
    /// Ephemeral Public Key Type
    type EphemeralPublicKey;
}

impl<T> EphemeralPublicKeyType for &T
where
    T: EphemeralPublicKeyType,
{
    type EphemeralPublicKey = T::EphemeralPublicKey;
}

/// Ephemeral Public Key Type
pub type EphemeralPublicKey<T> = <T as EphemeralPublicKeyType>::EphemeralPublicKey;

/// Shared Secret
pub trait SharedSecretType {
    /// Shared Secret Type
    type SharedSecret;
}

impl<T> SharedSecretType for &T
where
    T: SharedSecretType,
{
    type SharedSecret = T::SharedSecret;
}

/// Shared Secret Type
pub type SharedSecret<T> = <T as SharedSecretType>::SharedSecret;

/// Public Key Derivation
pub trait Derive<COM = ()>: PublicKeyType + SecretKeyType {
    /// Derives a [`PublicKey`](PublicKeyType::PublicKey) from `secret_key`.
    fn derive(&self, secret_key: &Self::SecretKey, compiler: &mut COM) -> Self::PublicKey;
}

impl<K, COM> Derive<COM> for &K
where
    K: Derive<COM>,
{
    #[inline]
    fn derive(&self, secret_key: &Self::SecretKey, compiler: &mut COM) -> Self::PublicKey {
        (*self).derive(secret_key, compiler)
    }
}

/// Ephemeral Public Key Derivation
pub trait DeriveEphemeral<COM = ()>: EphemeralPublicKeyType + EphemeralSecretKeyType {
    /// Derives a [`EphemeralPublicKey`](EphemeralPublicKeyType::EphemeralPublicKey) from
    /// `ephemeral_secret_key`.
    fn derive_ephemeral(
        &self,
        ephemeral_secret_key: &Self::EphemeralSecretKey,
        compiler: &mut COM,
    ) -> Self::EphemeralPublicKey;
}

impl<K, COM> DeriveEphemeral<COM> for &K
where
    K: DeriveEphemeral<COM>,
{
    #[inline]
    fn derive_ephemeral(
        &self,
        ephemeral_secret_key: &Self::EphemeralSecretKey,
        compiler: &mut COM,
    ) -> Self::EphemeralPublicKey {
        (*self).derive_ephemeral(ephemeral_secret_key, compiler)
    }
}

/// Key Agreement Secret Generation
pub trait GenerateSecret<COM = ()>:
    EphemeralSecretKeyType + PublicKeyType + SharedSecretType
{
    /// Performs the agreement protocol on `public_key` and `ephemeral_secret_key` to arrive at the
    /// [`SharedSecret`](SharedSecretType::SharedSecret).
    fn generate_secret(
        &self,
        public_key: &Self::PublicKey,
        ephemeral_secret_key: &Self::EphemeralSecretKey,
        compiler: &mut COM,
    ) -> Self::SharedSecret;
}

impl<K, COM> GenerateSecret<COM> for &K
where
    K: GenerateSecret<COM>,
{
    #[inline]
    fn generate_secret(
        &self,
        public_key: &Self::PublicKey,
        ephemeral_secret_key: &Self::EphemeralSecretKey,
        compiler: &mut COM,
    ) -> Self::SharedSecret {
        (*self).generate_secret(public_key, ephemeral_secret_key, compiler)
    }
}

/// Key Agreement
pub trait Agree<COM = ()>: PublicKeyType + SecretKeyType + SharedSecretType {
    /// Performs the agreement protocol on `public_key` and `secret_key` to arrive at the
    /// [`SharedSecret`](SharedSecretType::SharedSecret).
    fn agree(
        &self,
        public_key: &Self::PublicKey,
        secret_key: &Self::SecretKey,
        compiler: &mut COM,
    ) -> Self::SharedSecret;
}

impl<K, COM> Agree<COM> for &K
where
    K: Agree<COM>,
{
    #[inline]
    fn agree(
        &self,
        public_key: &Self::PublicKey,
        secret_key: &Self::SecretKey,
        compiler: &mut COM,
    ) -> Self::SharedSecret {
        (*self).agree(public_key, secret_key, compiler)
    }
}

/// Key Agreement Secret Reconstruction
pub trait ReconstructSecret<COM = ()>:
    EphemeralPublicKeyType + SecretKeyType + SharedSecretType
{
    /// Performs the agreement protocol on `ephemeral_public_key` and `secret_key` to arrive at the
    /// [`SharedSecret`](SharedSecretType::SharedSecret).
    fn reconstruct_secret(
        &self,
        ephemeral_public_key: &Self::EphemeralPublicKey,
        secret_key: &Self::SecretKey,
        compiler: &mut COM,
    ) -> Self::SharedSecret;
}

impl<K, COM> ReconstructSecret<COM> for &K
where
    K: ReconstructSecret<COM>,
{
    #[inline]
    fn reconstruct_secret(
        &self,
        ephemeral_public_key: &Self::EphemeralPublicKey,
        secret_key: &Self::SecretKey,
        compiler: &mut COM,
    ) -> Self::SharedSecret {
        (*self).reconstruct_secret(ephemeral_public_key, secret_key, compiler)
    }
}

/// Testing Framework
#[cfg(feature = "test")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "test")))]
pub mod test {
    use super::*;
    use core::fmt::Debug;

    /// Tests if the `agreement` property is satisfied for `K`.
    #[inline]
    pub fn agreement<K>(scheme: &K, lhs: &K::SecretKey, rhs: &K::SecretKey)
    where
        K: Agree + Derive,
        K::SharedSecret: Debug + PartialEq,
    {
        assert_eq!(
            scheme.agree(&scheme.derive(rhs, &mut ()), lhs, &mut ()),
            scheme.agree(&scheme.derive(lhs, &mut ()), rhs, &mut ()),
            "Key agreement schemes should satisfy the agreement property."
        )
    }
}
