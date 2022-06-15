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

//! Conversion Primitives and Adapters

use crate::encryption::{
    CiphertextType, Decrypt, DecryptionKeyType, DecryptionTypes, Derive, Encrypt,
    EncryptionKeyType, EncryptionTypes, HeaderType, PlaintextType,
};
use core::marker::PhantomData;

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Forward Conversion Type
pub trait ForwardType {
    /// Plaintext Type
    type Plaintext;
}

/// Forward Conversion
///
/// When encrypting over [`TargetPlaintext`] we can apply the [`as_target`] conversion function to
/// objects of type [`Plaintext`] to make them compatible with encryption.
///
/// [`TargetPlaintext`]: Self::TargetPlaintext
/// [`as_target`]: Self::as_target
/// [`Plaintext`]: ForwardType::Plaintext
pub trait Forward<COM = ()>: ForwardType {
    /// Target Plaintext Type
    type TargetPlaintext;

    /// Converts `source` into the [`TargetPlaintext`](Self::TargetPlaintext) type.
    fn as_target(source: &Self::Plaintext, compiler: &mut COM) -> Self::TargetPlaintext;
}

/// Reverse Conversion Type
pub trait ReverseType {
    /// Decrypted Plaintext Type
    type DecryptedPlaintext;
}

/// Reverse Conversion
///
/// When decrypting with result [`TargetDecryptedPlaintext`] we can apply the [`into_source`]
/// conversion function to get objects of type [`DecryptedPlaintext`] from the result of a
/// decryption.
///
/// [`TargetDecryptedPlaintext`]: Self::TargetDecryptedPlaintext
/// [`into_source`]: Self::into_source
/// [`DecryptedPlaintext`]: ReverseType::DecryptedPlaintext
pub trait Reverse<COM = ()>: ReverseType {
    /// Target Decrypted Plaintext Type
    type TargetDecryptedPlaintext;

    /// Converts `target` into the source [`DecryptedPlaintext`](ReverseType::DecryptedPlaintext)
    /// type.
    fn into_source(
        target: Self::TargetDecryptedPlaintext,
        compiler: &mut COM,
    ) -> Self::DecryptedPlaintext;
}

/// Plaintext Converting Encryption Scheme Adapter
///
/// In many applications we may have some structured plaintext data that feeds into a generic
/// encryption scheme over some unstructured type (like encryption over bit-strings). This converter
/// can be used to convert between the plaintext types for conversion before encryption and after
/// decryption. This `struct` utilizes the [`Forward`] (before encryption) and [`Reverse`] (after
/// decryption) `trait`s to give the definition of the conversion. The `C` type on this `struct` is
/// the converter that implements [`Forward`] and/or [`Reverse`].
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PlaintextConverter<E, C> {
    /// Base Encryption Scheme
    pub encryption_scheme: E,

    /// Type Parameter Marker
    __: PhantomData<C>,
}

impl<E, C> PlaintextConverter<E, C> {
    /// Builds a new [`PlaintextConverter`] over `encryption_scheme`.
    #[inline]
    pub fn new(encryption_scheme: E) -> Self {
        Self {
            encryption_scheme,
            __: PhantomData,
        }
    }

    /// Returns the inner encryption scheme from `self`.
    #[inline]
    pub fn into_inner(self) -> E {
        self.encryption_scheme
    }
}

impl<E, C> HeaderType for PlaintextConverter<E, C>
where
    E: HeaderType,
{
    type Header = E::Header;
}

impl<E, C> CiphertextType for PlaintextConverter<E, C>
where
    E: CiphertextType,
{
    type Ciphertext = E::Ciphertext;
}

impl<E, C> EncryptionKeyType for PlaintextConverter<E, C>
where
    E: EncryptionKeyType,
{
    type EncryptionKey = E::EncryptionKey;
}

impl<E, C> DecryptionKeyType for PlaintextConverter<E, C>
where
    E: DecryptionKeyType,
{
    type DecryptionKey = E::DecryptionKey;
}

impl<E, C> Derive for PlaintextConverter<E, C>
where
    E: Derive,
{
    #[inline]
    fn derive(
        &self,
        decryption_key: &Self::DecryptionKey,
        compiler: &mut (),
    ) -> Self::EncryptionKey {
        self.encryption_scheme.derive(decryption_key, compiler)
    }
}

impl<E, C> PlaintextType for PlaintextConverter<E, C>
where
    E: PlaintextType,
    C: ForwardType,
{
    type Plaintext = C::Plaintext;
}

impl<E, C> EncryptionTypes for PlaintextConverter<E, C>
where
    E: EncryptionTypes,
    C: ForwardType,
{
    type Randomness = E::Randomness;
}

impl<E, C, COM> Encrypt<COM> for PlaintextConverter<E, C>
where
    E: Encrypt<COM>,
    C: Forward<COM, TargetPlaintext = E::Plaintext>,
{
    #[inline]
    fn encrypt(
        &self,
        encryption_key: &Self::EncryptionKey,
        randomness: &Self::Randomness,
        header: &Self::Header,
        plaintext: &Self::Plaintext,
        compiler: &mut COM,
    ) -> Self::Ciphertext {
        self.encryption_scheme.encrypt(
            encryption_key,
            randomness,
            header,
            &C::as_target(plaintext, compiler),
            compiler,
        )
    }
}

impl<E, C> DecryptionTypes for PlaintextConverter<E, C>
where
    E: DecryptionTypes,
    C: ReverseType,
{
    type DecryptedPlaintext = C::DecryptedPlaintext;
}

impl<E, C, COM> Decrypt<COM> for PlaintextConverter<E, C>
where
    E: Decrypt<COM>,
    C: Reverse<COM, TargetDecryptedPlaintext = E::DecryptedPlaintext>,
{
    #[inline]
    fn decrypt(
        &self,
        decryption_key: &Self::DecryptionKey,
        header: &Self::Header,
        ciphertext: &Self::Ciphertext,
        compiler: &mut COM,
    ) -> Self::DecryptedPlaintext {
        C::into_source(
            self.encryption_scheme
                .decrypt(decryption_key, header, ciphertext, compiler),
            compiler,
        )
    }
}
