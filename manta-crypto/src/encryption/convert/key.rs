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

//! Encryption and Decryption Key Conversion Primitives and Adapters

use crate::encryption::{
    CiphertextType, Decrypt, DecryptionKeyType, DecryptionTypes, Derive, Encrypt,
    EncryptionKeyType, EncryptionTypes, HeaderType, PlaintextType,
};
use core::marker::PhantomData;

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

///
pub trait ForwardType {
    ///
    type EncryptionKey;
}

///
pub trait Forward<COM = ()>: ForwardType {
    ///
    type TargetEncryptionKey;

    ///
    fn as_target(source: &Self::EncryptionKey, compiler: &mut COM) -> Self::TargetEncryptionKey;
}

///
pub trait ReverseType {
    ///
    type DecryptionKey;
}

///
pub trait Reverse<COM = ()>: ReverseType {
    ///
    type TargetDecryptionKey;

    ///
    fn as_target(source: &Self::DecryptionKey, compiler: &mut COM) -> Self::TargetDecryptionKey;
}

///
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Converter<E, C> {
    /// Base Encryption Scheme
    pub base: E,

    /// Type Parameter Marker
    __: PhantomData<C>,
}

impl<E, C> Converter<E, C> {
    /// Builds a new [`Converter`] over `base`.
    #[inline]
    pub fn new(base: E) -> Self {
        Self {
            base,
            __: PhantomData,
        }
    }

    /// Returns the inner encryption scheme from `self`.
    #[inline]
    pub fn into_inner(self) -> E {
        self.base
    }
}

impl<E, C> HeaderType for Converter<E, C>
where
    E: HeaderType,
{
    type Header = E::Header;
}

impl<E, C> CiphertextType for Converter<E, C>
where
    E: CiphertextType,
{
    type Ciphertext = E::Ciphertext;
}

impl<E, C> EncryptionKeyType for Converter<E, C>
where
    E: EncryptionKeyType,
    C: ForwardType,
{
    type EncryptionKey = C::EncryptionKey;
}

impl<E, C> DecryptionKeyType for Converter<E, C>
where
    E: DecryptionKeyType,
    C: ReverseType,
{
    type DecryptionKey = C::DecryptionKey;
}

impl<E, C> PlaintextType for Converter<E, C>
where
    E: PlaintextType,
{
    type Plaintext = E::Plaintext;
}

impl<E, C> EncryptionTypes for Converter<E, C>
where
    E: EncryptionTypes,
    C: ForwardType,
{
    type Randomness = E::Randomness;
}

impl<E, C, COM> Encrypt<COM> for Converter<E, C>
where
    E: Encrypt<COM>,
    C: Forward<COM, TargetEncryptionKey = E::EncryptionKey>,
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
        self.base.encrypt(
            &C::as_target(encryption_key, compiler),
            randomness,
            header,
            plaintext,
            compiler,
        )
    }
}

impl<E, C> DecryptionTypes for Converter<E, C>
where
    E: DecryptionTypes,
    C: ReverseType,
{
    type DecryptedPlaintext = E::DecryptedPlaintext;
}

impl<E, C, COM> Decrypt<COM> for Converter<E, C>
where
    E: Decrypt<COM>,
    C: Reverse<COM, TargetDecryptionKey = E::DecryptionKey>,
{
    #[inline]
    fn decrypt(
        &self,
        decryption_key: &Self::DecryptionKey,
        header: &Self::Header,
        ciphertext: &Self::Ciphertext,
        compiler: &mut COM,
    ) -> Self::DecryptedPlaintext {
        self.base.decrypt(
            &C::as_target(decryption_key, compiler),
            header,
            ciphertext,
            compiler,
        )
    }
}
