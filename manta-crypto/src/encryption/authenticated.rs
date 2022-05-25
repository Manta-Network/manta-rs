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

//! Authenticated Encryption

// TODO: add authenticated data wrapper
// TODO: distinguish between one-time and nonce-based authenticated encryption

use crate::{constraint::Native, encryption::symmetric};

pub use symmetric::{Ciphertext, Key, Plaintext, Randomness};

/// Authenticated Encryption
///
/// This extension `trait` computes the authentication tag associated to an encryption. It can be
/// used to add authentication to any existing [`symmetric`] encryption scheme.
pub trait Authentication<COM = ()>: symmetric::Types {
    /// Authentication Tag Type
    type Tag;

    /// Computes the authentication tag for an encryption using all the available data, `key`,
    /// `randomness`, `plaintext`, `ciphertext` inside the `compiler`.
    fn tag_with(
        &self,
        key: &Self::Key,
        randomness: &Self::Randomness,
        plaintext: &Self::Plaintext,
        ciphertext: &Self::Ciphertext,
        compiler: &mut COM,
    ) -> Self::Tag;

    /// Computes the authentication tag for an encryption using all the available data, `key`,
    /// `randomness`, `plaintext`, `ciphertext`.
    #[inline]
    fn tag(
        &self,
        key: &Self::Key,
        randomness: &Self::Randomness,
        plaintext: &Self::Plaintext,
        ciphertext: &Self::Ciphertext,
    ) -> Self::Tag
    where
        COM: Native,
    {
        self.tag_with(key, randomness, plaintext, ciphertext, &mut COM::compiler())
    }

    ///
    #[inline]
    fn encrypt_authenticated(
        &self,
        key: &Self::Key,
        randomness: &Self::Randomness,
        plaintext: &Self::Plaintext,
        compiler: &mut COM,
    ) -> (Self::Tag, Self::Ciphertext)
    where
        Self: Encrypt<COM>,
    {
        let ciphertext = self.encrypt(key, randomness, plaintext);
        let tag = self.tag(key, randomness, plaintext, ciphertext);
        (tag, ciphertext)
    }

    ///
    #[inline]
    fn decrypt_authenticated(
        &self,
        key: &Self::Key,
        randomness: &Self::Randomness,
        tag: &Self::Tag,
        ciphertext: &Self::Ciphertext,
    ) -> Option<Self::Plaintext>
    where
        Self: Decrypt,
    {
        (tag == self.tag(key, randomness, plaintext, ciphertext))
            .then(|| self.decrypt(key, ciphertext))
    }
}

/// Authenticated Encryption Tag Type
pub type Tag<A> = <A as Authentication>::Tag;

/*
/// Encrypt-Then-MAC Authenticated Encryption Wrapper
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct EncryptThenMac<S, M, COM = ()>
where
    S: SymmetricKeyEncryptionScheme<COM>,
    S::Key: Sized,
    M: MessageAuthenticationCode<COM, Message = S::Ciphertext>,
    M::Key: Sized,
{
    /// Symmetric Key Encryption Scheme
    pub symmetric_key_encryption_scheme: S,

    /// Message Authentication Code
    pub message_authentication_code: M,

    /// Type Parameter Marker
    __: PhantomData<COM>,
}

impl<S, M, COM> EncryptThenMac<S, M, COM>
where
    S: SymmetricKeyEncryptionScheme<COM>,
    S::Key: Sized,
    M: MessageAuthenticationCode<COM, Message = S::Ciphertext>,
    M::Key: Sized,
{
    /// Builds a new [`EncryptThenMac`] adapter for authenticated encryption over
    /// `symmetric_key_encryption_scheme` using `message_authentication_code` as the
    /// [`MessageAuthenticationCode`].
    #[inline]
    pub fn new(symmetric_key_encryption_scheme: S, message_authentication_code: M) -> Self {
        Self {
            symmetric_key_encryption_scheme,
            message_authentication_code,
            __: PhantomData,
        }
    }
}
*/

/*

use crate::{
    constraint::Native, encryption::symmetric::SymmetricKeyEncryptionScheme,
    mac::MessageAuthenticationCode,
};
use core::marker::PhantomData;

/// Authenticated Encryption Types
///
/// See the [`Encrypt`] and [`Decrypt`] `trait`s for the definitions of the authenticated encryption
/// and decryption algorithms.
pub trait Types {
    /// Key Type
    ///
    /// This type is used to both encrypt plaintext and decrypt ciphertext. To use asymmetric keys,
    /// use a [`hybrid`](crate::encryption::hybrid) encryption model.
    type Key: ?Sized;

    /// Plaintext Type
    type Plaintext;

    /// Ciphertext Type
    type Ciphertext;

    /// Tag Type
    type Tag;
}

impl<A> Types for &A
where
    A: Types,
{
    type Key = A::Key;
    type Plaintext = A::Plaintext;
    type Ciphertext = A::Ciphertext;
    type Tag = A::Tag;
}

/// Authenticated Encryption Key Type
pub type Key<A> = <A as Types>::Key;

/// Authenticated Encryption Plaintext Type
pub type Plaintext<A> = <A as Types>::Plaintext;

/// Authenticated Encryption Ciphertext Type
pub type Ciphertext<A> = <A as Types>::Ciphertext;

/// Authenticated Encryption Tag Type
pub type Tag<A> = <A as Types>::Tag;

/// Authenticated Encryption
///
/// This `trait` covers the [`encrypt`](Self::encrypt_with) half of an authenticated encryption
/// scheme. To use decryption see the [`Decrypt`] `trait`.
pub trait Encrypt<COM = ()>: Types {
    /// Encrypts `plaintext` under `key`, producing the authentication [`Tag`](Self::Tag) and the
    /// relevant [`Ciphertext`](Self::Ciphertext) inside the `compiler`.
    fn encrypt_with(
        &self,
        key: &Self::Key,
        plaintext: &Self::Plaintext,
        compiler: &mut COM,
    ) -> (Self::Tag, Self::Ciphertext);

    /// Encrypts `plaintext` under `key`, producing the authentication [`Tag`](Self::Tag) and the
    /// relevant [`Ciphertext`](Self::Ciphertext).
    #[inline]
    fn encrypt(&self, key: &Self::Key, plaintext: &Self::Plaintext) -> (Self::Tag, Self::Ciphertext)
    where
        COM: Native,
    {
        self.encrypt_with(key, plaintext, &mut COM::compiler())
    }
}

impl<A, COM> Encrypt<COM> for &A
where
    A: Encrypt<COM>,
{
    #[inline]
    fn encrypt_with(
        &self,
        key: &Self::Key,
        plaintext: &Self::Plaintext,
        compiler: &mut COM,
    ) -> (Self::Tag, Self::Ciphertext) {
        (*self).encrypt_with(key, plaintext, compiler)
    }

    #[inline]
    fn encrypt(&self, key: &Self::Key, plaintext: &Self::Plaintext) -> (Self::Tag, Self::Ciphertext)
    where
        COM: Native,
    {
        (*self).encrypt(key, plaintext)
    }
}

/// Authenticated Decryption
///
/// This `trait` covers the [`decrypt`](Self::decrypt) half of an authenticated encryption scheme.
/// To use encryption see the [`Encrypt`] `trait`.
pub trait Decrypt: Types {
    /// Decrypts `ciphertext` under `key`, authenticating under `tag`, returning
    /// [`Plaintext`](Self::Plaintext) if the authentication succeeded.
    fn decrypt(
        &self,
        key: &Self::Key,
        tag: &Self::Tag,
        ciphertext: &Self::Ciphertext,
    ) -> Option<Self::Plaintext>;
}

impl<A> Decrypt for &A
where
    A: Decrypt,
{
    #[inline]
    fn decrypt(
        &self,
        key: &Self::Key,
        tag: &Self::Tag,
        ciphertext: &Self::Ciphertext,
    ) -> Option<Self::Plaintext> {
        (*self).decrypt(key, tag, ciphertext)
    }
}

/// Encrypt-Then-MAC Authenticated Encryption Wrapper
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct EncryptThenMac<S, M, COM = ()>
where
    S: SymmetricKeyEncryptionScheme<COM>,
    S::Key: Sized,
    M: MessageAuthenticationCode<COM, Message = S::Ciphertext>,
    M::Key: Sized,
{
    /// Symmetric Key Encryption Scheme
    pub symmetric_key_encryption_scheme: S,

    /// Message Authentication Code
    pub message_authentication_code: M,

    /// Type Parameter Marker
    __: PhantomData<COM>,
}

impl<S, M, COM> EncryptThenMac<S, M, COM>
where
    S: SymmetricKeyEncryptionScheme<COM>,
    S::Key: Sized,
    M: MessageAuthenticationCode<COM, Message = S::Ciphertext>,
    M::Key: Sized,
{
    /// Builds a new [`EncryptThenMac`] adapter for authenticated encryption over
    /// `symmetric_key_encryption_scheme` using `message_authentication_code` as the
    /// [`MessageAuthenticationCode`].
    #[inline]
    pub fn new(symmetric_key_encryption_scheme: S, message_authentication_code: M) -> Self {
        Self {
            symmetric_key_encryption_scheme,
            message_authentication_code,
            __: PhantomData,
        }
    }
}

impl<S, M, COM> Types for EncryptThenMac<S, M, COM>
where
    S: SymmetricKeyEncryptionScheme<COM>,
    S::Key: Sized,
    M: MessageAuthenticationCode<COM, Message = S::Ciphertext>,
    M::Key: Sized,
{
    type Key = (S::Key, M::Key);
    type Plaintext = S::Plaintext;
    type Ciphertext = S::Ciphertext;
    type Tag = M::Digest;
}

impl<S, M, COM> Encrypt<COM> for EncryptThenMac<S, M, COM>
where
    S: SymmetricKeyEncryptionScheme<COM>,
    S::Key: Sized,
    M: MessageAuthenticationCode<COM, Message = S::Ciphertext>,
    M::Key: Sized,
{
    #[inline]
    fn encrypt_with(
        &self,
        key: &Self::Key,
        plaintext: &Self::Plaintext,
        compiler: &mut COM,
    ) -> (Self::Tag, Self::Ciphertext) {
        let ciphertext = self
            .symmetric_key_encryption_scheme
            .encrypt_with(&key.0, plaintext, compiler);
        (
            self.message_authentication_code
                .hash_with(&key.1, &ciphertext, compiler),
            ciphertext,
        )
    }
}

impl<S, M> Decrypt for EncryptThenMac<S, M>
where
    S: SymmetricKeyEncryptionScheme,
    S::Key: Sized,
    M: MessageAuthenticationCode<Message = S::Ciphertext>,
    M::Key: Sized,
    M::Digest: PartialEq,
{
    #[inline]
    fn decrypt(
        &self,
        key: &Self::Key,
        tag: &Self::Tag,
        ciphertext: &Self::Ciphertext,
    ) -> Option<Self::Plaintext> {
        (tag == &self.message_authentication_code.hash(&key.1, ciphertext)).then(|| {
            self.symmetric_key_encryption_scheme
                .decrypt(&key.0, ciphertext)
        })
    }
}

*/
