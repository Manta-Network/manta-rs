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

use crate::{constraint::Native, encryption::symmetric, mac::MessageAuthenticationCode};
use core::marker::PhantomData;

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
}

impl<A, COM> Authentication<COM> for &A
where
    A: Authentication<COM>,
{
    type Tag = A::Tag;

    #[inline]
    fn tag_with(
        &self,
        key: &Self::Key,
        randomness: &Self::Randomness,
        plaintext: &Self::Plaintext,
        ciphertext: &Self::Ciphertext,
        compiler: &mut COM,
    ) -> Self::Tag {
        (*self).tag_with(key, randomness, plaintext, ciphertext, compiler)
    }

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
        (*self).tag(key, randomness, plaintext, ciphertext)
    }
}

/// Authenticated Encryption
///
/// This `trait` covers the [`authenticated_encrypt`](Self::authenticated_encrypt_with) half of an
/// authenticated encryption scheme. To use decryption see the [`Decrypt`] `trait`.
pub trait Encrypt<COM = ()>: Authentication<COM> + symmetric::Encrypt<COM> {
    /// Encrypts `plaintext` under `key` and `randomness`, producing the authentication
    /// [`Tag`](Self::Tag) and the relevant [`Ciphertext`](Self::Ciphertext) inside the `compiler`.
    #[inline]
    fn authenticated_encrypt_with(
        &self,
        key: &Self::Key,
        randomness: &Self::Randomness,
        plaintext: &Self::Plaintext,
        compiler: &mut COM,
    ) -> (Self::Tag, Self::Ciphertext) {
        let ciphertext = self.encrypt_with(key, randomness, plaintext, compiler);
        let tag = self.tag_with(key, randomness, plaintext, &ciphertext, compiler);
        (tag, ciphertext)
    }

    /// Encrypts `plaintext` under `key` and `randomness`, producing the authentication
    /// [`Tag`](Self::Tag) and the relevant [`Ciphertext`](Self::Ciphertext).
    #[inline]
    fn authenticated_encrypt(
        &self,
        key: &Self::Key,
        randomness: &Self::Randomness,
        plaintext: &Self::Plaintext,
    ) -> (Self::Tag, Self::Ciphertext)
    where
        COM: Native,
    {
        self.authenticated_encrypt_with(key, randomness, plaintext, &mut COM::compiler())
    }
}

/// Authenticated Decryption
///
/// This `trait` covers the [`authenticated_decrypt`](Self::authenticated_decrypt) half of an
/// authenticated encryption scheme. To use decryption see the [`Decrypt`] `trait`.
pub trait Decrypt: Authentication + symmetric::Decrypt
where
    Self::Tag: PartialEq,
{
    /// Decrypts `ciphertext` under `key` and `randomness`, authenticating under `tag`, returning
    /// [`Plaintext`](Self::Plaintext) if the authentication succeeded.
    #[inline]
    fn authenticated_decrypt(
        &self,
        key: &Self::Key,
        randomness: &Self::Randomness,
        tag: &Self::Tag,
        ciphertext: &Self::Ciphertext,
    ) -> Option<Self::Plaintext> {
        let plaintext = self.decrypt(key, randomness, ciphertext);
        (tag == &self.tag(key, randomness, &plaintext, ciphertext)).then(|| plaintext)
    }
}

/// Authenticated Encryption Tag Type
pub type Tag<A, COM = ()> = <A as Authentication<COM>>::Tag;

/// Encrypt-Then-MAC Authenticated Encryption Wrapper
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct EncryptThenMac<S, M, COM = ()> {
    /// Symmetric Key Encryption Scheme
    pub symmetric_key_encryption_scheme: S,

    /// Message Authentication Code
    pub message_authentication_code: M,

    /// Type Parameter Marker
    __: PhantomData<COM>,
}

impl<S, M, COM> EncryptThenMac<S, M, COM> {
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

impl<S, M, COM> symmetric::Types for EncryptThenMac<S, M, COM>
where
    S: symmetric::Types,
    S::Key: Sized,
    M: MessageAuthenticationCode<COM, Message = S::Ciphertext>,
{
    type Key = (S::Key, M::Key);
    type Randomness = S::Randomness;
    type Plaintext = S::Plaintext;
    type Ciphertext = S::Ciphertext;
}

impl<S, M, COM> Authentication<COM> for EncryptThenMac<S, M, COM>
where
    S: symmetric::Types,
    S::Key: Sized,
    M: MessageAuthenticationCode<COM, Message = S::Ciphertext>,
{
    type Tag = M::Digest;

    #[inline]
    fn tag_with(
        &self,
        key: &Self::Key,
        randomness: &Self::Randomness,
        plaintext: &Self::Plaintext,
        ciphertext: &Self::Ciphertext,
        compiler: &mut COM,
    ) -> Self::Tag {
        let _ = (randomness, plaintext);
        self.message_authentication_code
            .hash_with(&key.1, ciphertext, compiler)
    }
}

impl<S, M, COM> symmetric::Encrypt<COM> for EncryptThenMac<S, M, COM>
where
    S: symmetric::Encrypt<COM>,
    S::Key: Sized,
    M: MessageAuthenticationCode<COM, Message = S::Ciphertext>,
{
    #[inline]
    fn encrypt_with(
        &self,
        key: &Self::Key,
        randomness: &Self::Randomness,
        plaintext: &Self::Plaintext,
        compiler: &mut COM,
    ) -> Self::Ciphertext {
        self.symmetric_key_encryption_scheme
            .encrypt_with(&key.0, randomness, plaintext, compiler)
    }
}

impl<S, M, COM> Encrypt<COM> for EncryptThenMac<S, M, COM>
where
    S: symmetric::Encrypt<COM>,
    S::Key: Sized,
    M: MessageAuthenticationCode<COM, Message = S::Ciphertext>,
{
}

impl<S, M> symmetric::Decrypt for EncryptThenMac<S, M>
where
    S: symmetric::Decrypt,
    S::Key: Sized,
    M: MessageAuthenticationCode<Message = S::Ciphertext>,
    M::Digest: PartialEq,
{
    #[inline]
    fn decrypt_with(
        &self,
        key: &Self::Key,
        randomness: &Self::Randomness,
        ciphertext: &Self::Ciphertext,
        compiler: &mut (),
    ) -> Self::Plaintext {
        let _ = compiler;
        self.symmetric_key_encryption_scheme
            .decrypt(&key.0, randomness, ciphertext)
    }
}

impl<S, M> Decrypt for EncryptThenMac<S, M>
where
    S: symmetric::Decrypt,
    S::Key: Sized,
    M: MessageAuthenticationCode<Message = S::Ciphertext>,
    M::Digest: PartialEq,
{
    #[inline]
    fn authenticated_decrypt(
        &self,
        key: &Self::Key,
        randomness: &Self::Randomness,
        tag: &Self::Tag,
        ciphertext: &Self::Ciphertext,
    ) -> Option<Self::Plaintext> {
        // NOTE: Since the computation of the tag does not require the plaintext, we can compute the
        //       tag first and check if it's equal, before decrypting.
        (tag == &self.message_authentication_code.hash(&key.1, ciphertext)).then(move || {
            self.symmetric_key_encryption_scheme
                .decrypt(&key.0, randomness, ciphertext)
        })
    }
}
