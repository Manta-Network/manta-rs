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

pub use symmetric::{Ciphertext, Header, Key, Plaintext};

/// Authenticated Encryption
///
/// This extension `trait` computes the authentication tag associated to an encryption. It can be
/// used to add authentication to any existing [`symmetric`] encryption scheme.
pub trait Authentication<COM = ()>: symmetric::Types {
    /// Authentication Tag Type
    type Tag;

    /// Computes the authentication tag for an encryption using all the available data, `key`,
    /// `header`, `plaintext`, `ciphertext` inside the `compiler`.
    fn tag_with(
        &self,
        key: &Self::Key,
        header: &Self::Header,
        plaintext: &Self::Plaintext,
        ciphertext: &Self::Ciphertext,
        compiler: &mut COM,
    ) -> Self::Tag;

    /// Computes the authentication tag for an encryption using all the available data, `key`,
    /// `header`, `plaintext`, `ciphertext`.
    #[inline]
    fn tag(
        &self,
        key: &Self::Key,
        header: &Self::Header,
        plaintext: &Self::Plaintext,
        ciphertext: &Self::Ciphertext,
    ) -> Self::Tag
    where
        COM: Native,
    {
        self.tag_with(key, header, plaintext, ciphertext, &mut COM::compiler())
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
        header: &Self::Header,
        plaintext: &Self::Plaintext,
        ciphertext: &Self::Ciphertext,
        compiler: &mut COM,
    ) -> Self::Tag {
        (*self).tag_with(key, header, plaintext, ciphertext, compiler)
    }

    #[inline]
    fn tag(
        &self,
        key: &Self::Key,
        header: &Self::Header,
        plaintext: &Self::Plaintext,
        ciphertext: &Self::Ciphertext,
    ) -> Self::Tag
    where
        COM: Native,
    {
        (*self).tag(key, header, plaintext, ciphertext)
    }
}

/// Authenticated Encryption Tag Type
pub type Tag<A, COM = ()> = <A as Authentication<COM>>::Tag;

/// Authenticated Encryption
///
/// This `trait` covers the [`authenticated_encrypt`](Self::authenticated_encrypt_with) half of an
/// authenticated encryption scheme. To use decryption see the [`Decrypt`] `trait`.
pub trait Encrypt<COM = ()>: Authentication<COM> + symmetric::Encrypt<COM> {
    /// Encrypts `plaintext` under `key` and `header`, producing the authentication
    /// [`Tag`](Authentication::Tag) and the relevant [`Ciphertext`](symmetric::Types::Ciphertext)
    /// inside the `compiler`.
    #[inline]
    fn authenticated_encrypt_with(
        &self,
        key: &Self::Key,
        header: &Self::Header,
        plaintext: &Self::Plaintext,
        compiler: &mut COM,
    ) -> (Self::Tag, Self::Ciphertext) {
        let ciphertext = self.encrypt_with(key, header, plaintext, compiler);
        let tag = self.tag_with(key, header, plaintext, &ciphertext, compiler);
        (tag, ciphertext)
    }

    /// Encrypts `plaintext` under `key` and `header`, producing the authentication
    /// [`Tag`](Authentication::Tag) and the relevant [`Ciphertext`](symmetric::Types::Ciphertext).
    #[inline]
    fn authenticated_encrypt(
        &self,
        key: &Self::Key,
        header: &Self::Header,
        plaintext: &Self::Plaintext,
    ) -> (Self::Tag, Self::Ciphertext)
    where
        COM: Native,
    {
        self.authenticated_encrypt_with(key, header, plaintext, &mut COM::compiler())
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
    /// Decrypts `ciphertext` under `key` and `header`, authenticating under `tag`, returning
    /// [`Plaintext`](symmetric::Types::Plaintext) if the authentication succeeded.
    #[inline]
    fn authenticated_decrypt(
        &self,
        key: &Self::Key,
        header: &Self::Header,
        tag: &Self::Tag,
        ciphertext: &Self::Ciphertext,
    ) -> Option<Self::Plaintext> {
        let plaintext = self.decrypt(key, header, ciphertext);
        (tag == &self.tag(key, header, &plaintext, ciphertext)).then(|| plaintext)
    }
}

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
    type Header = S::Header;
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
        header: &Self::Header,
        plaintext: &Self::Plaintext,
        ciphertext: &Self::Ciphertext,
        compiler: &mut COM,
    ) -> Self::Tag {
        let _ = (header, plaintext);
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
        header: &Self::Header,
        plaintext: &Self::Plaintext,
        compiler: &mut COM,
    ) -> Self::Ciphertext {
        self.symmetric_key_encryption_scheme
            .encrypt_with(&key.0, header, plaintext, compiler)
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
        header: &Self::Header,
        ciphertext: &Self::Ciphertext,
        compiler: &mut (),
    ) -> Self::Plaintext {
        let _ = compiler;
        self.symmetric_key_encryption_scheme
            .decrypt(&key.0, header, ciphertext)
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
        header: &Self::Header,
        tag: &Self::Tag,
        ciphertext: &Self::Ciphertext,
    ) -> Option<Self::Plaintext> {
        // NOTE: Since the computation of the tag does not require the plaintext, we can compute the
        //       tag first and check if it's equal, before decrypting.
        (tag == &self.message_authentication_code.hash(&key.1, ciphertext)).then(move || {
            self.symmetric_key_encryption_scheme
                .decrypt(&key.0, header, ciphertext)
        })
    }
}

/// Duplex Sponge Authenticated Encryption Scheme
#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
pub mod duplex {
    use super::*;
    use crate::permutation::{
        sponge::{Absorb, Sponge, Squeeze},
        PseudorandomPermutation,
    };
    use alloc::vec::Vec;

    /// Duplex Sponge Configuration
    pub trait Configuration<P, COM = ()>
    where
        P: PseudorandomPermutation<COM>,
    {
        /// Key Type
        type Key: ?Sized;

        /// Header Type
        type Header: ?Sized;

        /// Sponge Input Block Type
        type Input: Absorb<P, COM> + Squeeze<P, COM>;

        /// Sponge Output Block Type
        type Output: Absorb<P, COM> + Squeeze<P, COM>;

        /// Authentication Tag Type
        type Tag;

        /// Initializes the [`Sponge`] state for the beginning of the cipher inside of `compiler`.
        fn initialize_with(&self, compiler: &mut COM) -> P::Domain;

        /// Initializes the [`Sponge`] state for the beginning of the cipher.
        #[inline]
        fn initialize(&self) -> P::Domain
        where
            COM: Native,
        {
            self.initialize_with(&mut COM::compiler())
        }

        /// Generates the starting input blocks for `key` and `header` data to be inserted into the
        /// cipher inside of `compiler`.
        fn generate_starting_blocks_with(
            &self,
            key: &Self::Key,
            header: &Self::Header,
            compiler: &mut COM,
        ) -> Vec<Self::Input>;

        /// Generates the starting input blocks for `key` and `header` data to be inserted into the
        /// cipher.
        #[inline]
        fn generate_starting_blocks(
            &self,
            key: &Self::Key,
            header: &Self::Header,
        ) -> Vec<Self::Input>
        where
            COM: Native,
        {
            self.generate_starting_blocks_with(key, header, &mut COM::compiler())
        }

        /// Extracts an instance of the [`Tag`](Self::Tag) type from `state` inside `compiler`.
        fn as_tag_with(&self, state: &P::Domain, compiler: &mut COM) -> Self::Tag;

        /// Extracts an instance of the [`Tag`](Self::Tag) type from `state`.
        #[inline]
        fn as_tag(&self, state: &P::Domain) -> Self::Tag
        where
            COM: Native,
        {
            self.as_tag_with(state, &mut COM::compiler())
        }
    }

    /// Duplex Sponge Authenticated Encryption Scheme
    pub struct Duplexer<P, C, COM = ()>
    where
        P: PseudorandomPermutation<COM>,
        C: Configuration<P, COM>,
    {
        /// Permutation
        permutation: P,

        /// Duplex Configuration
        configuration: C,

        /// Type Parameter Marker
        __: PhantomData<COM>,
    }

    impl<P, C, COM> Duplexer<P, C, COM>
    where
        P: PseudorandomPermutation<COM>,
        C: Configuration<P, COM>,
    {
        /// Builds a new [`DuplexPermutation`] authenticated encryption scheme from `permutation`,
        /// and `configuration`.
        #[inline]
        pub fn new(permutation: P, configuration: C) -> Self {
            Self {
                permutation,
                configuration,
                __: PhantomData,
            }
        }

        ///
        #[inline]
        fn setup_with(
            &self,
            key: &Key<Self>,
            header: &Header<Self>,
            compiler: &mut COM,
        ) -> P::Domain {
            let mut state = self.configuration.initialize_with(compiler);
            Sponge::new(&self.permutation, &mut state).absorb_all_with(
                &self
                    .configuration
                    .generate_starting_blocks_with(key, header, compiler),
                compiler,
            );
            state
        }

        ///
        #[inline]
        fn duplex_encryption_with(
            &self,
            key: &Key<Self>,
            header: &Header<Self>,
            plaintext: &Plaintext<Self>,
            compiler: &mut COM,
        ) -> (P::Domain, Ciphertext<Self>) {
            let mut state = self.setup_with(key, header, compiler);
            let ciphertext =
                Sponge::new(&self.permutation, &mut state).duplex_all_with(plaintext, compiler);
            (state, ciphertext)
        }

        ///
        #[inline]
        fn duplex_decryption_with(
            &self,
            key: &Key<Self>,
            header: &Header<Self>,
            ciphertext: &Ciphertext<Self>,
            compiler: &mut COM,
        ) -> (P::Domain, Plaintext<Self>) {
            let mut state = self.setup_with(key, header, compiler);
            let plaintext =
                Sponge::new(&self.permutation, &mut state).duplex_all_with(ciphertext, compiler);
            (state, plaintext)
        }

        ///
        #[inline]
        fn tag_with(&self, mut state: P::Domain, compiler: &mut COM) -> C::Tag {
            self.permutation.permute_with(&mut state, compiler);
            self.configuration.as_tag_with(&state, compiler)
        }
    }

    impl<P, C, COM> symmetric::Types for Duplexer<P, C, COM>
    where
        P: PseudorandomPermutation<COM>,
        C: Configuration<P, COM>,
    {
        type Key = C::Key;
        type Header = C::Header;
        type Plaintext = Vec<C::Input>;
        type Ciphertext = Vec<C::Output>;
    }

    impl<P, C, COM> symmetric::Encrypt<COM> for Duplexer<P, C, COM>
    where
        P: PseudorandomPermutation<COM>,
        C: Configuration<P, COM>,
    {
        #[inline]
        fn encrypt_with(
            &self,
            key: &Self::Key,
            header: &Self::Header,
            plaintext: &Self::Plaintext,
            compiler: &mut COM,
        ) -> Self::Ciphertext {
            self.duplex_encryption_with(key, header, plaintext, compiler)
                .1
        }

        #[inline]
        fn encrypt(
            &self,
            key: &Self::Key,
            header: &Self::Header,
            plaintext: &Self::Plaintext,
        ) -> Self::Ciphertext
        where
            COM: Native,
        {
            // TODO: self.duplex_encryption(key, header, plaintext).1
            todo!()
        }
    }

    impl<P, C, COM> symmetric::Decrypt<COM> for Duplexer<P, C, COM>
    where
        P: PseudorandomPermutation<COM>,
        C: Configuration<P, COM>,
    {
        #[inline]
        fn decrypt_with(
            &self,
            key: &Self::Key,
            header: &Self::Header,
            ciphertext: &Self::Ciphertext,
            compiler: &mut COM,
        ) -> Self::Plaintext {
            self.duplex_decryption_with(key, header, ciphertext, compiler)
                .1
        }

        #[inline]
        fn decrypt(
            &self,
            key: &Self::Key,
            header: &Self::Header,
            ciphertext: &Self::Ciphertext,
        ) -> Self::Plaintext
        where
            COM: Native,
        {
            // TODO: self.duplex_decryption(key, header, plaintext).1
            todo!()
        }
    }

    impl<P, C, COM> Authentication<COM> for Duplexer<P, C, COM>
    where
        P: PseudorandomPermutation<COM>,
        C: Configuration<P, COM>,
    {
        type Tag = C::Tag;

        fn tag_with(
            &self,
            key: &Self::Key,
            header: &Self::Header,
            plaintext: &Self::Plaintext,
            ciphertext: &Self::Ciphertext,
            compiler: &mut COM,
        ) -> Self::Tag {
            self.configuration.as_tag_with(
                &self
                    .duplex_encryption_with(key, header, plaintext, compiler)
                    .0,
                compiler,
            )
        }

        #[inline]
        fn tag(
            &self,
            key: &Self::Key,
            header: &Self::Header,
            plaintext: &Self::Plaintext,
            ciphertext: &Self::Ciphertext,
        ) -> Self::Tag
        where
            COM: Native,
        {
            /* TODO:
            self.configuration
                .tag(self.duplex_encryption(key, header, plaintext).0)
            */
            todo!()
        }
    }

    impl<P, C, COM> Encrypt<COM> for Duplexer<P, C, COM>
    where
        P: PseudorandomPermutation<COM>,
        C: Configuration<P, COM>,
    {
        #[inline]
        fn authenticated_encrypt_with(
            &self,
            key: &Self::Key,
            header: &Self::Header,
            plaintext: &Self::Plaintext,
            compiler: &mut COM,
        ) -> (Self::Tag, Self::Ciphertext) {
            let (state, ciphertext) = self.duplex_encryption_with(key, header, plaintext, compiler);
            (self.tag_with(state, compiler), ciphertext)
        }

        #[inline]
        fn authenticated_encrypt(
            &self,
            key: &Self::Key,
            header: &Self::Header,
            plaintext: &Self::Plaintext,
        ) -> (Self::Tag, Self::Ciphertext)
        where
            COM: Native,
        {
            todo!()
        }
    }

    impl<P, C> Decrypt for Duplexer<P, C>
    where
        P: PseudorandomPermutation,
        C: Configuration<P>,
        C::Tag: PartialEq,
    {
        #[inline]
        fn authenticated_decrypt(
            &self,
            key: &Self::Key,
            header: &Self::Header,
            tag: &Self::Tag,
            ciphertext: &Self::Ciphertext,
        ) -> Option<Self::Plaintext> {
            /* TODO:
            let (state, plaintext) = self.duplex_decryption(key, header, plaintext);
            (self.tag(state) == tag).then(|| plaintext)
            */
            todo!()
        }
    }
}
