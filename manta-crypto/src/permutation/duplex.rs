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

//! Duplex Sponge Authenticated Encryption Scheme

// TODO: Find a way to incorporate `Randomness` in this protocol.

use crate::{
    encryption::{
        CiphertextType, Decrypt, DecryptionKeyType, DecryptionTypes, Encrypt, EncryptionKeyType,
        EncryptionTypes, HeaderType, PlaintextType,
    },
    permutation::{
        sponge::{Absorb, Sponge, Squeeze},
        PseudorandomPermutation,
    },
};
use alloc::vec::Vec;
use core::marker::PhantomData;

/// Duplex Sponge Configuration
///
/// This `trait` configures the behavior of the [`Duplexer`] for duplex-sponge authenticated
/// encryption (with associated data) using a [`PseudorandomPermutation`].
pub trait Configuration<P, COM = ()>
where
    P: PseudorandomPermutation<COM>,
{
    /// Key Type
    ///
    /// The [`Duplexer`] implements symmetric encryption using this type as the encryption and
    /// decryption keys. To use asymmetric encryption, use [`Hybrid`] to wrap this encryption
    /// scheme.
    ///
    /// [`Hybrid`]: crate::encryption::hybrid::Hybrid
    type Key;

    /// Header Type
    type Header;

    /// Sponge Input Block Type
    type Input: Absorb<P, COM> + Squeeze<P, COM>;

    /// Sponge Output Block Type
    type Output: Absorb<P, COM> + Squeeze<P, COM>;

    /// Authentication Tag Type
    type Tag;

    /// Tag Verification Type
    type Verification;

    /// Initializes the [`Sponge`] state for the beginning of the cipher.
    fn initialize(&self, compiler: &mut COM) -> P::Domain;

    /// Generates the starting input blocks for `key` and `header` data to be inserted into the
    /// cipher.
    fn generate_starting_blocks(
        &self,
        key: &Self::Key,
        header: &Self::Header,
        compiler: &mut COM,
    ) -> Vec<Self::Input>;

    /// Extracts an instance of the [`Tag`](Self::Tag) type from `state`.
    fn as_tag(&self, state: &P::Domain, compiler: &mut COM) -> Self::Tag;

    /// Verifies that the `encryption_tag` returned by encryption matches the `decryption_tag`
    /// returned by decryption, returning a verification type.
    fn verify(
        &self,
        encryption_tag: &Self::Tag,
        decryption_tag: &Self::Tag,
        compiler: &mut COM,
    ) -> Self::Verification;
}

/// Ciphertext Payload
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Ciphertext<T, C> {
    /// Authentication Tag
    pub tag: T,

    /// Ciphertext Message
    pub message: C,
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
    /// Builds a new [`Duplexer`] authenticated encryption scheme from `permutation`, and
    /// `configuration`.
    #[inline]
    pub fn new(permutation: P, configuration: C) -> Self {
        Self {
            permutation,
            configuration,
            __: PhantomData,
        }
    }

    /// Prepares the duplex sponge by absorbing the `key` and `header`.
    #[inline]
    fn setup(&self, key: &C::Key, header: &C::Header, compiler: &mut COM) -> P::Domain {
        let mut state = self.configuration.initialize(compiler);
        Sponge::new(&self.permutation, &mut state).absorb_all(
            &self
                .configuration
                .generate_starting_blocks(key, header, compiler),
            compiler,
        );
        state
    }

    /// Performs duplex encryption by absorbing the initial state with `key` and `header`, and
    /// then duplexing `plaintext`, outputing the squeezed ciphertext blocks.
    #[inline]
    fn duplex_encryption(
        &self,
        key: &C::Key,
        header: &C::Header,
        plaintext: &[C::Input],
        compiler: &mut COM,
    ) -> (P::Domain, Vec<C::Output>) {
        let mut state = self.setup(key, header, compiler);
        let ciphertext = Sponge::new(&self.permutation, &mut state).duplex_all(plaintext, compiler);
        (state, ciphertext)
    }

    /// Performs duplex decryption by absorbing the initial state with `key` and `header`, and
    /// then duplexing `ciphertext`, outputing the squeezed plaintext blocks.
    #[inline]
    fn duplex_decryption(
        &self,
        key: &C::Key,
        header: &C::Header,
        ciphertext: &[C::Output],
        compiler: &mut COM,
    ) -> (P::Domain, Vec<C::Input>) {
        let mut state = self.setup(key, header, compiler);
        let plaintext = Sponge::new(&self.permutation, &mut state).duplex_all(ciphertext, compiler);
        (state, plaintext)
    }

    /// Computes the tag for the final round by running the permutation once on the current
    /// `state`.
    #[inline]
    fn tag(&self, mut state: P::Domain, compiler: &mut COM) -> C::Tag {
        self.permutation.permute(&mut state, compiler);
        self.configuration.as_tag(&state, compiler)
    }
}

impl<P, C, COM> HeaderType for Duplexer<P, C, COM>
where
    P: PseudorandomPermutation<COM>,
    C: Configuration<P, COM>,
{
    type Header = C::Header;
}

impl<P, C, COM> CiphertextType for Duplexer<P, C, COM>
where
    P: PseudorandomPermutation<COM>,
    C: Configuration<P, COM>,
{
    type Ciphertext = Ciphertext<C::Tag, Vec<C::Output>>;
}

impl<P, C, COM> EncryptionKeyType for Duplexer<P, C, COM>
where
    P: PseudorandomPermutation<COM>,
    C: Configuration<P, COM>,
{
    type EncryptionKey = C::Key;
}

impl<P, C, COM> DecryptionKeyType for Duplexer<P, C, COM>
where
    P: PseudorandomPermutation<COM>,
    C: Configuration<P, COM>,
{
    type DecryptionKey = C::Key;
}

impl<P, C, COM> PlaintextType for Duplexer<P, C, COM>
where
    P: PseudorandomPermutation<COM>,
    C: Configuration<P, COM>,
{
    type Plaintext = Vec<C::Input>;
}

impl<P, C, COM> EncryptionTypes for Duplexer<P, C, COM>
where
    P: PseudorandomPermutation<COM>,
    C: Configuration<P, COM>,
{
    /// Empty Randomness
    ///
    /// The current protocol does not support any private randomness injected with the plaintext,
    /// but may support it in the future.
    type Randomness = ();
}

impl<P, C, COM> Encrypt<COM> for Duplexer<P, C, COM>
where
    P: PseudorandomPermutation<COM>,
    C: Configuration<P, COM>,
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
        let _ = randomness;
        let (state, ciphertext) =
            self.duplex_encryption(encryption_key, header, plaintext, compiler);
        Ciphertext {
            tag: self.tag(state, compiler),
            message: ciphertext,
        }
    }
}

impl<P, C, COM> DecryptionTypes for Duplexer<P, C, COM>
where
    P: PseudorandomPermutation<COM>,
    C: Configuration<P, COM>,
{
    type DecryptedPlaintext = (C::Verification, Vec<C::Input>);
}

impl<P, C, COM> Decrypt<COM> for Duplexer<P, C, COM>
where
    P: PseudorandomPermutation<COM>,
    C: Configuration<P, COM>,
{
    #[inline]
    fn decrypt(
        &self,
        decryption_key: &Self::DecryptionKey,
        header: &Self::Header,
        ciphertext: &Self::Ciphertext,
        compiler: &mut COM,
    ) -> Self::DecryptedPlaintext {
        let (state, plaintext) =
            self.duplex_decryption(decryption_key, header, &ciphertext.message, compiler);
        (
            self.configuration
                .verify(&ciphertext.tag, &self.tag(state, compiler), compiler),
            plaintext,
        )
    }
}
