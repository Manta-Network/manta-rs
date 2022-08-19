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

// TODO: Add `Randomness` to the protocol by concatenating it to the plaintext on encryption and
//       dropping it on decryption.

use crate::{
    constraint::{HasInput, Input},
    eclair::{
        self,
        alloc::{mode::Public, Allocate, Allocator, Constant, Variable},
        bool::{Assert, AssertEq, Bool},
        ops::BitAnd,
        Has,
    },
    encryption::{
        CiphertextType, Decrypt, DecryptedPlaintextType, DecryptionKeyType, Encrypt,
        EncryptionKeyType, HeaderType, PlaintextType, RandomnessType,
    },
    permutation::{
        sponge::{Read, Sponge, Write},
        PseudorandomPermutation,
    },
    rand::{Rand, RngCore, Sample},
};
use alloc::vec::Vec;
use core::marker::PhantomData;
use manta_util::{
    codec::{self, Encode},
    iter::{BorrowIterator, Iterable},
};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Duplex Sponge Encryption Types
pub trait Types<P, COM = ()>
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

    /// Setup Block Type
    type SetupBlock: Write<P, COM, Output = ()>;

    /// Plaintext Block Type
    type PlaintextBlock: Write<P, COM, Output = Self::CiphertextBlock>;

    /// Plaintext Type
    type Plaintext: FromIterator<Self::PlaintextBlock> + BorrowIterator<Self::PlaintextBlock>;

    /// Ciphertext Block Type
    type CiphertextBlock: Write<P, COM, Output = Self::PlaintextBlock>;

    /// Ciphertext Type
    type Ciphertext: FromIterator<Self::CiphertextBlock> + BorrowIterator<Self::CiphertextBlock>;

    /// Authentication Tag Type
    type Tag: Read<P, COM>;
}

/// Duplex Sponge Initialization and Setup
pub trait Setup<P, COM = ()>: Types<P, COM>
where
    P: PseudorandomPermutation<COM>,
{
    /// Initializes the [`Sponge`] state for the beginning of the cipher.
    fn initialize(&self, compiler: &mut COM) -> P::Domain;

    /// Generates the starting input blocks for `key` and `header` data to be inserted into the
    /// cipher.
    fn setup(
        &self,
        key: &Self::Key,
        header: &Self::Header,
        compiler: &mut COM,
    ) -> Vec<Self::SetupBlock>;
}

/// Duplex Sponge Tag Verification
pub trait Verify<P, COM = ()>: Types<P, COM>
where
    P: PseudorandomPermutation<COM>,
{
    /// Tag Verification Type
    type Verification;

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
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Ciphertext<T, C> {
    /// Authentication Tag
    pub tag: T,

    /// Ciphertext Message
    pub message: C,
}

impl<T, C> Ciphertext<T, C> {
    /// Builds a new [`Ciphertext`] from `tag` and `message`.
    #[inline]
    pub fn new(tag: T, message: C) -> Self {
        Self { tag, message }
    }
}

impl<T, C, COM> eclair::cmp::PartialEq<Self, COM> for Ciphertext<T, C>
where
    COM: Has<bool>,
    Bool<COM>: BitAnd<Bool<COM>, COM, Output = Bool<COM>>,
    T: eclair::cmp::PartialEq<T, COM>,
    C: eclair::cmp::PartialEq<C, COM>,
{
    #[inline]
    fn eq(&self, rhs: &Self, compiler: &mut COM) -> Bool<COM> {
        self.tag
            .eq(&rhs.tag, compiler)
            .bitand(self.message.eq(&rhs.message, compiler), compiler)
    }

    #[inline]
    fn assert_equal(&self, rhs: &Self, compiler: &mut COM)
    where
        COM: Assert,
    {
        compiler.assert_eq(&self.tag, &rhs.tag);
        compiler.assert_eq(&self.message, &rhs.message);
    }
}

impl<T, C, COM> Variable<Public, COM> for Ciphertext<T, C>
where
    T: Variable<Public, COM>,
    C: Variable<Public, COM>,
{
    type Type = Ciphertext<T::Type, C::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self::new(compiler.allocate_unknown(), compiler.allocate_unknown())
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(this.tag.as_known(compiler), this.message.as_known(compiler))
    }
}

impl<T, C> Encode for Ciphertext<T, C>
where
    T: Encode,
    C: Encode,
{
    #[inline]
    fn encode<W>(&self, mut writer: W) -> Result<(), W::Error>
    where
        W: codec::Write,
    {
        self.tag.encode(&mut writer)?;
        self.message.encode(&mut writer)?;
        Ok(())
    }
}

impl<T, C, P> Input<P> for Ciphertext<T, C>
where
    P: HasInput<T> + HasInput<C> + ?Sized,
{
    #[inline]
    fn extend(&self, input: &mut P::Input) {
        P::extend(input, &self.tag);
        P::extend(input, &self.message);
    }
}

/// Duplex Sponge Authenticated Encryption Scheme
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Duplexer<P, C, COM = ()>
where
    P: PseudorandomPermutation<COM>,
    C: Types<P, COM>,
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
    C: Types<P, COM>,
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
    fn setup(&self, key: &C::Key, header: &C::Header, compiler: &mut COM) -> P::Domain
    where
        C: Setup<P, COM>,
    {
        let mut state = self.configuration.initialize(compiler);
        Sponge::new(&self.permutation, &mut state)
            .absorb_all::<_, _, ()>(&self.configuration.setup(key, header, compiler), compiler);
        state
    }

    /// Performs duplex encryption by absorbing the initial state with `key` and `header`, and
    /// then duplexing `plaintext`, outputting the encryption tag and the ciphertext blocks.
    #[inline]
    fn duplex_encryption(
        &self,
        key: &C::Key,
        header: &C::Header,
        plaintext: &C::Plaintext,
        compiler: &mut COM,
    ) -> (C::Tag, C::Ciphertext)
    where
        C: Setup<P, COM>,
    {
        let mut state = self.setup(key, header, compiler);
        let ciphertext =
            Sponge::new(&self.permutation, &mut state).absorb_all(plaintext.iter(), compiler);
        (C::Tag::read(&state, compiler), ciphertext)
    }

    /// Performs duplex decryption by absorbing the initial state with `key` and `header`, and
    /// then duplexing `ciphertext`, outputting the decryption tag and the plaintext blocks.
    #[inline]
    fn duplex_decryption(
        &self,
        key: &C::Key,
        header: &C::Header,
        ciphertext: &C::Ciphertext,
        compiler: &mut COM,
    ) -> (C::Tag, C::Plaintext)
    where
        C: Setup<P, COM>,
    {
        let mut state = self.setup(key, header, compiler);
        let plaintext =
            Sponge::new(&self.permutation, &mut state).absorb_all(ciphertext.iter(), compiler);
        (C::Tag::read(&state, compiler), plaintext)
    }
}

impl<P, C, COM> Constant<COM> for Duplexer<P, C, COM>
where
    P: PseudorandomPermutation<COM> + Constant<COM>,
    C: Types<P, COM> + Constant<COM>,
    P::Type: PseudorandomPermutation,
    C::Type: Types<P::Type>,
{
    type Type = Duplexer<P::Type, C::Type>;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(
            this.permutation.as_constant(compiler),
            this.configuration.as_constant(compiler),
        )
    }
}

impl<P, C, DP, DC> Sample<(DP, DC)> for Duplexer<P, C>
where
    P: PseudorandomPermutation + Sample<DP>,
    C: Sample<DC> + Types<P>,
{
    #[inline]
    fn sample<R>(distribution: (DP, DC), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self::new(rng.sample(distribution.0), rng.sample(distribution.1))
    }
}

impl<P, C, COM> HeaderType for Duplexer<P, C, COM>
where
    P: PseudorandomPermutation<COM>,
    C: Types<P, COM>,
{
    type Header = C::Header;
}

impl<P, C, COM> CiphertextType for Duplexer<P, C, COM>
where
    P: PseudorandomPermutation<COM>,
    C: Types<P, COM>,
{
    type Ciphertext = Ciphertext<C::Tag, C::Ciphertext>;
}

impl<P, C, COM> EncryptionKeyType for Duplexer<P, C, COM>
where
    P: PseudorandomPermutation<COM>,
    C: Types<P, COM>,
{
    type EncryptionKey = C::Key;
}

impl<P, C, COM> DecryptionKeyType for Duplexer<P, C, COM>
where
    P: PseudorandomPermutation<COM>,
    C: Types<P, COM>,
{
    type DecryptionKey = C::Key;
}

impl<P, C, COM> PlaintextType for Duplexer<P, C, COM>
where
    P: PseudorandomPermutation<COM>,
    C: Types<P, COM>,
{
    type Plaintext = C::Plaintext;
}

impl<P, C, COM> RandomnessType for Duplexer<P, C, COM>
where
    P: PseudorandomPermutation<COM>,
    C: Types<P, COM>,
{
    /// Empty Randomness
    ///
    /// The current protocol does not support any private randomness injected with the plaintext,
    /// but may support it in the future.
    type Randomness = ();
}

impl<P, C, COM> DecryptedPlaintextType for Duplexer<P, C, COM>
where
    P: PseudorandomPermutation<COM>,
    C: Verify<P, COM>,
{
    type DecryptedPlaintext = (C::Verification, C::Plaintext);
}

impl<P, C, COM> Encrypt<COM> for Duplexer<P, C, COM>
where
    P: PseudorandomPermutation<COM>,
    C: Setup<P, COM>,
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
        let (tag, ciphertext) = self.duplex_encryption(encryption_key, header, plaintext, compiler);
        Ciphertext {
            tag,
            message: ciphertext,
        }
    }
}

impl<P, C, COM> Decrypt<COM> for Duplexer<P, C, COM>
where
    P: PseudorandomPermutation<COM>,
    C: Setup<P, COM> + Verify<P, COM>,
{
    #[inline]
    fn decrypt(
        &self,
        decryption_key: &Self::DecryptionKey,
        header: &Self::Header,
        ciphertext: &Self::Ciphertext,
        compiler: &mut COM,
    ) -> Self::DecryptedPlaintext {
        let (tag, plaintext) =
            self.duplex_decryption(decryption_key, header, &ciphertext.message, compiler);
        (
            self.configuration.verify(&ciphertext.tag, &tag, compiler),
            plaintext,
        )
    }
}
