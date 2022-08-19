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

//! Hybrid Public-Key Encryption
//!
//! For encrypting against the same [`EncryptionKey`] and [`DecryptionKey`] we may want to use a
//! key-exchange protocol in order to generate these keys as unique shared secrets. The [`Hybrid`]
//! encryption scheme inlines this complexity into the encryption interfaces.

use crate::{
    constraint::{HasInput, Input},
    eclair::{
        self,
        alloc::{
            mode::{Derived, Public, Secret},
            Allocate, Allocator, Constant, Var, Variable,
        },
        bool::{Assert, AssertEq, Bool},
        ops::BitAnd,
        Has,
    },
    encryption::{
        CiphertextType, Decrypt, DecryptedPlaintextType, DecryptionKeyType, Derive, Encrypt,
        EncryptedMessage, EncryptionKeyType, HeaderType, PlaintextType, RandomnessType,
    },
    key,
    rand::{Rand, RngCore, Sample},
};
use core::{fmt::Debug, hash::Hash};
use manta_util::codec::{Decode, DecodeError, Encode, Read, Write};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Encryption Key
pub type EncryptionKey<K> = <K as key::agreement::Types>::PublicKey;

/// Decryption Key
pub type DecryptionKey<K> = <K as key::agreement::Types>::SecretKey;

/// Encryption Randomness
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "K::SecretKey: Clone, E::Randomness: Clone"),
    Copy(bound = "K::SecretKey: Copy, E::Randomness: Copy"),
    Debug(bound = "K::SecretKey: Debug, E::Randomness: Debug"),
    Default(bound = "K::SecretKey: Default, E::Randomness: Default"),
    Eq(bound = "K::SecretKey: Eq, E::Randomness: Eq"),
    Hash(bound = "K::SecretKey: Hash, E::Randomness: Hash"),
    PartialEq(bound = "K::SecretKey: PartialEq, E::Randomness: PartialEq")
)]
pub struct Randomness<K, E>
where
    K: key::agreement::Types,
    E: RandomnessType,
{
    /// Ephemeral Secret Key
    pub ephemeral_secret_key: K::SecretKey,

    /// Base Encryption Randomness
    pub randomness: E::Randomness,
}

impl<K, E> Randomness<K, E>
where
    K: key::agreement::Types,
    E: RandomnessType,
{
    /// Builds a new [`Randomness`] from `ephemeral_secret_key` and `randomness`.
    #[inline]
    pub fn new(ephemeral_secret_key: K::SecretKey, randomness: E::Randomness) -> Self {
        Self {
            ephemeral_secret_key,
            randomness,
        }
    }

    /// Builds a new [`Randomness`] from `ephemeral_secret_key` whenever the base encryption scheme
    /// has no [`Randomness`] type (i.e. uses `()` as its [`Randomness`] type).
    ///
    /// [`Randomness`]: RandomnessType::Randomness
    #[inline]
    pub fn from_key(ephemeral_secret_key: K::SecretKey) -> Self
    where
        E: RandomnessType<Randomness = ()>,
    {
        Self::new(ephemeral_secret_key, ())
    }
}

impl<K, E, DS, DR> Sample<(DS, DR)> for Randomness<K, E>
where
    K: key::agreement::Types,
    E: RandomnessType,
    K::SecretKey: Sample<DS>,
    E::Randomness: Sample<DR>,
{
    #[inline]
    fn sample<R>(distribution: (DS, DR), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self::new(rng.sample(distribution.0), rng.sample(distribution.1))
    }
}

impl<K, E, COM> Variable<Secret, COM> for Randomness<K, E>
where
    K: key::agreement::Types + Constant<COM>,
    E: Constant<COM> + RandomnessType,
    K::SecretKey: Variable<Secret, COM>,
    E::Randomness: Variable<Secret, COM>,
    K::Type: key::agreement::Types<SecretKey = Var<K::SecretKey, Secret, COM>>,
    E::Type: RandomnessType<Randomness = Var<E::Randomness, Secret, COM>>,
{
    type Type = Randomness<K::Type, E::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Variable::<Derived<(Secret, Secret)>, COM>::new_unknown(compiler)
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Variable::<Derived<(Secret, Secret)>, COM>::new_known(this, compiler)
    }
}

impl<K, E, S, R, COM> Variable<Derived<(S, R)>, COM> for Randomness<K, E>
where
    K: key::agreement::Types + Constant<COM>,
    E: RandomnessType + Constant<COM>,
    K::SecretKey: Variable<S, COM>,
    E::Randomness: Variable<R, COM>,
    K::Type: key::agreement::Types<SecretKey = Var<K::SecretKey, S, COM>>,
    E::Type: RandomnessType<Randomness = Var<E::Randomness, R, COM>>,
{
    type Type = Randomness<K::Type, E::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self::new(compiler.allocate_unknown(), compiler.allocate_unknown())
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(
            this.ephemeral_secret_key.as_known(compiler),
            this.randomness.as_known(compiler),
        )
    }
}

/// Full Ciphertext
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "K::PublicKey: Clone, E::Ciphertext: Clone"),
    Copy(bound = "K::PublicKey: Copy, E::Ciphertext: Copy"),
    Debug(bound = "K::PublicKey: Debug, E::Ciphertext: Debug"),
    Default(bound = "K::PublicKey: Default, E::Ciphertext: Default"),
    Eq(bound = "K::PublicKey: Eq, E::Ciphertext: Eq"),
    Hash(bound = "K::PublicKey: Hash, E::Ciphertext: Hash"),
    PartialEq(bound = "K::PublicKey: PartialEq, E::Ciphertext: PartialEq")
)]
pub struct Ciphertext<K, E>
where
    K: key::agreement::Types,
    E: CiphertextType,
{
    /// Ephemeral Public Key
    pub ephemeral_public_key: K::PublicKey,

    /// Base Encryption Ciphertext
    pub ciphertext: E::Ciphertext,
}

impl<K, E> Ciphertext<K, E>
where
    K: key::agreement::Types,
    E: CiphertextType,
{
    /// Builds a new [`Ciphertext`] from `ephemeral_public_key` and `ciphertext`.
    #[inline]
    pub fn new(ephemeral_public_key: K::PublicKey, ciphertext: E::Ciphertext) -> Self {
        Self {
            ephemeral_public_key,
            ciphertext,
        }
    }
}

impl<K, E, DP, DC> Sample<(DP, DC)> for Ciphertext<K, E>
where
    K: key::agreement::Types,
    E: CiphertextType,
    K::PublicKey: Sample<DP>,
    E::Ciphertext: Sample<DC>,
{
    #[inline]
    fn sample<R>(distribution: (DP, DC), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self::new(rng.sample(distribution.0), rng.sample(distribution.1))
    }
}

impl<K, E, COM> eclair::cmp::PartialEq<Self, COM> for Ciphertext<K, E>
where
    COM: Has<bool>,
    Bool<COM>: BitAnd<Bool<COM>, COM, Output = Bool<COM>>,
    K: key::agreement::Types,
    E: CiphertextType,
    K::PublicKey: eclair::cmp::PartialEq<K::PublicKey, COM>,
    E::Ciphertext: eclair::cmp::PartialEq<E::Ciphertext, COM>,
{
    #[inline]
    fn eq(&self, rhs: &Self, compiler: &mut COM) -> Bool<COM> {
        self.ephemeral_public_key
            .eq(&rhs.ephemeral_public_key, compiler)
            .bitand(self.ciphertext.eq(&rhs.ciphertext, compiler), compiler)
    }

    #[inline]
    fn assert_equal(&self, rhs: &Self, compiler: &mut COM)
    where
        COM: Assert,
    {
        compiler.assert_eq(&self.ephemeral_public_key, &rhs.ephemeral_public_key);
        compiler.assert_eq(&self.ciphertext, &rhs.ciphertext);
    }
}

impl<K, E, COM> Variable<Public, COM> for Ciphertext<K, E>
where
    K: key::agreement::Types + Constant<COM>,
    E: CiphertextType + Constant<COM>,
    K::PublicKey: Variable<Public, COM>,
    E::Ciphertext: Variable<Public, COM>,
    K::Type: key::agreement::Types<PublicKey = Var<K::PublicKey, Public, COM>>,
    E::Type: CiphertextType<Ciphertext = Var<E::Ciphertext, Public, COM>>,
{
    type Type = Ciphertext<K::Type, E::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Variable::<Derived<(Public, Public)>, COM>::new_unknown(compiler)
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Variable::<Derived<(Public, Public)>, COM>::new_known(this, compiler)
    }
}

impl<K, E, P, C, COM> Variable<Derived<(P, C)>, COM> for Ciphertext<K, E>
where
    K: key::agreement::Types + Constant<COM>,
    E: CiphertextType + Constant<COM>,
    K::PublicKey: Variable<P, COM>,
    E::Ciphertext: Variable<C, COM>,
    K::Type: key::agreement::Types<PublicKey = Var<K::PublicKey, P, COM>>,
    E::Type: CiphertextType<Ciphertext = Var<E::Ciphertext, C, COM>>,
{
    type Type = Ciphertext<K::Type, E::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self::new(compiler.allocate_unknown(), compiler.allocate_unknown())
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(
            this.ephemeral_public_key.as_known(compiler),
            this.ciphertext.as_known(compiler),
        )
    }
}

impl<K, E> Encode for Ciphertext<K, E>
where
    K: key::agreement::Types,
    K::PublicKey: Encode,
    E: CiphertextType,
    E::Ciphertext: Encode,
{
    #[inline]
    fn encode<W>(&self, mut writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.ephemeral_public_key.encode(&mut writer)?;
        self.ciphertext.encode(&mut writer)?;
        Ok(())
    }
}

impl<K, E, P> Input<P> for Ciphertext<K, E>
where
    K: key::agreement::Types,
    E: CiphertextType,
    P: HasInput<K::PublicKey> + HasInput<E::Ciphertext> + ?Sized,
{
    #[inline]
    fn extend(&self, input: &mut P::Input) {
        P::extend(input, &self.ephemeral_public_key);
        P::extend(input, &self.ciphertext);
    }
}

/// Hybrid Encryption Scheme
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Hybrid<K, E> {
    /// Key Agreement Scheme
    pub key_agreement_scheme: K,

    /// Base Encryption Scheme
    pub encryption_scheme: E,
}

impl<K, E> Hybrid<K, E> {
    /// Builds a new [`Hybrid`] encryption scheme from `key_agreement_scheme` and a base
    /// `encryption_scheme`.
    #[inline]
    pub fn new(key_agreement_scheme: K, encryption_scheme: E) -> Self {
        Self {
            key_agreement_scheme,
            encryption_scheme,
        }
    }
}

impl<K, E> EncryptedMessage<Hybrid<K, E>>
where
    K: key::agreement::Types,
    E: CiphertextType + HeaderType,
{
    /// Returns the ephemeral public key associated to `self`, stored in its ciphertext.
    #[inline]
    pub fn ephemeral_public_key(&self) -> &K::PublicKey {
        &self.ciphertext.ephemeral_public_key
    }
}

impl<K, E> HeaderType for Hybrid<K, E>
where
    E: HeaderType,
{
    type Header = E::Header;
}

impl<K, E> CiphertextType for Hybrid<K, E>
where
    K: key::agreement::Types,
    E: CiphertextType,
{
    type Ciphertext = Ciphertext<K, E>;
}

impl<K, E> EncryptionKeyType for Hybrid<K, E>
where
    K: key::agreement::Types,
{
    type EncryptionKey = EncryptionKey<K>;
}

impl<K, E> DecryptionKeyType for Hybrid<K, E>
where
    K: key::agreement::Types,
{
    type DecryptionKey = DecryptionKey<K>;
}

impl<K, E> PlaintextType for Hybrid<K, E>
where
    E: PlaintextType,
{
    type Plaintext = E::Plaintext;
}

impl<K, E> RandomnessType for Hybrid<K, E>
where
    K: key::agreement::Types,
    E: RandomnessType,
{
    type Randomness = Randomness<K, E>;
}

impl<K, E> DecryptedPlaintextType for Hybrid<K, E>
where
    E: DecryptedPlaintextType,
{
    type DecryptedPlaintext = E::DecryptedPlaintext;
}

impl<K, E, COM> Derive<COM> for Hybrid<K, E>
where
    K: key::agreement::Derive<COM>,
{
    #[inline]
    fn derive(
        &self,
        decryption_key: &Self::DecryptionKey,
        compiler: &mut COM,
    ) -> Self::EncryptionKey {
        self.key_agreement_scheme.derive(decryption_key, compiler)
    }
}

impl<K, E, COM> Encrypt<COM> for Hybrid<K, E>
where
    K: key::agreement::Derive<COM> + key::agreement::Agree<COM>,
    E: Encrypt<COM, EncryptionKey = K::SharedSecret>,
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
        Ciphertext {
            ephemeral_public_key: self
                .key_agreement_scheme
                .derive(&randomness.ephemeral_secret_key, compiler),
            ciphertext: self.encryption_scheme.encrypt(
                &self.key_agreement_scheme.agree(
                    encryption_key,
                    &randomness.ephemeral_secret_key,
                    compiler,
                ),
                &randomness.randomness,
                header,
                plaintext,
                compiler,
            ),
        }
    }
}

impl<K, E, COM> Decrypt<COM> for Hybrid<K, E>
where
    K: key::agreement::Agree<COM>,
    E: Decrypt<COM, DecryptionKey = K::SharedSecret>,
{
    #[inline]
    fn decrypt(
        &self,
        decryption_key: &Self::DecryptionKey,
        header: &Self::Header,
        ciphertext: &Self::Ciphertext,
        compiler: &mut COM,
    ) -> Self::DecryptedPlaintext {
        self.encryption_scheme.decrypt(
            &self.key_agreement_scheme.agree(
                &ciphertext.ephemeral_public_key,
                decryption_key,
                compiler,
            ),
            header,
            &ciphertext.ciphertext,
            compiler,
        )
    }
}

impl<K, E> Decode for Hybrid<K, E>
where
    K: Decode,
    E: Decode,
{
    type Error = ();

    #[inline]
    fn decode<R>(mut reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: Read,
    {
        Ok(Self::new(
            Decode::decode(&mut reader).map_err(|err| err.map_decode(|_| ()))?,
            Decode::decode(&mut reader).map_err(|err| err.map_decode(|_| ()))?,
        ))
    }
}

impl<K, E> Encode for Hybrid<K, E>
where
    K: Encode,
    E: Encode,
{
    #[inline]
    fn encode<W>(&self, mut writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.key_agreement_scheme.encode(&mut writer)?;
        self.encryption_scheme.encode(&mut writer)?;
        Ok(())
    }
}

impl<K, E, DK, DE> Sample<(DK, DE)> for Hybrid<K, E>
where
    K: Sample<DK>,
    E: Sample<DE>,
{
    #[inline]
    fn sample<R>(distribution: (DK, DE), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self::new(rng.sample(distribution.0), rng.sample(distribution.1))
    }
}

impl<K, E, COM> Constant<COM> for Hybrid<K, E>
where
    K: Constant<COM>,
    E: Constant<COM>,
{
    type Type = Hybrid<K::Type, E::Type>;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(
            this.key_agreement_scheme.as_constant(compiler),
            this.encryption_scheme.as_constant(compiler),
        )
    }
}
