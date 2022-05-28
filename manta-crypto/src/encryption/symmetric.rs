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

//! Symmetric Encryption

use crate::{
    constraint::Native,
    rand::{CryptoRng, RngCore, Sample},
};
use core::marker::PhantomData;
use manta_util::codec::{Decode, DecodeError, Encode, Read, Write};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Symmetric Encryption Types
///
/// See the [`Encrypt`] and [`Decrypt`] `trait`s for the definitions of the symmetric encryption
/// and decryption algorithms.
pub trait Types {
    /// Key Type
    ///
    /// This type is used to both encrypt plaintext and decrypt ciphertext. To use asymmetric keys,
    /// use a [`hybrid`](crate::encryption::hybrid) encryption model.
    type Key: ?Sized;

    /* TODO:
    /// Randomness Type
    ///
    /// This type is used to protect against known weaknesses in symmetric encryption protocols
    /// whenever an attacker knows two ciphertexts that were encrypted under the same [`Key`]. This
    /// randomness type can contribute to the nonce, synthetic initialization vector, or whatever
    /// other randomness is used in a particular protocol. For cryptographic protocols that use
    /// one-time keys, this may also be set to `()` since the uniqueness of the key already handles
    /// the randomness required to preserve the privacy of the encryption.
    type Randomness: ?Sized;
    */

    /// Data Header Type
    ///
    /// This type is used to describe the associated data and randomness involved in symmetric
    /// encryption protocols.
    type Header: ?Sized;

    /// Plaintext Type
    type Plaintext;

    /// Ciphertext Type
    type Ciphertext;
}

impl<S> Types for &S
where
    S: Types,
{
    type Key = S::Key;
    type Header = S::Header;
    type Plaintext = S::Plaintext;
    type Ciphertext = S::Ciphertext;
}

/// Symmetric Encryption Key Type
pub type Key<S> = <S as Types>::Key;

/// Symmetric Encryption Header Type
pub type Header<S> = <S as Types>::Header;

/// Symmetric Encryption Plaintext Type
pub type Plaintext<S> = <S as Types>::Plaintext;

/// Symmetric Encryption Ciphertext Type
pub type Ciphertext<S> = <S as Types>::Ciphertext;

/// Symmetric Encryption
///
/// This `trait` covers the [`encrypt`](Self::encrypt_with) half of a symmetric encryption scheme.
/// To use decryption see the [`Decrypt`] `trait`.
pub trait Encrypt<COM = ()>: Types {
    /// Encrypts `plaintext` under `key` and `header` inside of `compiler`.
    fn encrypt_with(
        &self,
        key: &Self::Key,
        header: &Self::Header,
        plaintext: &Self::Plaintext,
        compiler: &mut COM,
    ) -> Self::Ciphertext;

    /// Encrypts `plaintext` under `key` and `header`.
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
        self.encrypt_with(key, header, plaintext, &mut COM::compiler())
    }
}

impl<S, COM> Encrypt<COM> for &S
where
    S: Encrypt<COM>,
{
    #[inline]
    fn encrypt_with(
        &self,
        key: &Self::Key,
        header: &Self::Header,
        plaintext: &Self::Plaintext,
        compiler: &mut COM,
    ) -> Self::Ciphertext {
        (*self).encrypt_with(key, header, plaintext, compiler)
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
        (*self).encrypt(key, header, plaintext)
    }
}

/// Symmetric Decryption
///
/// This `trait` covers the [`decrypt`](Self::decrypt) half of a symmetric encryption scheme. To use
/// encryption see the [`Encrypt`] `trait`.
pub trait Decrypt<COM = ()>: Types {
    /// Decrypts `ciphertext` under `key` and `header` inside of `compiler`.
    fn decrypt_with(
        &self,
        key: &Self::Key,
        header: &Self::Header,
        ciphertext: &Self::Ciphertext,
        compiler: &mut COM,
    ) -> Self::Plaintext;

    /// Decrypts `ciphertext` under `key` and `header`.
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
        self.decrypt_with(key, header, ciphertext, &mut COM::compiler())
    }
}

impl<S, COM> Decrypt<COM> for &S
where
    S: Decrypt<COM>,
{
    #[inline]
    fn decrypt_with(
        &self,
        key: &Self::Key,
        header: &Self::Header,
        ciphertext: &Self::Ciphertext,
        compiler: &mut COM,
    ) -> Self::Plaintext {
        (*self).decrypt_with(key, header, ciphertext, compiler)
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
        (*self).decrypt(key, header, ciphertext)
    }
}

/* TODO:
/// Plaintext Mapping
pub trait PlaintextMapping<P>: Sized {
    /// Plaintext Type
    type Plaintext;

    /// Converts `self` into the base plaintext space `P`.
    fn into_base(plaintext: Self::Plaintext) -> P;

    /// Converts from the base `plaintext` to [`Plaintext`](Self::Plaintext) returning `None` if the
    /// conversion failed.
    fn from_base(plaintext: P) -> Option<Self::Plaintext>;
}

/// [`TryFrom`] Plaintext Mapping
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde")
)]
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TryFromMapping<P, Q>(PhantomData<(P, Q)>)
where
    Q: Into<P> + TryFrom<P>;

impl<P, Q> PlaintextMapping<P> for TryFromMapping<P, Q>
where
    Q: Into<P> + TryFrom<P>,
{
    type Plaintext = Q;

    #[inline]
    fn into_base(plaintext: Self::Plaintext) -> P {
        plaintext.into()
    }

    #[inline]
    fn from_base(plaintext: P) -> Option<Self::Plaintext> {
        plaintext.try_into().ok()
    }
}

/// Mapped Symmetric Encryption Scheme
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde")
)]
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Map<S, F>
where
    S: SymmetricKeyEncryptionScheme,
    F: PlaintextMapping<S::Plaintext>,
{
    /// Symmetric Encryption Scheme
    cipher: S,

    /// Type Parameter Marker
    __: PhantomData<F>,
}

impl<S, F> Map<S, F>
where
    S: SymmetricKeyEncryptionScheme,
    F: PlaintextMapping<S::Plaintext>,
{
    /// Builds a new [`SymmetricKeyEncryptionScheme`] from `cipher` mapping the plaintext space over
    /// `P`.
    #[inline]
    pub fn new(cipher: S) -> Self {
        Self {
            cipher,
            __: PhantomData,
        }
    }
}

impl<S, F> Decode for Map<S, F>
where
    S: Decode + SymmetricKeyEncryptionScheme,
    F: PlaintextMapping<S::Plaintext>,
{
    // NOTE: We use a blank error here for simplicity. This trait will be removed in the future
    //       anyways. See https://github.com/Manta-Network/manta-rs/issues/27.
    type Error = ();

    #[inline]
    fn decode<R>(mut reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: Read,
    {
        Ok(Self::new(
            S::decode(&mut reader).map_err(|err| err.map_decode(|_| ()))?,
        ))
    }
}

impl<S, F> Encode for Map<S, F>
where
    S: Encode + SymmetricKeyEncryptionScheme,
    F: PlaintextMapping<S::Plaintext>,
{
    #[inline]
    fn encode<W>(&self, mut writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.cipher.encode(&mut writer)?;
        Ok(())
    }
}

impl<S, F, D> Sample<D> for Map<S, F>
where
    S: SymmetricKeyEncryptionScheme + Sample<D>,
    F: PlaintextMapping<S::Plaintext>,
{
    #[inline]
    fn sample<R>(distribution: D, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Self::new(S::sample(distribution, rng))
    }
}

impl<S, F> SymmetricKeyEncryptionScheme for Map<S, F>
where
    S: SymmetricKeyEncryptionScheme,
    F: PlaintextMapping<S::Plaintext>,
{
    type Key = S::Key;
    type Plaintext = F::Plaintext;
    type Ciphertext = S::Ciphertext;

    #[inline]
    fn encrypt(&self, key: Self::Key, plaintext: Self::Plaintext) -> Self::Ciphertext {
        self.cipher.encrypt(key, F::into_base(plaintext))
    }

    #[inline]
    fn decrypt(&self, key: Self::Key, ciphertext: &Self::Ciphertext) -> Option<Self::Plaintext> {
        self.cipher.decrypt(key, ciphertext).and_then(F::from_base)
    }
}

/// Testing Framework
#[cfg(feature = "test")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "test")))]
pub mod test {
    use super::*;
    use core::fmt::Debug;

    /// Tests if symmetric encryption of `plaintext` using `key` returns the same plaintext on
    /// decryption.
    #[inline]
    pub fn encryption<S>(cipher: &S, key: S::Key, plaintext: S::Plaintext)
    where
        S: SymmetricKeyEncryptionScheme,
        S::Key: Clone,
        S::Plaintext: Clone + Debug + PartialEq,
    {
        assert_eq!(
            cipher
                .decrypt(key.clone(), &cipher.encrypt(key, plaintext.clone()))
                .expect("Decryption of encrypted message should have succeeded."),
            plaintext,
            "Plaintext should have matched decrypted-encrypted plaintext."
        )
    }
}

*/
