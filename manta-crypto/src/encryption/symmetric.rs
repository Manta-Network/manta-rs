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

use crate::rand::{CryptoRng, RngCore, Sample};
use core::marker::PhantomData;
use manta_util::codec::{Decode, DecodeError, Encode, Read, Write};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Symmetric Key Encryption Scheme
///
/// # Specification
///
/// All implementations of this trait must adhere to the following properties:
///
/// 1. **Invertibility**: For all possible inputs, the following function returns `true`:
///
///     ```text
///     fn invertibility(key: Key, plaintext: Plaintext) -> bool {
///         matches!(decrypt(key, &encrypt(key, plaintext.clone())), Some(p) if p == plaintext)
///     }
///     ```
pub trait SymmetricKeyEncryptionScheme {
    /// Encryption/Decryption Key Type
    type Key;

    /// Plaintext Type
    type Plaintext;

    /// Ciphertext Type
    type Ciphertext;

    /// Encrypts `plaintext` using `key`.
    fn encrypt(&self, key: Self::Key, plaintext: Self::Plaintext) -> Self::Ciphertext;

    /// Tries to decrypt `ciphertext` using `key`.
    fn decrypt(&self, key: Self::Key, ciphertext: &Self::Ciphertext) -> Option<Self::Plaintext>;

    /// Borrows `self` rather than consuming it, returning an implementation of
    /// [`SymmetricKeyEncryptionScheme`].
    #[inline]
    fn by_ref(&self) -> &Self {
        self
    }

    /// Maps the plaintext space using `F` and builds a new [`SymmetricKeyEncryptionScheme`] from it.
    #[inline]
    fn map<F>(self) -> Map<Self, F>
    where
        Self: Sized,
        F: PlaintextMapping<Self::Plaintext>,
    {
        Map::new(self)
    }
}

impl<S> SymmetricKeyEncryptionScheme for &S
where
    S: SymmetricKeyEncryptionScheme,
{
    type Key = S::Key;
    type Plaintext = S::Plaintext;
    type Ciphertext = S::Ciphertext;

    #[inline]
    fn encrypt(&self, key: Self::Key, plaintext: Self::Plaintext) -> Self::Ciphertext {
        (*self).encrypt(key, plaintext)
    }

    #[inline]
    fn decrypt(&self, key: Self::Key, ciphertext: &Self::Ciphertext) -> Option<Self::Plaintext> {
        (*self).decrypt(key, ciphertext)
    }
}

/// Symmetric Key Type
pub type Key<S> = <S as SymmetricKeyEncryptionScheme>::Key;

/// Plaintext Type
pub type Plaintext<S> = <S as SymmetricKeyEncryptionScheme>::Plaintext;

/// Ciphertext Type
pub type Ciphertext<S> = <S as SymmetricKeyEncryptionScheme>::Ciphertext;

/// Plaintext Mapping
pub trait PlaintextMapping<P>: Sized {
    /// Plaintext Type
    type Plaintext;

    /// Converts `self` into the plaintext space `P`.
    fn into(plaintext: Self::Plaintext) -> P;

    /// Converts from `plaintext` to [`Plaintext`](Self::Plaintext) returning `None` if the
    /// conversion failed.
    fn from(plaintext: P) -> Option<Self::Plaintext>;
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
    fn into(plaintext: Self::Plaintext) -> P {
        plaintext.into()
    }

    #[inline]
    fn from(plaintext: P) -> Option<Self::Plaintext> {
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
        self.cipher.encrypt(key, F::into(plaintext))
    }

    #[inline]
    fn decrypt(&self, key: Self::Key, ciphertext: &Self::Ciphertext) -> Option<Self::Plaintext> {
        self.cipher.decrypt(key, ciphertext).and_then(F::from)
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
