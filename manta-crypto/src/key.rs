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

//! Cryptographic Key Primitives

/// Key Derivation Function
pub trait KeyDerivationFunction<COM = ()> {
    /// Input Key Type
    type Key: ?Sized;

    /// Output Key Type
    type Output;

    /// Derives a key of type [`Output`](Self::Output) from `key`.
    fn derive(&self, key: &Self::Key, compiler: &mut COM) -> Self::Output;

    /// Derives a key of type [`Output`](Self::Output) from `key`.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for [`derive`] when the `key` value is owned, and by
    /// default, [`derive`] is used as its implementation. This method must return the same value
    /// as [`derive`] on the same input.
    ///
    /// [`derive`]: Self::derive
    #[inline]
    fn derive_owned(&self, key: Self::Key, compiler: &mut COM) -> Self::Output
    where
        Self::Key: Sized,
    {
        self.derive(&key, compiler)
    }

    /// Borrows `self` rather than consuming it, returning an implementation of
    /// [`KeyDerivationFunction`].
    #[inline]
    fn by_ref(&self) -> &Self {
        self
    }
}

impl<COM, F> KeyDerivationFunction<COM> for &F
where
    F: KeyDerivationFunction<COM>,
{
    type Key = F::Key;
    type Output = F::Output;

    #[inline]
    fn derive(&self, key: &Self::Key, compiler: &mut COM) -> Self::Output {
        (*self).derive(key, compiler)
    }

    #[inline]
    fn derive_owned(&self, key: Self::Key, compiler: &mut COM) -> Self::Output
    where
        Self::Key: Sized,
    {
        (*self).derive_owned(key, compiler)
    }
}

/// Key Derivation Function Adapters
pub mod kdf {
    use super::*;
    use crate::rand::{RngCore, Sample};
    use alloc::vec::Vec;
    use core::marker::PhantomData;
    use manta_util::codec::{Decode, DecodeError, Encode, Read, Write};

    #[cfg(feature = "serde")]
    use manta_util::serde::{Deserialize, Serialize};

    /// Identity Key Derivation Function
    #[cfg_attr(
        feature = "serde",
        derive(Deserialize, Serialize),
        serde(crate = "manta_util::serde")
    )]
    #[derive(derivative::Derivative)]
    #[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct Identity<K, COM = ()>(PhantomData<(K, COM)>)
    where
        K: Clone;

    impl<K, COM> KeyDerivationFunction<COM> for Identity<K, COM>
    where
        K: Clone,
    {
        type Key = K;
        type Output = K;

        #[inline]
        fn derive(&self, key: &Self::Key, compiler: &mut COM) -> Self::Output {
            let _ = compiler;
            key.clone()
        }
    }

    /// From Byte Slice Reference Adapter
    #[cfg_attr(
        feature = "serde",
        derive(Deserialize, Serialize),
        serde(crate = "manta_util::serde")
    )]
    #[derive(derivative::Derivative)]
    #[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct FromByteSliceRef<T, F, COM = ()>
    where
        T: AsRef<[u8]>,
        F: KeyDerivationFunction<COM, Key = [u8]>,
    {
        /// Key Derivation Function
        key_derivation_function: F,

        /// Type Parameter Marker
        __: PhantomData<(T, COM)>,
    }

    impl<T, F, COM> FromByteSliceRef<T, F, COM>
    where
        T: AsRef<[u8]>,
        F: KeyDerivationFunction<COM, Key = [u8]>,
    {
        /// Builds a new [`FromByteSliceRef`] adapter for `key_derivation_function`.
        #[inline]
        pub fn new(key_derivation_function: F) -> Self {
            Self {
                key_derivation_function,
                __: PhantomData,
            }
        }
    }

    impl<T, F> Decode for FromByteSliceRef<T, F>
    where
        T: AsRef<[u8]>,
        F: Decode + KeyDerivationFunction<Key = [u8]>,
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
                F::decode(&mut reader).map_err(|err| err.map_decode(|_| ()))?,
            ))
        }
    }

    impl<T, F> Encode for FromByteSliceRef<T, F>
    where
        T: AsRef<[u8]>,
        F: Encode + KeyDerivationFunction<Key = [u8]>,
    {
        #[inline]
        fn encode<W>(&self, mut writer: W) -> Result<(), W::Error>
        where
            W: Write,
        {
            self.key_derivation_function.encode(&mut writer)?;
            Ok(())
        }
    }

    impl<T, F, COM> KeyDerivationFunction<COM> for FromByteSliceRef<T, F, COM>
    where
        T: AsRef<[u8]>,
        F: KeyDerivationFunction<COM, Key = [u8]>,
    {
        type Key = T;
        type Output = F::Output;

        #[inline]
        fn derive(&self, key: &Self::Key, compiler: &mut COM) -> Self::Output {
            self.key_derivation_function.derive(key.as_ref(), compiler)
        }
    }

    impl<T, F, D> Sample<D> for FromByteSliceRef<T, F>
    where
        T: AsRef<[u8]>,
        F: KeyDerivationFunction<Key = [u8]> + Sample<D>,
    {
        #[inline]
        fn sample<R>(distribution: D, rng: &mut R) -> Self
        where
            R: RngCore + ?Sized,
        {
            Self::new(F::sample(distribution, rng))
        }
    }

    /// Byte Conversion Trait
    pub trait AsBytes {
        /// Returns an owned byte representation of `self`.
        fn as_bytes(&self) -> Vec<u8>;
    }

    /// From Byte Vector Adapter
    #[cfg_attr(
        feature = "serde",
        derive(Deserialize, Serialize),
        serde(crate = "manta_util::serde")
    )]
    #[derive(derivative::Derivative)]
    #[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct FromByteVector<T, F, COM = ()>
    where
        T: AsBytes,
        F: KeyDerivationFunction<COM, Key = [u8]>,
    {
        /// Key Derivation Function
        key_derivation_function: F,

        /// Type Parameter Marker
        __: PhantomData<(T, COM)>,
    }

    impl<T, F, COM> FromByteVector<T, F, COM>
    where
        T: AsBytes,
        F: KeyDerivationFunction<COM, Key = [u8]>,
    {
        /// Builds a new [`FromByteVector`] adapter for `key_derivation_function`.
        #[inline]
        pub fn new(key_derivation_function: F) -> Self {
            Self {
                key_derivation_function,
                __: PhantomData,
            }
        }
    }

    impl<T, F> Decode for FromByteVector<T, F>
    where
        T: AsBytes,
        F: Decode + KeyDerivationFunction<Key = [u8]>,
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
                F::decode(&mut reader).map_err(|err| err.map_decode(|_| ()))?,
            ))
        }
    }

    impl<T, F> Encode for FromByteVector<T, F>
    where
        T: AsBytes,
        F: Encode + KeyDerivationFunction<Key = [u8]>,
    {
        #[inline]
        fn encode<W>(&self, mut writer: W) -> Result<(), W::Error>
        where
            W: Write,
        {
            self.key_derivation_function.encode(&mut writer)?;
            Ok(())
        }
    }

    impl<T, F, COM> KeyDerivationFunction<COM> for FromByteVector<T, F, COM>
    where
        T: AsBytes,
        F: KeyDerivationFunction<COM, Key = [u8]>,
    {
        type Key = T;
        type Output = F::Output;

        #[inline]
        fn derive(&self, key: &Self::Key, compiler: &mut COM) -> Self::Output {
            self.key_derivation_function
                .derive(&key.as_bytes(), compiler)
        }
    }

    impl<T, F, D> Sample<D> for FromByteVector<T, F>
    where
        T: AsBytes,
        F: KeyDerivationFunction<Key = [u8]> + Sample<D>,
    {
        #[inline]
        fn sample<R>(distribution: D, rng: &mut R) -> Self
        where
            R: RngCore + ?Sized,
        {
            Self::new(F::sample(distribution, rng))
        }
    }
}

/// Key Agreement Scheme
///
/// # Specification
///
/// All implementations of this trait must adhere to the following properties:
///
/// 1. **Agreement**: For all possible inputs, the following function returns `true`:
///
///     ```text
///     fn agreement(lhs: SecretKey, rhs: SecretKey) -> bool {
///         agree(lhs, derive(rhs)) == agree(rhs, derive(lhs))
///     }
///     ```
///     This ensures that both parties in the shared computation will arrive at the same conclusion
///     about the value of the [`SharedSecret`](Self::SharedSecret).
pub trait KeyAgreementScheme<COM = ()>:
    KeyDerivationFunction<COM, Key = Self::SecretKey, Output = Self::PublicKey>
{
    /// Secret Key Type
    type SecretKey;

    /// Public Key Type
    type PublicKey;

    /// Shared Secret Type
    type SharedSecret;

    /// Computes the shared secret given the known `secret_key` and the given `public_key`.
    fn agree(
        &self,
        secret_key: &Self::SecretKey,
        public_key: &Self::PublicKey,
        compiler: &mut COM,
    ) -> Self::SharedSecret;

    /// Computes the shared secret given the known `secret_key` and the given `public_key`.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for [`agree`] when the `secret_key` value and
    /// `public_key` value are owned, and by default, [`agree`] is used as its implementation. This
    /// method must return the same value as [`agree`] on the same input.
    ///
    /// [`agree`]: Self::agree
    #[inline]
    fn agree_owned(
        &self,
        secret_key: Self::SecretKey,
        public_key: Self::PublicKey,
        compiler: &mut COM,
    ) -> Self::SharedSecret {
        self.agree(&secret_key, &public_key, compiler)
    }

    /// Borrows `self` rather than consuming it, returning an implementation of
    /// [`KeyAgreementScheme`].
    #[inline]
    fn by_ref(&self) -> &Self {
        self
    }
}

impl<K, COM> KeyAgreementScheme<COM> for &K
where
    K: KeyAgreementScheme<COM>,
{
    type SecretKey = K::SecretKey;
    type PublicKey = K::PublicKey;
    type SharedSecret = K::SharedSecret;

    #[inline]
    fn agree(
        &self,
        secret_key: &Self::SecretKey,
        public_key: &Self::PublicKey,
        compiler: &mut COM,
    ) -> Self::SharedSecret {
        (*self).agree(secret_key, public_key, compiler)
    }

    #[inline]
    fn agree_owned(
        &self,
        secret_key: Self::SecretKey,
        public_key: Self::PublicKey,
        compiler: &mut COM,
    ) -> Self::SharedSecret {
        (*self).agree_owned(secret_key, public_key, compiler)
    }
}

/// Testing Framework
#[cfg(feature = "test")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "test")))]
pub mod test {
    use super::*;
    use core::fmt::Debug;

    /// Tests if the `agreement` property is satisfied for `K`.
    #[inline]
    pub fn key_agreement<K>(scheme: &K, lhs: &K::SecretKey, rhs: &K::SecretKey)
    where
        K: KeyAgreementScheme,
        K::SharedSecret: Debug + PartialEq,
    {
        assert_eq!(
            scheme.agree(lhs, &scheme.derive(rhs, &mut ()), &mut ()),
            scheme.agree(rhs, &scheme.derive(lhs, &mut ()), &mut ()),
            "Key agreement schemes should satisfy the agreement property."
        )
    }
}
