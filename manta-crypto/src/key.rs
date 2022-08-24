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

/// Key Agreement Schemes
pub mod agreement {
    /// Types
    pub trait Types {
        /// Secret Key Type
        type SecretKey;

        /// Public Key Type
        type PublicKey;

        /// Shared Secret Type
        type SharedSecret;
    }

    impl<K> Types for &K
    where
        K: Types,
    {
        type SecretKey = K::SecretKey;
        type PublicKey = K::PublicKey;
        type SharedSecret = K::SharedSecret;
    }

    /// Secret Key Type
    pub type SecretKey<K> = <K as Types>::SecretKey;

    /// Public Key Type
    pub type PublicKey<K> = <K as Types>::PublicKey;

    /// Shared Secret Type
    pub type SharedSecret<K> = <K as Types>::SharedSecret;

    /// Public Key Derivation
    pub trait Derive<COM = ()>: Types {
        /// Derives a [`PublicKey`](Types::PublicKey) from `secret_key`.
        fn derive(&self, secret_key: &Self::SecretKey, compiler: &mut COM) -> Self::PublicKey;
    }

    impl<K, COM> Derive<COM> for &K
    where
        K: Derive<COM>,
    {
        #[inline]
        fn derive(&self, secret_key: &Self::SecretKey, compiler: &mut COM) -> Self::PublicKey {
            (*self).derive(secret_key, compiler)
        }
    }

    /// Key Agreement
    pub trait Agree<COM = ()>: Types {
        /// Performs the agreement protocol on `public_key` and `secret_key` to arrive at the
        /// [`SharedSecret`](Types::SharedSecret).
        fn agree(
            &self,
            public_key: &Self::PublicKey,
            secret_key: &Self::SecretKey,
            compiler: &mut COM,
        ) -> Self::SharedSecret;
    }

    impl<K, COM> Agree<COM> for &K
    where
        K: Agree<COM>,
    {
        #[inline]
        fn agree(
            &self,
            public_key: &Self::PublicKey,
            secret_key: &Self::SecretKey,
            compiler: &mut COM,
        ) -> Self::SharedSecret {
            (*self).agree(public_key, secret_key, compiler)
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
        pub fn agreement<K>(scheme: &K, lhs: &K::SecretKey, rhs: &K::SecretKey)
        where
            K: Agree + Derive,
            K::SharedSecret: Debug + PartialEq,
        {
            assert_eq!(
                scheme.agree(&scheme.derive(rhs, &mut ()), lhs, &mut ()),
                scheme.agree(&scheme.derive(lhs, &mut ()), rhs, &mut ()),
                "Key agreement schemes should satisfy the agreement property."
            )
        }
    }
}

/// Key Derivation Functions
pub mod kdf {
    use crate::rand::{RngCore, Sample};
    use core::marker::PhantomData;
    use manta_util::{
        codec::{Decode, DecodeError, Encode, Read, Write},
        AsBytes,
    };

    #[cfg(feature = "serde")]
    use manta_util::serde::{Deserialize, Serialize};

    /// Key Derivation Function
    pub trait KeyDerivationFunction<COM = ()> {
        /// Key Type
        type Key: ?Sized;

        /// Output Type
        type Output;

        /// Derives a key of type [`Output`](Self::Output) from `key`.
        fn derive(&self, key: &Self::Key, compiler: &mut COM) -> Self::Output;
    }

    impl<K, COM> KeyDerivationFunction<COM> for &K
    where
        K: KeyDerivationFunction<COM>,
    {
        type Key = K::Key;
        type Output = K::Output;

        #[inline]
        fn derive(&self, key: &Self::Key, compiler: &mut COM) -> Self::Output {
            (*self).derive(key, compiler)
        }
    }

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
                Decode::decode(&mut reader).map_err(|err| err.map_decode(|_| ()))?,
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
