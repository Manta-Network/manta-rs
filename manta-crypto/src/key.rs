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

use crate::constraint::Native;
use core::marker::PhantomData;

/// Key Derivation Function
pub trait KeyDerivationFunction {
    /// Input Key Type
    type Key: ?Sized;

    /// Output Key Type
    type Output;

    /// Derives an output key from `secret` computed from a cryptographic agreement scheme.
    fn derive(secret: &Self::Key) -> Self::Output;
}

/// Key Derivation Function Adapter
pub mod kdf {
    use super::*;
    use alloc::vec::Vec;

    #[cfg(feature = "serde")]
    use manta_util::serde::{Deserialize, Serialize};

    /// From Byte Slice Reference Adapter
    #[cfg_attr(
        feature = "serde",
        derive(Deserialize, Serialize),
        serde(crate = "manta_util::serde")
    )]
    #[derive(derivative::Derivative)]
    #[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct FromByteSliceRef<T, F>(PhantomData<(T, F)>)
    where
        T: AsRef<[u8]>,
        F: KeyDerivationFunction<Key = [u8]>;

    impl<T, F> KeyDerivationFunction for FromByteSliceRef<T, F>
    where
        T: AsRef<[u8]>,
        F: KeyDerivationFunction<Key = [u8]>,
    {
        type Key = T;
        type Output = F::Output;

        #[inline]
        fn derive(secret: &Self::Key) -> Self::Output {
            F::derive(secret.as_ref())
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
    pub struct FromByteVector<T, F>(PhantomData<(T, F)>)
    where
        T: AsBytes,
        F: KeyDerivationFunction<Key = [u8]>;

    impl<T, F> KeyDerivationFunction for FromByteVector<T, F>
    where
        T: AsBytes,
        F: KeyDerivationFunction<Key = [u8]>,
    {
        type Key = T;
        type Output = F::Output;

        #[inline]
        fn derive(secret: &Self::Key) -> Self::Output {
            F::derive(&secret.as_bytes())
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
pub trait KeyAgreementScheme<COM = ()> {
    /// Secret Key Type
    type SecretKey;

    /// Public Key Type
    type PublicKey;

    /// Shared Secret Type
    type SharedSecret;

    /// Derives a public key corresponding to `secret_key` in the given `compiler`. This public key
    /// should be sent to the other party involved in the shared computation.
    fn derive_in(&self, secret_key: &Self::SecretKey, compiler: &mut COM) -> Self::PublicKey;

    /// Derives a public key corresponding to `secret_key`. This public key should be sent to the
    /// other party involved in the shared computation.
    #[inline]
    fn derive(&self, secret_key: &Self::SecretKey) -> Self::PublicKey
    where
        COM: Native,
    {
        self.derive_in(secret_key, &mut COM::compiler())
    }

    /// Derives a public key corresponding to `secret_key` in the given `compiler`. This public key
    /// should be sent to the other party involved in the shared computation.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for [`derive_in`] when the `secret_key` value is owned,
    /// and by default, [`derive_in`] is used as its implementation. This method must return the same
    /// value as [`derive_in`] on the same input.
    ///
    /// [`derive_in`]: Self::derive_in
    #[inline]
    fn derive_owned_in(&self, secret_key: Self::SecretKey, compiler: &mut COM) -> Self::PublicKey {
        self.derive_in(&secret_key, compiler)
    }

    /// Derives a public key corresponding to `secret_key`. This public key should be sent to the
    /// other party involved in the shared computation.
    ///
    /// See [`derive_owned_in`](Self::derive_owned_in) for more.
    #[inline]
    fn derive_owned(&self, secret_key: Self::SecretKey) -> Self::PublicKey
    where
        COM: Native,
    {
        self.derive(&secret_key)
    }

    /// Computes the shared secret given the known `secret_key` and the given `public_key` in the
    /// given `compiler`.
    fn agree_in(
        &self,
        secret_key: &Self::SecretKey,
        public_key: &Self::PublicKey,
        compiler: &mut COM,
    ) -> Self::SharedSecret;

    /// Computes the shared secret given the known `secret_key` and the given `public_key`.
    #[inline]
    fn agree(
        &self,
        secret_key: &Self::SecretKey,
        public_key: &Self::PublicKey,
    ) -> Self::SharedSecret
    where
        COM: Native,
    {
        self.agree_in(secret_key, public_key, &mut COM::compiler())
    }

    /// Computes the shared secret given the known `secret_key` and the given `public_key` in the
    /// given `compiler`.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for [`agree_in`] when the `secret_key` value and
    /// `public_key` value are owned, and by default, [`agree_in`] is used as its implementation. This
    /// method must return the same value as [`agree_in`] on the same input.
    ///
    /// [`agree_in`]: Self::agree_in
    #[inline]
    fn agree_owned_in(
        &self,
        secret_key: Self::SecretKey,
        public_key: Self::PublicKey,
        compiler: &mut COM,
    ) -> Self::SharedSecret {
        self.agree_in(&secret_key, &public_key, compiler)
    }

    /// Computes the shared secret given the known `secret_key` and the given `public_key`.
    ///
    /// See [`agree_owned_in`](Self::agree_owned_in) for more.
    #[inline]
    fn agree_owned(
        &self,
        secret_key: Self::SecretKey,
        public_key: Self::PublicKey,
    ) -> Self::SharedSecret
    where
        COM: Native,
    {
        self.agree(&secret_key, &public_key)
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
    pub fn key_agreement<K>(parameters: &K, lhs: &K::SecretKey, rhs: &K::SecretKey)
    where
        K: KeyAgreementScheme,
        K::SharedSecret: Debug + PartialEq,
    {
        assert_eq!(
            parameters.agree(lhs, &parameters.derive(rhs)),
            parameters.agree(rhs, &parameters.derive(lhs)),
            "Key agreement schemes should satisfy the agreement property."
        )
    }
}
