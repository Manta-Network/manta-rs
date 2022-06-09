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

/// Key Agreement Scheme
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
}
