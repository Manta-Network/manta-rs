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

//! Signature Schemes

use crate::{constraint::Native, key::KeyDerivationFunction};

/// Signature Scheme
pub trait SignatureScheme<COM = ()>: KeyDerivationFunction<COM> {
    /// Message Type
    type Message;

    /// Signature Type
    type Signature;

    /// Signs a message of type [`Message`](Self::Message) with `key` in `compiler`.
    fn sign_in(
        &self,
        key: &Self::Key,
        message: &Self::Message,
        compiler: &mut COM,
    ) -> Self::Signature;

    /// Signs a message of type [`Message`](Self::Message) with `key`.
    #[inline]
    fn sign(&self, key: &Self::Key, message: &Self::Message) -> Self::Signature
    where
        COM: Native,
    {
        self.sign_in(key, message, &mut COM::compiler())
    }

    /// Signs a message of type [`Message`](Self::Message) with `key` in `compiler`.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for [`sign_in`] when the `key` value
    /// is owned, and by default, [`sign_in`] is used as its implementation. This
    /// method must return the same value as [`sign_in`] on the same input.
    ///
    /// [`sign_in`]: Self::sign_in
    #[inline]
    fn sign_owned_in(
        &self,
        key: Self::Key,
        message: Self::Message,
        compiler: &mut COM,
    ) -> Self::Signature
    where
        Self::Key: Sized,
    {
        self.sign_in(&key, &message, compiler)
    }

    /// Signs a message of type [`Message`](Self::Message) with `key`.
    ///
    /// # Implementation Note
    ///
    /// See [`sign_owned_in`](Self::sign_owned_in) for more.
    #[inline]
    fn sign_owned(&self, key: Self::Key, message: Self::Message) -> Self::Signature
    where
        COM: Native,
        Self::Key: Sized,
    {
        self.sign_in(&key, &message, &mut COM::compiler())
    }

    /// Verifies a signature of type [`Signature`](Self::Signature) with `public_key`
    /// and `message` in `compiler`.
    fn verify_in(
        &self,
        public_key: &Self::Output,
        message: &Self::Message,
        signature: &Self::Signature,
        compiler: &mut COM,
    ) -> bool;

    /// Verifies a signature of type [`Signature`](Self::Signature) with `public_key`
    /// and `message`.
    #[inline]
    fn verify(
        &self,
        public_key: &Self::Output,
        message: &Self::Message,
        signature: &Self::Signature,
    ) -> bool
    where
        COM: Native,
    {
        self.verify_in(public_key, message, signature, &mut COM::compiler())
    }

    /// Verifies a signature of type [`Signature`](Self::Signature) with `public_key`
    /// and `message` in `compiler`.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for [`verify_in`] when the `key` value is
    /// owned, and by default, [`verify_in`] is used as its implementation. This method
    /// must return the same value as [`verify_in`] on the same input.
    ///
    /// [`verify_in`]: Self::derive_in
    #[inline]
    fn verify_owned_in(
        &self,
        public_key: Self::Output,
        message: Self::Message,
        signature: Self::Signature,
        compiler: &mut COM,
    ) -> bool {
        self.verify_in(&public_key, &message, &signature, compiler)
    }

    /// Verifies a signature of type [`Signature`](Self::Signature) with `public_key`
    /// and `message`.
    ///
    /// See [`verify_in`](Self::verify_in) for more.
    #[inline]
    fn verify_owned(
        &self,
        public_key: Self::Output,
        message: Self::Message,
        signature: Self::Signature,
    ) -> bool
    where
        COM: Native,
    {
        self.verify_in(&public_key, &message, &signature, &mut COM::compiler())
    }
}
