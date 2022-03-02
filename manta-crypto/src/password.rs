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

//! Password Hashing Primitives

use core::{fmt::Debug, hash::Hash};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Password Hasher
pub trait Hasher {
    /// Password Type
    ///
    /// In general, this type can be `[u8]` but if the password must be a certain length or must
    /// have a particular format, this should be a custom type which parses or validates the input
    /// password.
    type Password: ?Sized;

    /// Salt Type
    type Salt;

    /// Hash Type
    type Hash: PartialEq;

    /// Hashes `password` with the given `salt`.
    fn hash(&self, salt: &Self::Salt, password: &Self::Password) -> Self::Hash;

    /// Hashes `password` with the given `salt`, and checks that its output hash is equal to `hash`.
    #[inline]
    fn verify(&self, salt: &Self::Salt, hash: &Self::Hash, password: &Self::Password) -> bool {
        &self.hash(salt, password) == hash
    }
}

/// Password Hash
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "H: Clone, H::Salt: Clone, H::Hash: Clone"),
    Copy(bound = "H: Copy, H::Salt: Copy, H::Hash: Copy"),
    Debug(bound = "H: Debug, H::Salt: Debug, H::Hash: Debug"),
    Eq(bound = "H: Eq, H::Salt: Eq, H::Hash: Eq"),
    Hash(bound = "H: Hash, H::Salt: Hash, H::Hash: Hash"),
    PartialEq(bound = "H: PartialEq, H::Salt: PartialEq, H::Hash: PartialEq")
)]
pub struct PasswordHash<H>
where
    H: Hasher,
{
    /// Hasher
    hasher: H,

    /// Hash Salt
    salt: H::Salt,

    /// Output Hash
    hash: H::Hash,
}

impl<H> PasswordHash<H>
where
    H: Hasher,
{
    /// Hashes `password` with the given `hasher` and `salt`.
    #[inline]
    pub fn new(hasher: H, salt: H::Salt, password: &H::Password) -> Self {
        Self {
            hash: hasher.hash(&salt, password),
            hasher,
            salt,
        }
    }

    /// Hashes `password` with the given `salt` using the default [`Hasher`].
    #[inline]
    pub fn from_default(salt: H::Salt, password: &H::Password) -> Self
    where
        H: Default,
    {
        Self::new(H::default(), salt, password)
    }

    /// Verifies that `password` hashes to the same value as the hash stored in `self`.
    #[inline]
    pub fn verify(&self, password: &H::Password) -> bool {
        self.hasher.verify(&self.salt, &self.hash, password)
    }

    /// Returns a shared reference to the [`Hasher`] used to generate `self`.
    #[inline]
    pub fn hasher(&self) -> &H {
        &self.hasher
    }

    /// Returns a shared reference to the salt used to generate `self`.
    #[inline]
    pub fn salt(&self) -> &H::Salt {
        &self.salt
    }

    /// Returns a shared reference to the hash stored in `self`.
    #[inline]
    pub fn hash(&self) -> &H::Hash {
        &self.hash
    }
}
