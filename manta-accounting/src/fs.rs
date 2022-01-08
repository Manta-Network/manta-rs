// Copyright 2019-2021 Manta Network.
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

//! Encrypted Filesystem Primitives

// FIXME: Add asynchronous streaming interfaces.

use alloc::vec::Vec;
use core::future::Future;

/// Serialization
pub trait Serialize {
    /// Appends representation of `self` in bytes to `buffer`.
    fn serialize(&self, buffer: &mut Vec<u8>);

    /// Converts `self` into a vector of bytes.
    #[inline]
    fn to_vec(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        self.serialize(&mut buffer);
        buffer
    }
}

impl Serialize for u8 {
    #[inline]
    fn serialize(&self, buffer: &mut Vec<u8>) {
        buffer.push(*self);
    }
}

impl<T> Serialize for [T]
where
    T: Serialize,
{
    #[inline]
    fn serialize(&self, buffer: &mut Vec<u8>) {
        for item in self {
            item.serialize(buffer);
        }
    }
}

impl<T, const N: usize> Serialize for [T; N]
where
    T: Serialize,
{
    #[inline]
    fn serialize(&self, buffer: &mut Vec<u8>) {
        for item in self {
            item.serialize(buffer);
        }
    }
}

/// Deserialization
pub trait Deserialize: Sized {
    /// Error Type
    type Error;

    /// Parses the input `buffer` into a concrete value of type `Self` if possible.
    fn deserialize(buffer: Vec<u8>) -> Result<Self, Self::Error>;
}

/// Filesystem Encrypted Saving
pub trait SaveEncrypted {
    /// Path Type
    type Path;

    /// Saving Key Type
    type SavingKey;

    /// Saving Error
    type Error;

    /// Saving Future
    type Future: Future<Output = Result<(), Self::Error>>;

    /// Saves the `payload` to `path` using the `saving_key` to encrypt it.
    fn save_bytes(path: Self::Path, saving_key: Self::SavingKey, payload: Vec<u8>) -> Self::Future;

    /// Saves the `payload` to `path` after serializing using the `saving_key` to encrypt it.
    #[inline]
    fn save<S>(path: Self::Path, saving_key: Self::SavingKey, payload: &S) -> Self::Future
    where
        S: Serialize,
    {
        Self::save_bytes(path, saving_key, payload.to_vec())
    }
}

/// Filesystem Decrypted Loading
pub trait LoadDecrypted {
    /// Path Type
    type Path;

    /// Loading Key Type
    type LoadingKey;

    /// Loading Error Type
    type Error;

    /// Loading Future
    type Future: Future<Output = Result<Vec<u8>, Self::Error>>;

    /// Loads a vector of bytes from `path` using `loading_key` to decrypt them.
    fn load_bytes(path: Self::Path, loading_key: Self::LoadingKey) -> Self::Future;
}

/// Loads a vector of bytes from `path` using `loading_key` to decrypt them, then deserializing
/// the bytes to a concrete value of type `D`.
#[inline]
pub async fn load<L, D>(path: L::Path, loading_key: L::LoadingKey) -> Result<D, LoadError<D, L>>
where
    L: LoadDecrypted,
    D: Deserialize,
{
    match L::load_bytes(path, loading_key).await {
        Ok(bytes) => D::deserialize(bytes).map_err(LoadError::Deserialize),
        Err(err) => Err(LoadError::Loading(err)),
    }
}

/// Loading Error
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LoadError<D, L>
where
    D: Deserialize,
    L: LoadDecrypted,
{
    /// Deserialization Error
    Deserialize(D::Error),

    /// Payload Loading Error
    Loading(L::Error),
}

/// Cocoon Adapters
#[cfg(feature = "cocoon-fs")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "cocoon-fs")))]
pub mod cocoon {
    use super::*;
    use async_std::{
        fs::OpenOptions,
        io::{Error as IoError, ReadExt, WriteExt},
        path::PathBuf,
    };
    use cocoon_crate::{Cocoon, Error as CocoonError};
    use core::fmt;
    use futures::future::LocalBoxFuture;
    use manta_util::from_variant_impl;
    use zeroize::Zeroizing;

    /// Cocoon Loading/Saving Error
    #[derive(Debug)]
    pub enum Error {
        /// File Opening Error
        UnableToOpenFile(IoError),

        /// Cocoon Error
        Cocoon(CocoonError),
    }

    from_variant_impl!(Error, UnableToOpenFile, IoError);
    from_variant_impl!(Error, Cocoon, CocoonError);

    impl fmt::Display for Error {
        #[inline]
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                Self::UnableToOpenFile(err) => write!(f, "File Opening Error: {}", err),
                Self::Cocoon(err) => write!(f, "Cocoon Error: {:?}", err),
            }
        }
    }

    #[cfg(feature = "std")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
    impl std::error::Error for Error {}

    /// Cocoon [`SaveEncrypted`] Adapter
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct Save;

    impl SaveEncrypted for Save {
        type Path = PathBuf;
        type SavingKey = Vec<u8>;
        type Error = Error;
        type Future = LocalBoxFuture<'static, Result<(), Self::Error>>;

        #[inline]
        fn save_bytes(
            path: Self::Path,
            saving_key: Self::SavingKey,
            payload: Vec<u8>,
        ) -> Self::Future {
            Box::pin(async {
                let saving_key = Zeroizing::new(saving_key);
                let mut buffer = Zeroizing::new(Vec::new());
                Cocoon::new(&saving_key).dump(payload, &mut buffer.as_mut_slice())?;
                OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .open(path)
                    .await?
                    .write_all(&buffer)
                    .await?;
                Ok(())
            })
        }
    }

    /// Cocoon [`LoadDecrypted`] Adapter
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct Load;

    impl LoadDecrypted for Load {
        type Path = PathBuf;
        type LoadingKey = Vec<u8>;
        type Error = Error;
        type Future = LocalBoxFuture<'static, Result<Vec<u8>, Self::Error>>;

        #[inline]
        fn load_bytes(path: Self::Path, loading_key: Self::LoadingKey) -> Self::Future {
            Box::pin(async move {
                let loading_key = Zeroizing::new(loading_key);
                let mut buffer = Zeroizing::new(Vec::new());
                let mut file = OpenOptions::new().read(true).open(path).await?;
                file.read_to_end(&mut buffer).await?;
                Ok(Cocoon::parse_only(&loading_key).parse(&mut buffer.as_slice())?)
            })
        }
    }
}
