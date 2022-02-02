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

//! Encrypted Filesystem Primitives

// FIXME: Add streaming interfaces.

use alloc::vec::Vec;
use core::{fmt::Debug, hash::Hash};
use manta_util::codec::{Decode, Encode};

/// Filesystem Encrypted Saving
pub trait SaveEncrypted {
    /// Path Type
    type Path: ?Sized;

    /// Saving Key Type
    type SavingKey: ?Sized;

    /// Saving Error
    type Error;

    /// Saves the `payload` to `path` using the `saving_key` to encrypt it.
    fn save_bytes<P>(
        path: P,
        saving_key: &Self::SavingKey,
        payload: Vec<u8>,
    ) -> Result<(), Self::Error>
    where
        P: AsRef<Self::Path>;

    /// Saves the `payload` to `path` after serializing using the `saving_key` to encrypt it.
    #[inline]
    fn save<P, E>(path: P, saving_key: &Self::SavingKey, payload: &E) -> Result<(), Self::Error>
    where
        P: AsRef<Self::Path>,
        E: Encode,
    {
        Self::save_bytes(path, saving_key, payload.to_vec())
    }
}

/// Filesystem Decrypted Loading
pub trait LoadDecrypted {
    /// Path Type
    type Path: ?Sized;

    /// Loading Key Type
    type LoadingKey: ?Sized;

    /// Loading Error Type
    type Error;

    /// Loads a vector of bytes from `path` using `loading_key` to decrypt them.
    fn load_bytes<P>(path: P, loading_key: &Self::LoadingKey) -> Result<Vec<u8>, Self::Error>
    where
        P: AsRef<Self::Path>;

    /// Loads a vector of bytes from `path` using `loading_key` to decrypt them, then deserializing
    /// the bytes to a concrete value of type `D`.
    #[inline]
    fn load<P, D>(path: P, loading_key: &Self::LoadingKey) -> Result<D, LoadError<Self, D>>
    where
        P: AsRef<Self::Path>,
        D: Decode,
    {
        match Self::load_bytes(path, loading_key) {
            Ok(bytes) => D::from_vec(bytes).map_err(LoadError::Decode),
            Err(err) => Err(LoadError::Loading(err)),
        }
    }
}

/// Loading Error
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "L::Error: Clone, D::Error: Clone"),
    Copy(bound = "L::Error: Copy, D::Error: Copy"),
    Debug(bound = "L::Error: Debug, D::Error: Debug"),
    Eq(bound = "L::Error: Eq, D::Error: Eq"),
    Hash(bound = "L::Error: Hash, D::Error: Hash"),
    PartialEq(bound = "L::Error: PartialEq, D::Error: PartialEq")
)]
pub enum LoadError<L, D>
where
    L: LoadDecrypted + ?Sized,
    D: Decode + ?Sized,
{
    /// Payload Loading Error
    Loading(L::Error),

    /// Decoding Error
    Decode(D::Error),
}

/// Cocoon Adapters
#[cfg(feature = "cocoon-fs")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "cocoon-fs")))]
pub mod cocoon {
    use super::*;
    use cocoon_crate::{Cocoon, Error as CocoonError};
    use core::fmt;
    use manta_util::from_variant_impl;
    use std::{
        fs::OpenOptions,
        io::{Error as IoError, Read, Write},
        path::Path,
    };
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

    impl std::error::Error for Error {}

    /// Cocoon [`SaveEncrypted`] Adapter
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct Save;

    impl SaveEncrypted for Save {
        type Path = Path;
        type SavingKey = [u8];
        type Error = Error;

        #[inline]
        fn save_bytes<P>(
            path: P,
            saving_key: &Self::SavingKey,
            payload: Vec<u8>,
        ) -> Result<(), Self::Error>
        where
            P: AsRef<Self::Path>,
        {
            let mut buffer = Zeroizing::new(Vec::new());
            Cocoon::new(saving_key).dump(payload, &mut buffer.as_mut_slice())?;
            OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(path)?
                .write_all(&buffer)?;
            Ok(())
        }
    }

    /// Cocoon [`LoadDecrypted`] Adapter
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct Load;

    impl LoadDecrypted for Load {
        type Path = Path;
        type LoadingKey = [u8];
        type Error = Error;

        #[inline]
        fn load_bytes<P>(path: P, loading_key: &Self::LoadingKey) -> Result<Vec<u8>, Self::Error>
        where
            P: AsRef<Self::Path>,
        {
            let mut buffer = Zeroizing::new(Vec::new());
            let mut file = OpenOptions::new().read(true).open(path)?;
            file.read_to_end(&mut buffer)?;
            Ok(Cocoon::parse_only(loading_key).parse(&mut buffer.as_slice())?)
        }
    }
}
