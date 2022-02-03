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

use alloc::vec::Vec;
use core::{fmt::Debug, hash::Hash};

/// Open Options
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct OpenOptions {
    ///
    read: bool,

    ///
    write: bool,

    ///
    append: bool,

    ///
    truncate: bool,

    ///
    create: bool,

    ///
    create_new: bool,
}

impl OpenOptions {
    /// Builds a new default [`OpenOptions`].
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    ///
    #[inline]
    pub fn read(mut self, read: bool) -> Self {
        self.read = read;
        self
    }

    ///
    #[inline]
    pub fn write(mut self, write: bool) -> Self {
        self.write = write;
        self
    }

    ///
    #[inline]
    pub fn append(mut self, append: bool) -> Self {
        self.append = append;
        self
    }

    ///
    #[inline]
    pub fn truncate(mut self, truncate: bool) -> Self {
        self.truncate = truncate;
        self
    }

    ///
    #[inline]
    pub fn create(mut self, create: bool) -> Self {
        self.create = create;
        self
    }

    ///
    #[inline]
    pub fn create_new(mut self, create_new: bool) -> Self {
        self.create_new = create_new;
        self
    }

    ///
    #[inline]
    pub fn open<F, P>(&self, path: P, password: &[u8]) -> Result<F, F::Error>
    where
        F: File,
        P: AsRef<F::Path>,
    {
        F::open(path, password, self)
    }
}

/// Data Block
pub struct Block {
    /// Block Data
    data: Box<[u8; 8192]>,
}

impl Block {
    /// Builds a new [`Block`] from an owned collection of bytes.
    #[inline]
    pub fn new(data: Vec<u8>) -> Option<Self> {
        Some(Self {
            data: data.into_boxed_slice().try_into().ok()?,
        })
    }
}

/// Encrypted File
pub trait File: Sized {
    /// Path Type
    type Path: ?Sized;

    /// Error Type
    type Error;

    /// Opens a new file at `path` with `password` and `options`.
    fn open<P>(path: P, password: &[u8], options: &OpenOptions) -> Result<Self, Self::Error>
    where
        P: AsRef<Self::Path>;

    /// Creates a new file at `path` with `password`.
    #[inline]
    fn create<P>(path: P, password: &[u8]) -> Result<Self, Self::Error>
    where
        P: AsRef<Self::Path>,
    {
        OpenOptions::new().create(true).open(path, password)
    }

    /// Writes `block` to `self` after encrypting it.
    fn write(&mut self, block: Block) -> Result<(), Self::Error>;

    /// Reads a [`Block`] from `self` after decrypting it.
    fn read(&mut self) -> Result<Block, Self::Error>;
}

/// Encrypting Serializer
pub struct Serializer<'f, F>
where
    F: File,
{
    /// Encrypted File
    file: &'f mut F,
}

impl<'f, F> Serializer<'f, F>
where
    F: File,
{
    ///
    #[inline]
    pub fn new(file: &'f mut F) -> Self {
        Self { file }
    }
}

// TODO: impl<'f, F> serde::Serializer for Serializer<'f, F> where F: File {}

/// Decrypting Deserializer
pub struct Deserializer<'f, F>
where
    F: File,
{
    /// Encrypted File
    file: &'f mut F,
}

impl<'f, F> Deserializer<'f, F>
where
    F: File,
{
    ///
    #[inline]
    pub fn new(file: &'f mut F) -> Self {
        Self { file }
    }
}

// TODO: impl<'de, 'f, F> serde::Deserializer<'de> for Deserializer<'f, F> where F: File + Read {}

/// Cocoon Encrypted File System Adapter
#[cfg(feature = "cocoon-fs")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "cocoon-fs")))]
pub mod cocoon {
    use super::*;
    use cocoon_crate::{Error as CocoonError, MiniCocoon};
    use core::fmt;
    use manta_crypto::rand::{Rand, SeedableRng};
    use manta_util::from_variant_impl;
    use rand_chacha::ChaCha20Rng;
    use std::{
        fs::{self, OpenOptions},
        io::Error as IoError,
        path::Path,
    };

    /// Cocoon Loading/Saving Error
    #[derive(Debug)]
    pub enum Error {
        /// I/O Error
        IoError(IoError),

        /// Cocoon Error
        Cocoon(CocoonError),

        /// Invalid Block Size
        InvalidBlockSize,
    }

    from_variant_impl!(Error, IoError, IoError);
    from_variant_impl!(Error, Cocoon, CocoonError);

    impl fmt::Display for Error {
        #[inline]
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                Self::IoError(err) => write!(f, "File I/O Error: {}", err),
                Self::Cocoon(err) => write!(f, "Cocoon Error: {:?}", err),
                Self::InvalidBlockSize => write!(f, "Invalid Block Size"),
            }
        }
    }

    impl std::error::Error for Error {}

    /// Encrypted File
    pub struct File {
        /// File Pointer
        file: fs::File,

        /// Encrypting Device
        cocoon: MiniCocoon,
    }

    impl File {
        /// Builds a new [`File`] for encrypted data storage with `password`.
        #[inline]
        fn new(
            path: &Path,
            password: &[u8],
            options: &super::OpenOptions,
        ) -> Result<Self, IoError> {
            Ok(Self {
                file: OpenOptions::new()
                    .read(options.read)
                    .write(options.write)
                    .append(options.append)
                    .truncate(options.truncate)
                    .create(options.create)
                    .create_new(options.create_new)
                    .open(path)?,
                cocoon: MiniCocoon::from_password(
                    password,
                    &ChaCha20Rng::from_entropy().gen::<_, [u8; 32]>(),
                ),
            })
        }
    }

    impl super::File for File {
        type Path = Path;
        type Error = Error;

        #[inline]
        fn open<P>(
            path: P,
            password: &[u8],
            options: &super::OpenOptions,
        ) -> Result<Self, Self::Error>
        where
            P: AsRef<Path>,
        {
            Ok(Self::new(path.as_ref(), password, options)?)
        }

        #[inline]
        fn write(&mut self, block: Block) -> Result<(), Self::Error> {
            Ok(self.cocoon.dump(block.data.to_vec(), &mut self.file)?)
        }

        #[inline]
        fn read(&mut self) -> Result<Block, Self::Error> {
            Block::new(self.cocoon.parse(&mut self.file)?).ok_or(Error::InvalidBlockSize)
        }
    }
}
