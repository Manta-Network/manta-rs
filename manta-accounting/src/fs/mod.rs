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
//!
//! This module defines an abstraction over the standard file system which enforces that data is
//! encrypted before being written and decrypted after being read. See [`File`] for the main
//! abstraction which allows for encrypted file systems and [`cocoon`] for a concrete implementation
//! of this file system.
//!
//! # Serialization
//!
//! For these file system abstractions we use the [`Block`] type for buffering raw binary data into
//! an encryption scheme, so to facilitate the encryption of structured data, we have the [`serde`]
//! module which defines serializers and deserializers which encrypt and decrypt data on the fly
//! using the [`Block`] as the underlying serialization and deserialization target. See the
//! [`serde`] module for more.

use alloc::{boxed::Box, vec::Vec};
use core::{cmp, hash::Hash, marker::PhantomData};

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
use core::fmt::{Debug, Display};

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
pub use serde::{de::Error as LoadError, ser::Error as SaveError};

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
pub mod serde;

bitflags::bitflags! {
    /// File Access Mode
    pub struct AccessMode: u8 {
        /// Read Access Mode
        const READ = 0b0001;

        /// Write Access Mode
        const WRITE = 0b0010;

        /// Append Mode
        const APPEND = 0b0100;
    }

    /// File Creation Mode
    #[derive(Default)]
    pub struct CreationMode: u8 {
        /// Create Mode
        const CREATE = 0b0001;

        /// Truncate Mode
        const TRUNCATE = 0b0010;

        /// Exclusive Creation Mode
        const EXCLUSIVE = 0b0100;
    }
}

/// Open Options
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[must_use]
pub struct OpenOptions<F>
where
    F: File,
{
    /// Read Access
    read: bool,

    /// Write Access
    write: bool,

    /// Append Mode
    append: bool,

    /// Truncate Mode
    truncate: bool,

    /// Create Mode
    create: bool,

    /// Create New Mode
    create_new: bool,

    /// Type Parameter Marker
    __: PhantomData<F>,
}

impl<F> OpenOptions<F>
where
    F: File,
{
    /// Builds a new default [`OpenOptions`].
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the `read` flag in `self`.
    #[inline]
    pub fn read(mut self, read: bool) -> Self {
        self.read = read;
        self
    }

    /// Sets the `write` flag in `self`.
    #[inline]
    pub fn write(mut self, write: bool) -> Self {
        self.write = write;
        self
    }

    /// Sets the `append` flag in `self`.
    #[inline]
    pub fn append(mut self, append: bool) -> Self {
        self.append = append;
        self
    }

    /// Sets the `truncate` flag in `self`.
    #[inline]
    pub fn truncate(mut self, truncate: bool) -> Self {
        self.truncate = truncate;
        self
    }

    /// Sets the `create` flag in `self`.
    #[inline]
    pub fn create(mut self, create: bool) -> Self {
        self.create = create;
        self
    }

    /// Sets the `create_new` flag in `self`.
    #[inline]
    pub fn create_new(mut self, create_new: bool) -> Self {
        self.create_new = create_new;
        self
    }

    /// Returns the [`AccessMode`] for the combination of options stored in `self`.
    #[inline]
    pub fn access_mode(&self) -> Option<AccessMode> {
        match (self.read, self.write, self.append) {
            (true, false, false) => Some(AccessMode::READ),
            (false, true, false) => Some(AccessMode::WRITE),
            (true, true, false) => Some(AccessMode::READ | AccessMode::WRITE),
            (false, _, true) => Some(AccessMode::WRITE | AccessMode::APPEND),
            (true, _, true) => Some(AccessMode::READ | AccessMode::WRITE | AccessMode::APPEND),
            (false, false, false) => None,
        }
    }

    /// Returns the [`CreationMode`] for the combination of options stored in `self`.
    #[inline]
    pub fn creation_mode(&self) -> Option<CreationMode> {
        match (self.write, self.append) {
            (true, false) => {}
            (false, false) => {
                if self.truncate || self.create || self.create_new {
                    return None;
                }
            }
            (_, true) => {
                if self.truncate && !self.create_new {
                    return None;
                }
            }
        }
        Some(match (self.create, self.truncate, self.create_new) {
            (false, false, false) => CreationMode::empty(),
            (true, false, false) => CreationMode::CREATE,
            (false, true, false) => CreationMode::TRUNCATE,
            (true, true, false) => CreationMode::CREATE | CreationMode::TRUNCATE,
            (_, _, true) => CreationMode::CREATE | CreationMode::EXCLUSIVE,
        })
    }

    /// Opens a file of type `F` at the given `path` using `self` for opening options and `password`
    /// for encryption.
    #[inline]
    pub fn open<P>(&self, path: P, password: &[u8]) -> Result<F, F::Error>
    where
        P: AsRef<F::Path>,
    {
        F::open(path, password, self)
    }
}

#[cfg(feature = "std")]
impl<F> From<OpenOptions<F>> for std::fs::OpenOptions
where
    F: File,
{
    #[inline]
    fn from(options: OpenOptions<F>) -> Self {
        let mut result = Self::new();
        result
            .read(options.read)
            .write(options.write)
            .append(options.append)
            .truncate(options.truncate)
            .create(options.create)
            .create_new(options.create_new);
        result
    }
}

/// Data Block
pub struct Block {
    /// Block Data
    data: Box<[u8; Self::SIZE]>,
}

impl Block {
    /// Block Size
    pub const SIZE: usize = 8192;

    /// Builds a new [`Block`] from an owned collection of bytes. If the `data` vector is too short
    /// it's padded to fit the block and if it's too long, `None` is returned.
    #[inline]
    pub fn new(data: Vec<u8>) -> Option<Self> {
        (data.len() <= Self::SIZE).then(|| Self::new_unchecked(data))
    }

    /// Builds a new [`Block`] from an owned collection of bytes without checking if the data vector
    /// is too long to fit into a block.
    #[inline]
    pub fn new_unchecked(mut data: Vec<u8>) -> Self {
        data.resize(Self::SIZE, 0);
        Self {
            data: data
                .into_boxed_slice()
                .try_into()
                .expect("Input data is guaranteed to be no greater than the block size."),
        }
    }

    /// Parses a [`Block`] from an owned collection of bytes, leaving the remaining bytes in `data`
    /// that don't fit into a single [`Block`] and padding otherwise.
    #[inline]
    pub fn parse(data: &mut Vec<u8>) -> Self {
        Self::new_unchecked(data.drain(..cmp::min(data.len(), Self::SIZE)).collect())
    }

    /// Parses a [`Block`] from an owned collection of bytes, if the bytes in `data` fill at least
    /// one [`Block`] otherwise, return `None`.
    #[inline]
    pub fn parse_full(data: &mut Vec<u8>) -> Option<Self> {
        (data.len() >= Self::SIZE).then(|| Self::parse(data))
    }
}

impl Default for Block {
    #[inline]
    fn default() -> Self {
        Self {
            data: Box::new([0; Self::SIZE]),
        }
    }
}

impl From<Block> for Vec<u8> {
    #[inline]
    fn from(block: Block) -> Self {
        block.data.to_vec()
    }
}

/// Encrypted File
pub trait File: Sized {
    /// Path Type
    type Path: AsRef<Self::Path> + ?Sized;

    /// Error Type
    type Error;

    /// Opens a new file at `path` with `password` and `options`.
    fn open<P>(path: P, password: &[u8], options: &OpenOptions<Self>) -> Result<Self, Self::Error>
    where
        P: AsRef<Self::Path>;

    /// Creates a new file at `path` with `password`.
    #[inline]
    fn create<P>(path: P, password: &[u8]) -> Result<Self, Self::Error>
    where
        P: AsRef<Self::Path>,
    {
        Self::options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path, password)
    }

    /// Returns a new [`OpenOptions`] object.
    #[inline]
    fn options() -> OpenOptions<Self> {
        OpenOptions::new()
    }

    /// Writes `block` to `self` after encrypting it.
    fn write(&mut self, block: Block) -> Result<(), Self::Error>;

    /// Reads a [`Block`] from `self` after decrypting it, returning `None` if there are no more
    /// blocks in the file.
    fn read(&mut self) -> Result<Option<Block>, Self::Error>;

    /// Saves `value` to `path` by serializing and encrypting with `password`.
    #[cfg(feature = "serde")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
    #[inline]
    fn save<P, T>(path: P, password: &[u8], value: T) -> Result<(), SaveError<Self>>
    where
        Self::Error: Debug + Display,
        P: AsRef<Self::Path>,
        T: serde::Serialize,
    {
        let mut file = Self::options()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path, password)
            .map_err(SaveError::Io)?;
        value.serialize(&mut serde::Serializer::new(&mut file))
    }

    /// Loads a value of type `T` from `path` by deserializing and decrypting with `password`.
    #[cfg(feature = "serde")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
    #[inline]
    fn load<P, T>(path: P, password: &[u8]) -> Result<T, LoadError<Self>>
    where
        Self::Error: Debug + Display,
        P: AsRef<Self::Path>,
        T: serde::DeserializeOwned,
    {
        let mut file = Self::options()
            .read(true)
            .open(path, password)
            .map_err(LoadError::Io)?;
        T::deserialize(&mut serde::Deserializer::new(&mut file))
    }
}

/// Cocoon Encrypted File System Adapter
#[cfg(feature = "cocoon-fs")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "cocoon-fs")))]
pub mod cocoon {
    use super::{Block, OpenOptions};
    use cocoon::{Error as CocoonError, MiniCocoon};
    use core::fmt;
    use manta_util::from_variant;
    use std::{fs, io::Error as IoError, path::Path};

    /// Cocoon Loading/Saving Error
    #[derive(Debug)]
    pub enum Error {
        /// I/O Error
        IoError(IoError),

        /// Cocoon Error
        Cocoon(CocoonError),
    }

    from_variant!(Error, IoError, IoError);
    from_variant!(Error, Cocoon, CocoonError);

    impl fmt::Display for Error {
        #[inline]
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                Self::IoError(err) => write!(f, "File I/O Error: {}", err),
                Self::Cocoon(err) => write!(f, "Cocoon Error: {:?}", err),
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
        fn new(path: &Path, password: &[u8], options: OpenOptions<Self>) -> Result<Self, IoError> {
            Ok(Self {
                file: fs::OpenOptions::from(options).open(path)?,
                cocoon: {
                    // FIXME: Use a random seed here. Ideally, we want to rewrite `cocoon` for
                    //        better security and flexibility and move to a streaming encryption
                    //        protocol.
                    MiniCocoon::from_password(password, &[0; 32])
                },
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
            options: &OpenOptions<Self>,
        ) -> Result<Self, Self::Error>
        where
            P: AsRef<Path>,
        {
            Ok(Self::new(path.as_ref(), password, *options)?)
        }

        #[inline]
        fn write(&mut self, block: Block) -> Result<(), Self::Error> {
            Ok(self.cocoon.dump(block.into(), &mut self.file)?)
        }

        #[inline]
        fn read(&mut self) -> Result<Option<Block>, Self::Error> {
            let data = self.cocoon.parse(&mut self.file)?;
            if !data.is_empty() {
                Ok(Block::new(data))
            } else {
                Ok(None)
            }
        }
    }
}
