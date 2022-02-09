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

use alloc::{boxed::Box, vec::Vec};
use core::{fmt::Debug, hash::Hash};

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
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[must_use]
pub struct OpenOptions {
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
}

impl OpenOptions {
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
    pub fn open<F, P>(&self, path: P, password: &[u8]) -> Result<F, F::Error>
    where
        F: File,
        P: AsRef<F::Path>,
    {
        F::open(path, password, self)
    }
}

#[cfg(feature = "std")]
impl From<OpenOptions> for std::fs::OpenOptions {
    #[inline]
    fn from(options: OpenOptions) -> Self {
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
    pub fn new(mut data: Vec<u8>) -> Option<Self> {
        if data.len() > Self::SIZE {
            return None;
        }
        data.resize(Self::SIZE, 0);
        Some(Self {
            data: data.into_boxed_slice().try_into().expect(""),
        })
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
        Self::options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path, password)
    }

    /// Returns a new [`OpenOptions`] object.
    #[inline]
    fn options() -> OpenOptions {
        OpenOptions::new()
    }

    /// Writes `block` to `self` after encrypting it.
    fn write(&mut self, block: Block) -> Result<(), Self::Error>;

    /// Reads a [`Block`] from `self` after decrypting it.
    fn read(&mut self) -> Result<Block, Self::Error>;
}

/// Cocoon Encrypted File System Adapter
#[cfg(feature = "cocoon-fs")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "cocoon-fs")))]
pub mod cocoon {
    use super::{Block, OpenOptions};
    use cocoon::{Error as CocoonError, MiniCocoon};
    use core::fmt;
    use manta_crypto::rand::{Rand, SeedableRng};
    use manta_util::from_variant_impl;
    use rand_chacha::ChaCha20Rng;
    use std::{fs, io::Error as IoError, path::Path};

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
        fn new(path: &Path, password: &[u8], options: OpenOptions) -> Result<Self, IoError> {
            Ok(Self {
                file: fs::OpenOptions::from(options).open(path)?,
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
        fn open<P>(path: P, password: &[u8], options: &OpenOptions) -> Result<Self, Self::Error>
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
        fn read(&mut self) -> Result<Block, Self::Error> {
            Block::new(self.cocoon.parse(&mut self.file)?).ok_or(Error::InvalidBlockSize)
        }
    }
}
