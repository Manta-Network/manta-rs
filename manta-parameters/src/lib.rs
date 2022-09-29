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

//! Manta Parameters

#![no_std]
#![cfg_attr(doc_cfg, feature(doc_cfg))]
#![forbid(rustdoc::broken_intra_doc_links)]
#![forbid(missing_docs)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
use std::{fs, io, path::Path};

#[cfg(feature = "download")]
use anyhow::Result;

/// Git Utilities
#[cfg(feature = "git")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "git")))]
pub mod git {
    use super::*;
    use core::fmt;
    use std::{borrow::ToOwned, error, string::String};

    #[doc(inline)]
    pub use git2::*;

    /// Errors for the [`current_branch`] Function
    #[derive(Debug, PartialEq)]
    pub enum CurrentBranchError {
        /// Current Git HEAD reference is not at a branch
        NotBranch,

        /// Unable to generate shorthand for the branch name
        MissingShorthand,

        /// Git Error
        Git(Error),
    }

    impl From<Error> for CurrentBranchError {
        #[inline]
        fn from(err: Error) -> Self {
            Self::Git(err)
        }
    }

    impl fmt::Display for CurrentBranchError {
        #[inline]
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                Self::NotBranch => write!(f, "CurrentBranchError: Not a Branch"),
                Self::MissingShorthand => write!(f, "Current Branch Error: Missing Shorthand"),
                Self::Git(err) => write!(f, "Current Branch Error: Git Error: {}", err),
            }
        }
    }

    impl error::Error for CurrentBranchError {}

    /// Returns the name of the current branch of this crate as a Git repository.
    #[inline]
    pub fn current_branch() -> Result<String, CurrentBranchError> {
        let repo = Repository::discover(".")?;
        let head = repo.head()?;
        if head.is_branch() {
            Ok(head
                .shorthand()
                .ok_or(CurrentBranchError::MissingShorthand)?
                .to_owned())
        } else {
            Err(CurrentBranchError::NotBranch)
        }
    }
}

/// GitHub Data File Downloading
#[cfg(feature = "download")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "download")))]
pub mod github {
    use super::*;
    use std::{
        fs::{File, OpenOptions},
        string::String,
    };

    /// GitHub Organization
    pub const ORGANIZATION: &str = "manta-network";

    /// Manta-RS GitHub Repository Name
    pub const REPO: &str = "manta-rs";

    /// Manta-Parameters GitHub Repository Name
    pub const CRATE: &str = "manta-parameters";

    /// Default GitHub Branch
    pub const DEFAULT_BRANCH: &str = "feat/new-circuits";

    /// Returns the Git-LFS URL for GitHub content at the given `branch` and `data_path`.
    #[inline]
    pub fn lfs_url(branch: &str, data_path: &str) -> String {
        std::format!(
            "https://media.githubusercontent.com/media/{ORGANIZATION}/{REPO}/{branch}/{CRATE}/{data_path}"
        )
    }

    /// Returns the raw file storage URL for GitHub content at the given `branch` and `data_path`.
    #[inline]
    pub fn raw_url(branch: &str, data_path: &str) -> String {
        std::format!(
            "https://raw.githubusercontent.com/{ORGANIZATION}/{REPO}/{branch}/{CRATE}/{data_path}"
        )
    }

    /// Downloads the data from `url` to `file` returning the number of bytes read.
    #[inline]
    fn download_from(url: String, file: &mut File) -> Result<u64> {
        Ok(attohttpc::get(url).send()?.write_to(file)?)
    }

    /// Downloads data from `data_path` relative to the given `branch` to a file at `path` without
    /// checking any checksums.
    ///
    /// # Safety
    ///
    /// Prefer the [`download`] method which checks the data against a given checksum.
    #[inline]
    pub fn download_unchecked<P>(branch: &str, data_path: &str, path: P) -> Result<()>
    where
        P: AsRef<Path>,
    {
        let mut file = OpenOptions::new().create(true).write(true).open(path)?;
        if download_from(lfs_url(branch, data_path), &mut file)? == 0 {
            download_from(raw_url(branch, data_path), &mut file)?;
        }
        Ok(())
    }

    /// Downloads data from `data_path` relative to the given `branch` to a file at `path` verifying
    /// that the data matches the `checksum`.
    #[inline]
    pub fn download<P>(branch: &str, data_path: &str, path: P, checksum: &[u8; 32]) -> Result<()>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref();
        download_unchecked(branch, data_path, path)?;
        anyhow::ensure!(
            verify_file(path, checksum)?,
            "Checksum did not match. Expected: {:?}",
            checksum
        );
        Ok(())
    }
}

/// Verifies the `data` against the `checksum`.
#[inline]
pub fn verify(data: &[u8], checksum: &[u8; 32]) -> bool {
    &blake3::hash(data) == checksum
}

/// Verifies the data in the file located at `path` against the `checksum`.
#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
#[inline]
pub fn verify_file<P>(path: P, checksum: &[u8; 32]) -> io::Result<bool>
where
    P: AsRef<Path>,
{
    Ok(verify(&fs::read(path)?, checksum))
}

/// Fixed Checksum
pub trait HasChecksum {
    /// Data Checksum for the Type
    const CHECKSUM: &'static [u8; 32];

    /// Verifies that `data` is compatible with [`CHECKSUM`](Self::CHECKSUM).
    #[inline]
    fn verify_data(data: &[u8]) -> bool {
        verify(data, Self::CHECKSUM)
    }

    /// Verifies that the data in the file located at `path` is compatible with
    /// [`CHECKSUM`](Self::CHECKSUM).
    #[cfg(feature = "std")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
    #[inline]
    fn verify_file<P>(path: P) -> io::Result<bool>
    where
        P: AsRef<Path>,
    {
        verify_file(path, Self::CHECKSUM)
    }
}

/// Local Data
pub trait Get: HasChecksum {
    /// Binary Data Payload
    const DATA: &'static [u8];

    /// Verifies that [`DATA`](Self::DATA) is compatible with [`CHECKSUM`](HasChecksum::CHECKSUM).
    #[inline]
    fn verify() -> bool {
        Self::verify_data(Self::DATA)
    }

    /// Reads [`DATA`](Self::DATA), making sure that the [`CHECKSUM`](HasChecksum::CHECKSUM) is
    /// compatible with [`verify`](Self::verify).
    #[inline]
    fn get() -> Option<&'static [u8]> {
        if Self::verify() {
            Some(Self::DATA)
        } else {
            None
        }
    }
}

/// Defines a data marker type loading its raw data and checksum from disk.
macro_rules! define_dat {
    ($name:tt, $doc:expr, $path:expr $(,)?) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name;

        impl $crate::HasChecksum for $name {
            const CHECKSUM: &'static [u8; 32] =
                include_bytes!(concat!(env!("OUT_DIR"), "/data/", $path, ".checksum"));
        }

        impl $crate::Get for $name {
            const DATA: &'static [u8] =
                include_bytes!(concat!(env!("OUT_DIR"), "/data/", $path, ".dat"));
        }
    };
}

/// Nonlocal Download-able Data
#[cfg(feature = "download")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "download")))]
pub trait Download: HasChecksum {
    /// Downlaods the data for this type from GitHub. This method automatically verifies the
    /// checksum while downloading. See [`github::download`] for more.
    fn download<P>(path: P) -> Result<()>
    where
        P: AsRef<Path>;

    /// Checks if the data for this type at the given `path` matches the [`CHECKSUM`] and if not,
    /// then it downloads it from GitHub. This method automatically verifies the checksum while
    /// downloading. See [`github::download`] for more.
    ///
    /// [`CHECKSUM`]: HasChecksum::CHECKSUM
    fn download_if_invalid<P>(path: P) -> Result<()>
    where
        P: AsRef<Path>,
    {
        match verify_file(&path, Self::CHECKSUM) {
            Ok(true) => Ok(()),
            _ => Self::download(path),
        }
    }
}

/// Defines a data marker type for download-required data from GitHub LFS and checksum from disk.
macro_rules! define_lfs {
    ($name:tt, $doc:expr, $path:expr $(,)?) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name;

        impl $crate::HasChecksum for $name {
            const CHECKSUM: &'static [u8; 32] =
                include_bytes!(concat!(env!("OUT_DIR"), "/data/", $path, ".checksum"));
        }

        #[cfg(feature = "download")]
        #[cfg_attr(doc_cfg, doc(cfg(feature = "download")))]
        impl $crate::Download for $name {
            #[inline]
            fn download<P>(path: P) -> $crate::Result<()>
            where
                P: AsRef<$crate::Path>,
            {
                $crate::github::download(
                    $crate::github::DEFAULT_BRANCH,
                    concat!("/data/", $path, ".lfs"),
                    path,
                    <Self as $crate::HasChecksum>::CHECKSUM,
                )
            }
        }
    };
}

/// Concrete Parameters for Manta Pay
pub mod pay {
    /// Testnet Data
    pub mod testnet {
        /// Parameters
        pub mod parameters {
            define_dat!(
                GroupGenerator,
                "Group Generator",
                "pay/testnet/parameters/group-generator",
            );
            define_dat!(
                UtxoCommitmentScheme,
                "UTXO Commitment Scheme Parameters",
                "pay/testnet/parameters/utxo-commitment-scheme",
            );
            define_dat!(
                IncomingBaseEncryptionScheme,
                "Incoming Base Encryption Scheme Parameters",
                "pay/testnet/parameters/incoming-base-encryption-scheme",
            );
            define_dat!(
                ViewingKeyDerivationFunction,
                "Viewing Key Derivation Function Parameters",
                "pay/testnet/parameters/viewing-key-derivation-function",
            );
            define_dat!(
                UtxoAccumulatorItemHash,
                "UTXO Accumulator Item Hash Parameters",
                "pay/testnet/parameters/utxo-accumulator-item-hash",
            );
            define_dat!(
                NullifierCommitmentScheme,
                "Nullifier Commitment Scheme Parameters",
                "pay/testnet/parameters/nullifier-commitment-scheme",
            );
            define_dat!(
                OutgoingBaseEncryptionScheme,
                "Outgoing Base Encryption Scheme Parameters",
                "pay/testnet/parameters/outgoing-base-encryption-scheme",
            );
            define_dat!(
                SchnorrHashFunction,
                "Schnorr Hash Function Parameters",
                "pay/testnet/parameters/schnorr-hash-function",
            );
            define_dat!(
                UtxoAccumulatorModel,
                "UTXO Accumulator Model Parameters",
                "pay/testnet/parameters/utxo-accumulator-model",
            );
        }

        /// Zero-Knowledge Proof System Proving Data
        pub mod proving {
            define_lfs!(
                ToPrivate,
                "ToPrivate Proving Context",
                "pay/testnet/proving/to-private",
            );
            define_lfs!(
                PrivateTransfer,
                "Private Transfer Proving Context",
                "pay/testnet/proving/private-transfer",
            );
            define_lfs!(
                ToPublic,
                "ToPublic Proving Context",
                "pay/testnet/proving/to-public",
            );
        }

        /// Zero-Knowledge Proof System Verifying Data
        pub mod verifying {
            define_dat!(
                ToPrivate,
                "ToPrivate Verifying Context",
                "pay/testnet/verifying/to-private"
            );
            define_dat!(
                PrivateTransfer,
                "Private Transfer Verifying Context",
                "pay/testnet/verifying/private-transfer"
            );
            define_dat!(
                ToPublic,
                "ToPublic Verifying Context",
                "pay/testnet/verifying/to-public"
            );
        }
    }
}

/// Testing Suite
#[cfg(test)]
mod test {
    use super::*;
    use anyhow::{anyhow, bail};
    use hex::FromHex;
    use std::{
        collections::HashMap,
        fs::{File, OpenOptions},
        io::{BufRead, BufReader, Read},
        path::PathBuf,
        println,
    };

    /// Checks if two files `lhs` and `rhs` have equal content.
    #[inline]
    fn equal_files(lhs: &mut File, rhs: &mut File) -> Result<bool> {
        let mut lhs_buffer = [0; 2048];
        let mut rhs_buffer = [0; 2048];
        loop {
            let lhs_len = lhs.read(&mut lhs_buffer)?;
            let rhs_len = rhs.read(&mut rhs_buffer)?;
            if (lhs_len != rhs_len) || (lhs_buffer[..lhs_len] != rhs_buffer[..rhs_len]) {
                return Ok(false);
            }
            if lhs_len == 0 {
                return Ok(true);
            }
        }
    }

    /// Checksum
    type Checksum = [u8; 32];

    /// Checksum Map
    type ChecksumMap = HashMap<PathBuf, Checksum>;

    /// Parses the checkfile at `path` producing a [`ChecksumMap`] for all the files in the data
    /// directory.
    #[inline]
    fn parse_checkfile<P>(path: P) -> Result<ChecksumMap>
    where
        P: AsRef<Path>,
    {
        let file = OpenOptions::new().read(true).open(path)?;
        let mut checksums = ChecksumMap::new();
        for line in BufReader::new(file).lines() {
            let line = line?;
            let mut iter = line.split("  ");
            match (iter.next(), iter.next(), iter.next()) {
                (Some(checksum), Some(path), None) => {
                    checksums.insert(path.into(), Checksum::from_hex(checksum)?);
                }
                _ => bail!("Invalid checkfile line: {:?}", line),
            }
        }
        Ok(checksums)
    }

    /// Gets the checksum from the `checksums` map for `path` returning an error if it was not found.
    #[inline]
    fn get_checksum<P>(checksums: &ChecksumMap, path: P) -> Result<&Checksum>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref();
        checksums
            .get(path)
            .ok_or_else(|| anyhow!("Unable to get checksum for path: {:?}", path))
    }

    /// Downloads all data from GitHub and checks if they are the same as the data known locally to
    /// this Rust crate.
    #[ignore] // NOTE: We use this so that CI doesn't run this test while still allowing developers to test.
    #[test]
    fn download_all_data() -> Result<()> {
        let current_branch = super::git::current_branch()?;
        let directory = tempfile::tempdir()?;
        println!("[INFO] Temporary Directory: {:?}", directory);
        let checksums = parse_checkfile("data.checkfile")?;
        let directory_path = directory.path();
        for file in walkdir::WalkDir::new("data") {
            let file = file?;
            let path = file.path();
            if !path.is_dir() {
                println!("[INFO] Checking path: {:?}", path);
                let target = directory_path.join(path);
                fs::create_dir_all(target.parent().unwrap())?;
                github::download(
                    &current_branch,
                    path.to_str().unwrap(),
                    &target,
                    get_checksum(&checksums, path)?,
                )?;
                assert!(
                    equal_files(&mut File::open(path)?, &mut File::open(&target)?)?,
                    "The files at {:?} and {:?} are not equal.",
                    path,
                    target
                );
            }
        }
        Ok(())
    }
}
