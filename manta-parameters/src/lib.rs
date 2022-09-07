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

#[cfg(feature = "download")]
use {anyhow::Result, std::path::Path};

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
    pub const DEFAULT_BRANCH: &str = "main";

    /// Returns the Git-LFS URL for GitHub content at the given `branch` and `data_path`.
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
pub fn verify_file<P>(path: P, checksum: &[u8; 32]) -> std::io::Result<bool>
where
    P: AsRef<std::path::Path>,
{
    Ok(verify(&std::fs::read(path)?, checksum))
}

/// Defines a data marker type loading its raw data and checksum from disk.
macro_rules! define_dat {
    ($name:tt, $doc:expr, $path:expr $(,)?) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name;

        impl $name {
            #[doc = $doc]
            #[doc = "Data Bytes"]
            pub const DATA: &'static [u8] = include_bytes!(concat!(env!("OUT_DIR"), $path, ".dat"));

            #[doc = $doc]
            #[doc = "Data Checksum"]
            pub const CHECKSUM: &'static [u8; 32] =
                include_bytes!(concat!(env!("OUT_DIR"), $path, ".checksum"));

            /// Verifies that [`Self::DATA`] is consistent against [`Self::CHECKSUM`].
            #[inline]
            pub fn verify() -> bool {
                crate::verify(Self::DATA, Self::CHECKSUM)
            }

            /// Gets the underlying binary data after verifying against [`Self::CHECKSUM`].
            #[inline]
            pub fn get() -> Option<&'static [u8]> {
                if Self::verify() {
                    Some(Self::DATA)
                } else {
                    None
                }
            }
        }
    };
}

/// Defines a data marker type for download-required data from GitHub LFS and checksum from disk.
macro_rules! define_lfs {
    ($name:tt, $doc:expr, $path:expr $(,)?) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name;

        impl $name {
            #[doc = $doc]
            #[doc = "Data Checksum"]
            pub const CHECKSUM: &'static [u8; 32] =
                include_bytes!(concat!(env!("OUT_DIR"), $path, ".checksum"));

            #[doc = "Downloads the data for the"]
            #[doc = $doc]
            #[doc = r"from GitHub. This method automatically verifies the checksum when downloading.
                      See [`github::download`](crate::github::download) for more."]
            #[cfg(feature = "download")]
            #[cfg_attr(doc_cfg, doc(cfg(feature = "download")))]
            #[inline]
            pub fn download<P>(path: P) -> anyhow::Result<()>
            where
                P: AsRef<std::path::Path>,
            {
                $crate::github::download(
                    $crate::github::DEFAULT_BRANCH,
                    concat!($path, ".lfs"),
                    path,
                    Self::CHECKSUM,
                )
            }

            #[doc = "Checks if the data for the"]
            #[doc = $doc]
            #[doc = r"matches the checksum and if not downloads it from GitHub. This method
                      automatically verifies the checksum when downloading.
                      See [`github::download`](crate::github::download) for more."]
            #[cfg(feature = "download")]
            #[cfg_attr(doc_cfg, doc(cfg(feature = "download")))]
            #[inline]
            pub fn download_if_invalid<P>(path: P) -> anyhow::Result<()>
            where
                P: AsRef<std::path::Path>,
            {
                match $crate::verify_file(&path, Self::CHECKSUM) {
                    Ok(true) => Ok(()),
                    _ => Self::download(path),
                }
            }
        }
    };
}

/// Perpetual Powers of Tau Accumulators
pub mod ppot {
    define_lfs!(
        Round72Powers19,
        "Accumulator with 1 << 19 powers, Bn",
        "/data/ppot/round72powers19",
    );
}

/// Concrete Parameters for Manta Pay
pub mod pay {
    /// Testnet Data
    pub mod testnet {
        /// Parameters
        pub mod parameters {
            define_dat!(
                NoteEncryptionScheme,
                "Note Encryption Scheme Parameters",
                "/data/pay/testnet/parameters/note-encryption-scheme",
            );
            define_dat!(
                UtxoCommitmentScheme,
                "UTXO Commitment Scheme Parameters",
                "/data/pay/testnet/parameters/utxo-commitment-scheme",
            );
            define_dat!(
                VoidNumberCommitmentScheme,
                "Void Number Commitment Scheme Parameters",
                "/data/pay/testnet/parameters/void-number-commitment-scheme",
            );
            define_dat!(
                UtxoAccumulatorModel,
                "UTXO Accumulator Model",
                "/data/pay/testnet/parameters/utxo-accumulator-model",
            );
        }

        /// Zero-Knowledge Proof System Proving Data
        pub mod proving {
            define_lfs!(
                Mint,
                "Mint Proving Context",
                "/data/pay/testnet/proving/mint",
            );
            define_lfs!(
                PrivateTransfer,
                "Private Transfer Proving Context",
                "/data/pay/testnet/proving/private-transfer",
            );
            define_lfs!(
                Reclaim,
                "Reclaim Proving Context",
                "/data/pay/testnet/proving/reclaim",
            );
        }

        /// Zero-Knowledge Proof System Verifying Data
        pub mod verifying {
            define_dat!(
                Mint,
                "Mint Verifying Context",
                "/data/pay/testnet/verifying/mint"
            );
            define_dat!(
                PrivateTransfer,
                "Private Transfer Verifying Context",
                "/data/pay/testnet/verifying/private-transfer"
            );
            define_dat!(
                Reclaim,
                "Reclaim Verifying Context",
                "/data/pay/testnet/verifying/reclaim"
            );
        }
    }
}

/// Testing Suite
#[cfg(test)]
mod test {
    use super::*;
    use anyhow::{anyhow, bail, Result};
    use git2::Repository;
    use hex::FromHex;
    use std::{
        borrow::ToOwned,
        collections::HashMap,
        fs::{self, File, OpenOptions},
        io::{BufRead, BufReader, Read},
        path::PathBuf,
        println,
        string::String,
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
    fn get_checksum<P>(checksums: &ChecksumMap, path: P) -> Result<Checksum>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref();
        checksums
            .get(path)
            .ok_or_else(|| anyhow!("Unable to get checksum for path: {:?}", path))
            .map(move |c| *c)
    }

    /// Returns the name of the current branch of this crate as a Git repository.
    #[inline]
    fn get_current_branch() -> Result<String> {
        let repo = Repository::discover(".")?;
        let head = repo.head()?;
        if head.is_branch() {
            Ok(head
                .shorthand()
                .ok_or_else(|| anyhow!("Unable to generate shorthand for branch name."))?
                .to_owned())
        } else {
            bail!("Current Git HEAD reference is not at a branch.")
        }
    }

    /// Downloads all data from GitHub and checks if they are the same as the data known locally to
    /// this Rust crate.
    #[ignore] // NOTE: Adds `ignore` such that CI does NOT run this test while still allowing developers to test.
    #[test]
    fn download_all_data() -> Result<()> {
        let current_branch = get_current_branch()?;
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
                    &get_checksum(&checksums, path)?,
                )?;
                assert!(equal_files(
                    &mut File::open(path)?,
                    &mut File::open(target)?
                )?);
            }
        }
        Ok(())
    }
}
