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

// FIXME: Change this to a "payload parsing" scheme, like serdes but ensure it gets encrypted
//        before saving and decrypted after loading. So we need something like EncryptedSerialize
//        and DecryptedDeserialize.

/// Filesystem Encrypted Loading
pub trait Load: Sized {
    /// Path Type
    type Path: ?Sized;

    /// Loading Key Type
    type LoadingKey: ?Sized;

    /// Load Error Type
    type Error;

    /// Loads an element of type `Self` from `path` unlocking it with the `loading_key`.
    fn load<P>(path: P, loading_key: &Self::LoadingKey) -> Result<Self, Self::Error>
    where
        P: AsRef<Self::Path>;
}

/// Filesystem Encrypted Loading with Extra Data
pub trait LoadWith<T>: Load {
    /// Loads an element of type `Self` along with additional data from `path` unlocking it with
    /// the `loading_key`.
    fn load_with<P>(path: P, loading_key: &Self::LoadingKey) -> Result<(Self, T), Self::Error>
    where
        P: AsRef<Self::Path>;
}

/// Filesystem Encrypted Saving
pub trait Save {
    /// Path Type
    type Path: ?Sized;

    /// Saving Key Type
    type SavingKey: ?Sized;

    /// Save Error Type
    type Error;

    /// Saves `self` to `path` locking it with the `saving_key`.
    fn save<P>(self, path: P, saving_key: &Self::SavingKey) -> Result<(), Self::Error>
    where
        P: AsRef<Self::Path>;
}

/// Filesystem Encrypted Saving with Extra Data
pub trait SaveWith<T>: Save {
    /// Saves `self` along with `additional` data to `path` locking it with the `saving_key`.
    fn save_with<P>(
        self,
        additional: T,
        path: P,
        saving_key: &Self::SavingKey,
    ) -> Result<(), Self::Error>
    where
        P: AsRef<Self::Path>;
}

/// Cocoon [`Load`] and [`Save`] Adapters
#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
pub mod cocoon {
    use super::*;
    use cocoon_crate::{Cocoon, Error as CocoonError};
    use core::{
        convert::{Infallible, TryInto},
        fmt, mem,
        ops::Drop,
    };
    use manta_util::from_variant_impl;
    use std::{fs::OpenOptions, io::Error as IoError, path::Path};
    use zeroize::Zeroize;

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

    /// Payload Parsing
    pub trait FromPayload: Sized {
        /// Parsing Error Type
        type Error;

        /// Converts the `payload` into an element of type `Self`.
        fn from_payload(payload: &[u8]) -> Result<Self, Self::Error>;
    }

    impl<const N: usize> FromPayload for [u8; N] {
        type Error = core::array::TryFromSliceError;

        #[inline]
        fn from_payload(payload: &[u8]) -> Result<Self, Self::Error> {
            (*payload).try_into()
        }
    }

    impl FromPayload for Vec<u8> {
        type Error = Infallible;

        #[inline]
        fn from_payload(payload: &[u8]) -> Result<Self, Self::Error> {
            Ok(payload.to_vec())
        }
    }

    /// Owned Payload Parsing
    pub trait FromPayloadOwned: Sized {
        /// Parsing Error Type
        type Error;

        /// Converts the `payload` into an element of type `Self`.
        fn from_payload_owned(payload: Vec<u8>) -> Result<Self, Self::Error>;
    }

    impl<const N: usize> FromPayloadOwned for [u8; N] {
        type Error = Vec<u8>;

        #[inline]
        fn from_payload_owned(payload: Vec<u8>) -> Result<Self, Self::Error> {
            payload.try_into()
        }
    }

    impl FromPayloadOwned for Vec<u8> {
        type Error = Infallible;

        #[inline]
        fn from_payload_owned(payload: Vec<u8>) -> Result<Self, Self::Error> {
            Ok(payload)
        }
    }

    /// Cocoon [`Load`] Adapter
    #[derive(Zeroize)]
    #[zeroize(drop)]
    pub struct Loader(Vec<u8>);

    impl Loader {
        /// Parses the loaded data into an element of type `T` by taking a referece to the payload.
        #[inline]
        pub fn parse<T>(self) -> Result<T, T::Error>
        where
            T: FromPayload,
        {
            T::from_payload(&self.0)
        }

        /// Parses the loaded data into an element of type `T` by taking ownership of the payload.
        #[inline]
        pub fn parse_owned<T>(mut self) -> Result<T, T::Error>
        where
            T: FromPayloadOwned,
        {
            T::from_payload_owned(mem::take(&mut self.0))
        }
    }

    impl Load for Loader {
        type Path = Path;

        type LoadingKey = [u8];

        type Error = Error;

        #[inline]
        fn load<P>(path: P, loading_key: &Self::LoadingKey) -> Result<Self, Self::Error>
        where
            P: AsRef<Self::Path>,
        {
            Ok(Self(
                Cocoon::new(loading_key).parse(&mut OpenOptions::new().read(true).open(path)?)?,
            ))
        }
    }

    /// Payload Extraction
    pub trait Payload {
        /// Extracts a byte vector payload from `self`.
        fn payload(&self) -> Vec<u8>;
    }

    impl<const N: usize> Payload for [u8; N] {
        #[inline]
        fn payload(&self) -> Vec<u8> {
            (*self).into()
        }
    }

    impl Payload for &[u8] {
        #[inline]
        fn payload(&self) -> Vec<u8> {
            self.to_vec()
        }
    }

    impl Payload for Vec<u8> {
        #[inline]
        fn payload(&self) -> Vec<u8> {
            self.clone()
        }
    }

    /// Cocoon [`Save`] Borrowed Data Adapter
    #[derive(Clone, Copy)]
    pub struct Saver<'t, T>(
        /// Payload Source
        pub &'t T,
    )
    where
        T: Payload;

    impl<'t, T> Save for Saver<'t, T>
    where
        T: Payload,
    {
        type Path = Path;

        type SavingKey = [u8];

        type Error = Error;

        #[inline]
        fn save<P>(self, path: P, saving_key: &Self::SavingKey) -> Result<(), Self::Error>
        where
            P: AsRef<Self::Path>,
        {
            save_payload(self.0, path, saving_key)
        }
    }

    /// Cocoon [`Save`] Owned Data Adapter
    #[derive(Zeroize)]
    pub struct SaverOwned<T>(T)
    where
        T: Payload + Zeroize;

    impl<T> Drop for SaverOwned<T>
    where
        T: Payload + Zeroize,
    {
        #[inline]
        fn drop(&mut self) {
            self.0.zeroize();
        }
    }

    impl<T> Save for SaverOwned<T>
    where
        T: Payload + Zeroize,
    {
        type Path = Path;

        type SavingKey = [u8];

        type Error = Error;

        #[inline]
        fn save<P>(mut self, path: P, saving_key: &Self::SavingKey) -> Result<(), Self::Error>
        where
            P: AsRef<Self::Path>,
        {
            save_payload(&self.0, path, saving_key)?;
            self.0.zeroize();
            Ok(())
        }
    }

    /// Saves the payload generated from `source` to `path` using the `saving_key`.
    #[inline]
    fn save_payload<T, P>(source: &T, path: P, saving_key: &[u8]) -> Result<(), Error>
    where
        T: Payload,
        P: AsRef<Path>,
    {
        // NOTE: We want to check that the file can be opened and that we can write to it
        //       before we extract the sensitive payload out of `self`.
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)?;
        Ok(Cocoon::new(saving_key).dump(source.payload(), &mut file)?)
    }

    /// Testing Suite
    #[cfg(test)]
    mod test {
        use super::*;
        use rand::{thread_rng, RngCore};

        /// Tests loading some saved data using the [`Saver`] and [`Loader`] adapters.
        #[test]
        fn load_saved() {
            let dir = tempfile::tempdir().expect("Temporary directory should have been created.");
            let path = dir.path().join("load_saved.data");
            let mut rng = thread_rng();

            // Generate random password to save to and load from the file system.
            let mut password = [0; 256];
            rng.fill_bytes(&mut password);

            // Generate random payload.
            let mut expected = [0; 2048];
            rng.fill_bytes(&mut expected);

            // Save the target payload to the file system.
            Saver(&expected)
                .save(&path, &password)
                .expect("Payload should have been saved.");

            // Load the payload from the file system.
            let observed = Loader::load(&path, &password)
                .expect("Payload should have been loaded.")
                .parse::<[u8; 2048]>()
                .expect("Payload should have been parsed properly.");

            // Check that the payload matches.
            assert_eq!(expected, observed);

            // Close the testing directory.
            dir.close()
                .expect("Temporary directory should have closed.");
        }
    }
}
