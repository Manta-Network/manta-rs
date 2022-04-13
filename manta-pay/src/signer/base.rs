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

//! Manta Pay Signer Configuration

use crate::{
    config::{Bls12_381_Edwards, Config, MerkleTreeConfiguration, MultiProvingContext, SecretKey},
    crypto::constraint::arkworks::Fp,
    key::{CoinType, KeySecret, Testnet, TestnetKeySecret},
};
use ark_ec::ProjectiveCurve;
use ark_ff::PrimeField;
use core::marker::PhantomData;
use manta_accounting::{
    asset::HashAssetMap,
    key::{self, HierarchicalKeyDerivationScheme},
    wallet::{self, signer::AssetMapKey},
};
use manta_crypto::{key::KeyDerivationFunction, merkle_tree};

#[cfg(feature = "serde")]
use manta_util::serde::{Deserialize, Serialize};

/// Hierarchical Key Derivation Function
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HierarchicalKeyDerivationFunction<C = Testnet>(PhantomData<C>)
where
    C: CoinType;

impl<C> KeyDerivationFunction for HierarchicalKeyDerivationFunction<C>
where
    C: CoinType,
{
    type Key = <KeySecret<C> as HierarchicalKeyDerivationScheme>::SecretKey;
    type Output = SecretKey;

    #[inline]
    fn derive_in(&self, key: &Self::Key, _: &mut ()) -> Self::Output {
        // FIXME: Check that this conversion is logical/safe.
        let bytes: [u8; 32] = key
            .private_key()
            .to_bytes()
            .try_into()
            .expect("The secret key has 32 bytes.");
        Fp(<Bls12_381_Edwards as ProjectiveCurve>::ScalarField::from_le_bytes_mod_order(&bytes))
    }
}

/// Signer UTXO Accumulator
pub type UtxoAccumulator = merkle_tree::forest::TreeArrayMerkleForest<
    MerkleTreeConfiguration,
    merkle_tree::fork::ForkedTree<
        MerkleTreeConfiguration,
        merkle_tree::full::Full<MerkleTreeConfiguration>,
    >,
    { MerkleTreeConfiguration::FOREST_WIDTH },
>;

/// Proving Context Cache
pub mod cache {
    use super::*;
    use crate::config::ProvingContext;
    use core::marker::PhantomData;
    use manta_util::{
        cache::CachedResource,
        codec::{Decode, Encode, IoReader, IoWriter},
    };
    use std::{
        fs::{File, OpenOptions},
        io,
        path::{Path, PathBuf},
    };

    /// Caching Error
    #[derive(Debug)]
    pub enum Error {
        /// Encoding Error
        Encode,

        /// Decoding Error
        Decode,

        /// I/O Error
        Io(io::Error),
    }

    impl From<io::Error> for Error {
        #[inline]
        fn from(err: io::Error) -> Self {
            Self::Io(err)
        }
    }

    /// Cache Reading Key
    pub struct ReadingKey(PhantomData<()>);

    impl ReadingKey {
        #[inline]
        fn new() -> Self {
            Self(PhantomData)
        }
    }

    /// On-Disk Multi-Proving Context
    pub struct OnDiskMultiProvingContext {
        /// Source Directory
        directory: PathBuf,

        /// Current Cached Context
        context: Option<MultiProvingContext>,
    }

    impl OnDiskMultiProvingContext {
        /// Builds a new [`OnDiskMultiProvingContext`] setting the source directory to `directory`.
        ///
        /// To save the cache data to disk, use [`save`](Self::save).
        #[inline]
        pub fn new<P>(directory: P) -> Self
        where
            P: AsRef<Path>,
        {
            Self {
                directory: directory.as_ref().to_owned(),
                context: None,
            }
        }

        /// Returns the directory where `self` stores the [`MultiProvingContext`].
        #[inline]
        pub fn directory(&self) -> &Path {
            &self.directory
        }

        /// Reads a single [`ProvingContext`] from `path`.
        #[inline]
        fn read_context<P>(path: P) -> Result<ProvingContext, Error>
        where
            P: AsRef<Path>,
        {
            File::open(path.as_ref())
                .map_err(Error::Io)
                .and_then(move |f| ProvingContext::decode(IoReader(f)).map_err(|_| Error::Decode))
        }

        /// Writes `context` to `path`.
        #[inline]
        fn write_context<P>(path: P, context: ProvingContext) -> Result<(), Error>
        where
            P: AsRef<Path>,
        {
            OpenOptions::new()
                .write(true)
                .create(true)
                .open(path.as_ref())
                .map_err(Error::Io)
                .and_then(move |f| context.encode(IoWriter(f)).map_err(|_| Error::Encode))
        }

        /// Saves the `context` to the on-disk directory. This method _does not_ write `context` into
        /// the cache.
        #[inline]
        pub fn save(&self, context: MultiProvingContext) -> Result<(), Error> {
            Self::write_context(self.directory.join("mint.pk"), context.mint)?;
            Self::write_context(
                self.directory.join("private-transfer.pk"),
                context.private_transfer,
            )?;
            Self::write_context(self.directory.join("reclaim.pk"), context.reclaim)?;
            Ok(())
        }
    }

    impl CachedResource<MultiProvingContext> for OnDiskMultiProvingContext {
        type ReadingKey = ReadingKey;
        type Error = Error;

        #[inline]
        fn aquire(&mut self) -> Result<Self::ReadingKey, Self::Error> {
            self.context = Some(MultiProvingContext {
                mint: Self::read_context(self.directory.join("mint.pk"))?,
                private_transfer: Self::read_context(self.directory.join("private-transfer.pk"))?,
                reclaim: Self::read_context(self.directory.join("reclaim.pk"))?,
            });
            Ok(ReadingKey::new())
        }

        #[inline]
        fn read(&self, reading_key: Self::ReadingKey) -> &MultiProvingContext {
            // SAFETY: Since `reading_key` is only given out when we know that `context` is `Some`,
            //         we can safely `unwrap` here.
            let _ = reading_key;
            self.context.as_ref().unwrap()
        }

        #[inline]
        fn release(&mut self) {
            self.context.take();
        }
    }

    impl Clone for OnDiskMultiProvingContext {
        #[inline]
        fn clone(&self) -> Self {
            Self::new(&self.directory)
        }
    }
}

impl wallet::signer::Configuration for Config {
    type HierarchicalKeyDerivationScheme =
        key::Map<TestnetKeySecret, HierarchicalKeyDerivationFunction>;
    type UtxoAccumulator = UtxoAccumulator;
    type AssetMap = HashAssetMap<AssetMapKey<Self>>;
    type ProvingContextCache = MultiProvingContext;
    type Rng = rand_chacha::ChaCha20Rng;
}

/// Signer Parameters Type
pub type SignerParameters = wallet::signer::SignerParameters<Config>;

/// Signer State Type
pub type SignerState = wallet::signer::SignerState<Config>;

/// Signer Base Type
pub type Signer = wallet::signer::Signer<Config>;
