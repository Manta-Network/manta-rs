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

//! Proving Context Caching

use crate::config::{MultiProvingContext, ProvingContext};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use async_std::{
    io,
    path::{Path, PathBuf},
    task,
};
use core::marker::PhantomData;
use manta_util::{cache::CachedResource, future::LocalBoxFuture};
use std::fs::{File, OpenOptions};

/// Caching Error
#[derive(Debug)]
pub enum Error {
    /// Serialization Error
    Serialization(SerializationError),

    /// I/O Error
    Io(io::Error),
}

impl From<SerializationError> for Error {
    #[inline]
    fn from(err: SerializationError) -> Self {
        Self::Serialization(err)
    }
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
    async fn read_context<P>(path: P) -> Result<ProvingContext, Error>
    where
        P: 'static + AsRef<Path> + Send,
    {
        Ok(task::spawn_blocking(move || {
            File::open(path.as_ref())
                .map_err(Error::Io)
                .and_then(move |f| ProvingContext::deserialize(f).map_err(Error::Serialization))
        })
        .await?)
    }

    /// Writes `context` to `path`.
    #[inline]
    async fn write_context<P>(path: P, context: ProvingContext) -> Result<(), Error>
    where
        P: 'static + AsRef<Path> + Send,
    {
        Ok(task::spawn_blocking(move || {
            OpenOptions::new()
                .write(true)
                .create(true)
                .open(path.as_ref())
                .map_err(Error::Io)
                .and_then(move |f| context.serialize(f).map_err(Error::Serialization))
        })
        .await?)
    }

    /// Saves the `context` to the on-disk directory. This method _does not_ write `context` into
    /// the cache.
    #[inline]
    pub async fn save(&self, context: MultiProvingContext) -> Result<(), Error> {
        let mint_path = self.directory.join("mint.pk");
        let private_transfer_path = self.directory.join("private-transfer.pk");
        let reclaim_path = self.directory.join("reclaim.pk");
        Self::write_context(mint_path, context.mint).await?;
        Self::write_context(private_transfer_path, context.private_transfer).await?;
        Self::write_context(reclaim_path, context.reclaim).await?;
        Ok(())
    }
}

impl CachedResource<MultiProvingContext> for OnDiskMultiProvingContext {
    type ReadingKey = ReadingKey;
    type Error = Error;

    #[inline]
    fn aquire(&mut self) -> LocalBoxFuture<Result<Self::ReadingKey, Self::Error>> {
        Box::pin(async {
            let mint_path = self.directory.join("mint.pk");
            let private_transfer_path = self.directory.join("private-transfer.pk");
            let reclaim_path = self.directory.join("reclaim.pk");
            self.context = Some(MultiProvingContext {
                mint: Self::read_context(mint_path).await?,
                private_transfer: Self::read_context(private_transfer_path).await?,
                reclaim: Self::read_context(reclaim_path).await?,
            });
            Ok(ReadingKey::new())
        })
    }

    #[inline]
    fn read(&self, reading_key: Self::ReadingKey) -> &MultiProvingContext {
        // SAFETY: Since `reading_key` is only given out when we know that `context` is `Some`,
        //         we can safely `unwrap` here.
        let _ = reading_key;
        self.context.as_ref().unwrap()
    }

    #[inline]
    fn release(&mut self) -> LocalBoxFuture {
        Box::pin(async {
            self.context.take();
        })
    }
}

impl Clone for OnDiskMultiProvingContext {
    #[inline]
    fn clone(&self) -> Self {
        Self::new(&self.directory)
    }
}
