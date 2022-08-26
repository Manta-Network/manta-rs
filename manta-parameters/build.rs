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

//! Manta Parameters Build Script

use anyhow::{anyhow, bail, ensure, Result};
use hex::FromHex;
use std::{
    collections::{HashMap, HashSet},
    env,
    fs::{self, OpenOptions},
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};
use walkdir::{DirEntry, WalkDir};

/// Returns the parent of `path` which should exist relative to `OUT_DIR`.
#[inline]
fn parent(path: &Path) -> Result<&Path> {
    path.parent()
        .ok_or_else(|| anyhow!("The parent should be in the subtree of the `OUT_DIR` directory."))
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

/// Writes the `checksum` to `path` returning an error if the write failed.
#[inline]
fn write_checksum<P>(path: P, checksum: Checksum) -> Result<()>
where
    P: AsRef<Path>,
{
    let path = path.as_ref();
    fs::create_dir_all(parent(path)?)?;
    Ok(fs::write(path.with_extension("checksum"), checksum)?)
}

/// Compiles a raw binary file by checking its BLAKE3 checksum with the `checksums` map and copying
/// the data and checksum to the `out_dir`.
#[inline]
fn compile_dat(source: &Path, out_dir: &Path, checksums: &ChecksumMap) -> Result<()> {
    let checksum = get_checksum(checksums, source)?;
    let data = fs::read(source)?;
    let found_checksum = blake3::hash(&data);
    ensure!(
        found_checksum == checksum,
        "Checksum did not match for {:?}. Expected: {:?}, Found: {:?}. Data: {:?}",
        source,
        hex::encode(checksum),
        found_checksum,
        data,
    );
    let target = out_dir.join(source);
    write_checksum(&target, checksum)?;
    fs::copy(source, target)?;
    Ok(())
}

/// Compiles a Git LFS file by writing its checksum to the `out_dir`.
#[inline]
fn compile_lfs(source: &Path, out_dir: &Path, checksums: &ChecksumMap) -> Result<()> {
    write_checksum(out_dir.join(source), get_checksum(checksums, source)?)
}

/// Checks that the filename in `entry` returns `true` when running `predicate`.
#[inline]
fn matches_predicate<P>(entry: &DirEntry, predicate: P) -> bool
where
    P: FnOnce(&str) -> bool,
{
    entry.file_name().to_str().map(predicate).unwrap_or(false)
}

/// Returns `true` when `entry` points to a hidden file.
#[inline]
fn is_hidden(entry: &DirEntry) -> bool {
    matches_predicate(entry, |s| s.starts_with('.'))
}

/// Ignore Table
type IgnoreTable = HashSet<PathBuf>;

/// Builds the [`IgnoreTable`] for paths under `root`.
#[inline]
fn build_ignore_table<P>(root: P) -> Result<IgnoreTable>
where
    P: AsRef<Path>,
{
    let mut ignore_table = IgnoreTable::new();
    for entry in WalkDir::new(root) {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() && path.file_name().expect("") == ".gitignore" {
            ignore_table.insert(
                path.parent()
                    .expect("The parent directory should exist.")
                    .to_owned(),
            );
        }
    }
    Ok(ignore_table)
}

/// Returns `true` if `path` is ignored by the corresponding entry in the `ignore_table`.
#[inline]
fn should_ignore(path: &Path, ignore_table: &IgnoreTable) -> Result<bool> {
    let parent = path.parent().expect("The parent directory should exist.");
    if ignore_table.contains(parent) {
        gitignore::File::new(&parent.join(".gitignore"))
            .map_err(|e| anyhow!("Unable to parse `.gitignore` file: {:?}", e))?
            .is_excluded(path)
            .map_err(|e| anyhow!("Error while ignoring the file: {}: {:?}", path.display(), e))
    } else {
        Ok(false)
    }
}

/// Loads all the files from `data` into the `OUT_DIR` directory for inclusion into the library.
#[inline]
fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=data");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let checksums = parse_checkfile("data.checkfile")?;
    let ignore_table = build_ignore_table("data")?;
    for entry in WalkDir::new("data")
        .into_iter()
        .filter_entry(|e| !is_hidden(e))
    {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() && !should_ignore(path, &ignore_table)? {
            match path.extension() {
                Some(extension) => match extension.to_str() {
                    Some("dat") => compile_dat(path, &out_dir, &checksums)?,
                    Some("lfs") => compile_lfs(path, &out_dir, &checksums)?,
                    Some("md") => {}
                    _ => bail!("Unsupported data file extension: {}.", path.display()),
                },
                _ => bail!("All data files must have an extension: {}.", path.display()),
            }
        }
    }
    Ok(())
}
