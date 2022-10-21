use manta_trusted_setup::groth16::ppot::kzg::{decompression::decompress_response, PpotCeremony};
use manta_util::into_array_unchecked;
use memmap::{Mmap, MmapOptions};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
};

// on remote, run with
// nohup cargo run --release --bin decompress_test --all-features &> ./decompress_test.log &

fn main() {
    let source_path = PathBuf::from("/home/mobula/ppot-verifier/response_0058");
    let target_path = source_path
        .parent()
        .expect("source path has no parent")
        .join("response_0058_decompressed");
    let hash_path = PathBuf::from("/home/mobula/ppot-verifier/response_0058_hash");

    let file = OpenOptions::new()
        .read(true)
        .open(source_path)
        .expect("Cannot open response file at path");

    let mmap = unsafe {
        MmapOptions::new()
            .map(&file)
            .expect("Unable to create memory map for input")
    };
    let mut hash = [0u8; 64];
    let mut hash_file = OpenOptions::new()
        .read(true)
        .open(hash_path)
        .expect("Cannot open hash file at path");
    assert_eq!(
        hash_file
            .read(&mut hash[..])
            .expect("Failed to read hash from file"),
        64
    );

    // decompress_response::<PpotCeremony>(&mmap, hash, target_path.clone())
    //     .expect("Error decompressing");

    // // Then hash the result
    let new_hash_path = PathBuf::from("/home/mobula/ppot-verifier/response_0058_decompressed_hash");
    let mut new_hash_file = OpenOptions::new()
        .write(true)
        .read(true)
        .create(true)
        .truncate(true)
        .open(new_hash_path)
        .expect("Unable to open hash file");
    // hash_to(&mut new_hash_file, target_path).expect("Hashing error");

    // Check the result:
    let mut new_hash = [0u8; 64];
    assert_eq!(
        new_hash_file
            .read(&mut new_hash)
            .expect("Failed to read new hash"),
        64
    );
    let mut old_hash = [0u8; 64];
    let old_hash_path = PathBuf::from("/home/mobula/ppot-verifier/challenge_0058_hash");
    let mut old_hash_file = OpenOptions::new()
        .read(true)
        .open(old_hash_path)
        .expect("Unable to open hash file");
    assert_eq!(
        old_hash_file
            .read(&mut old_hash)
            .expect("Failed to read new hash"),
        64
    );
    println!("Computed a challenge file with hash {:?}", new_hash);
    println!("The resulting hashes match: {}", old_hash == new_hash);
}

use blake2::{Blake2b, Digest};

/// Computes the hash of a potentially large file,
/// such as PPoT `challenge` or `response` files.
pub fn calculate_hash(input_map: &Mmap) -> [u8; 64] {
    let chunk_size = 1 << 30; // read by 1GB from map
    let mut hasher = Blake2b::default();

    for (counter, chunk) in input_map.chunks(chunk_size).enumerate() {
        hasher.update(chunk);
        println!("Have hashed {:?} GB of the file", counter);
    }
    into_array_unchecked(hasher.finalize())
}

/// Hashes the file at `path` and saves the hash to `file`.
fn hash_to(file: &mut File, path: PathBuf) -> Result<(), std::io::Error> {
    // Make memory map from `path`
    let reader = OpenOptions::new()
        .read(true)
        .open(path)
        .expect("unable open file in this directory");
    // Make a memory map
    let reader = unsafe {
        MmapOptions::new()
            .map(&reader)
            .expect("unable to create a memory map for input")
    };
    let hash = calculate_hash(&reader);
    file.write_all(&hash)?;
    Ok(())
}
