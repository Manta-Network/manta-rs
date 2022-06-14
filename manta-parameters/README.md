# manta-parameters

This is a data library that represents the parts of the Manta protocols which depend on real-world data or concrete public parameters. 

- [`data`](data)
- [`data.checkfile`](data.checkfile)
- [`src`](src/lib.rs)
- [`build.rs`](build.rs)

The data library is comprised of a bunch of data files, either as raw binary data or JSON, and an accompanying Rust library which has access to these data files at compile-time. See the [`build.rs`](./build.rs) file for more on how those data files are parsed into Rust. Some data files are too large to package into a Rust library and so are left as stand-alone files. For these files, a [`BLAKE3`](https://github.com/BLAKE3-team/BLAKE3) digest is offered in the Rust library as a checksum.

## Checksums

For checksums we use [`BLAKE3`](https://github.com/BLAKE3-team/BLAKE3). Install `b3sum` with

```sh
cargo install b3sum
```

to compute the checksums for yourself. The checksums for the [`data`](./data/) directory are stored in [`data.checkfile`](./data.checkfile) which is created by the following command:

```sh
./generate_checkfile.sh
```

To check that the checkfile is up-to-date use the following command:

```sh
b3sum --check data.checkfile
```

## Validating the Dataset

To check that the dataset in the [`data`](./data) directory matches the data exported by the `manta-parameters` crate, run 

```sh
cargo test --release -- --ignored --nocapture
```

which will download all the files on the GitHub source repository for the current branch and check that all the files match the known checksums.
