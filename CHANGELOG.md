# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added

### Changed
- [\#293](https://github.com/Manta-Network/manta-rs/pull/293) Add decimals argument to AssetMetadata display

### Deprecated

### Removed

### Fixed

### Security

## [0.5.8] - 2022-12-03
### Added
- [\#286](https://github.com/Manta-Network/manta-rs/pull/286) MantaPay v1.0.0

### Changed
- [\#283](https://github.com/Manta-Network/manta-rs/pull/283) Upgrade asset system.
- [\#284](https://github.com/Manta-Network/manta-rs/pull/284) Moved `R1CS` implementation to `manta-crypto` 
- [\#282](https://github.com/Manta-Network/manta-rs/pull/282) Upgrade key system.

## [0.5.7] - 2022-11-04
### Added
- [\#262](https://github.com/Manta-Network/manta-rs/pull/262) Added exporting seed phrase and multiple networks support for signer.
- [#276](https://github.com/Manta-Network/manta-rs/pull/276) New circuits part 1: manta-crypto abstractions

### Changed
- [\#274](https://github.com/Manta-Network/manta-rs/pull/274) Update TS client installer script to use release 0.5.6.

## [0.5.6] - 2022-10-27
### Added
- [\#267](https://github.com/Manta-Network/manta-rs/pull/267) Add trusted setup client downloader

### Changed
- [\#268](https://github.com/Manta-Network/manta-rs/pull/268) Trusted Setup Client v2

## [0.5.5] - 2022-10-09
### Added
- [\#264](https://github.com/Manta-Network/manta-rs/pull/238) Add trusted setup client binary
- [\#238](https://github.com/Manta-Network/manta-rs/pull/238) Add trusted setup ceremony primitives for server and client
- [\#237](https://github.com/Manta-Network/manta-rs/pull/237) Public input fuzzing tests for transfer protocol
- [\#215](https://github.com/Manta-Network/manta-rs/pull/215) Add windowed multiplication algorithm for groups
- [\#213](https://github.com/Manta-Network/manta-rs/pull/197) Add Ceremony Utilities
- [\#206](https://github.com/Manta-Network/manta-rs/pull/206) Move Poseidon sage script to test the hardcoded round constant values
- [\#197](https://github.com/Manta-Network/manta-rs/pull/197) Add ECLAIR utilities for next circuit upgrade
- [\#196](https://github.com/Manta-Network/manta-rs/pull/172) Add fixed base scalar multiplication using precomputed bases
- [\#193](https://github.com/Manta-Network/manta-rs/pull/193) Add Bn254 curve backend for Groth16 trusted setup
- [\#172](https://github.com/Manta-Network/manta-rs/pull/172) Add abstract Phase 2 for Groth16 trusted setup 

### Changed
- [\#247](https://github.com/Manta-Network/manta-rs/pull/247) Moved BLS12-381 and BN254 curves (and Edwards counterparts) to `manta-crypto`
- [\#236](https://github.com/Manta-Network/manta-rs/pull/236) Moved `RatioProof` from `manta-trusted-setup` to `manta-crypto`
- [\#180](https://github.com/Manta-Network/manta-rs/pull/180) Start moving to new `arkworks` backend for `manta-crypto`
- [\#191](https://github.com/Manta-Network/manta-rs/pull/191) Move HTTP Utilities to `manta-util`

### Fixed
- [\#212](https://github.com/Manta-Network/manta-rs/pull/212) Reduce the number of checks when computing `is_identity` and `is_symmetric` on matrices
- [\#220](https://github.com/Manta-Network/manta-rs/pull/220) Add support for `.gitignore` and `README.md` to `manta-parameters`

## [0.5.4] - 2022-07-28
### Added
- [\#131](https://github.com/Manta-Network/manta-rs/pull/131) Add abstract Phase 1 for Groth16 trusted setup
- [\#176](https://github.com/Manta-Network/manta-rs/pull/176) Add ECLAIR utilities for the new circuits
- [\#175](https://github.com/Manta-Network/manta-rs/pull/175) Add more documentation around `cargo-hakari`

## [0.5.3] - 2022-07-08
### Added
- [\#141](https://github.com/Manta-Network/manta-rs/pull/141) Add `U128` type and range assertion trait to ECLAIR
- [\#144](https://github.com/Manta-Network/manta-rs/pull/144) Add new release PR template for future releases
- [\#145](https://github.com/Manta-Network/manta-rs/pull/145) Add `cargo-hakari` and `cargo-nextest` to speed up CI pipeline
- [\#149](https://github.com/Manta-Network/manta-rs/pull/149) Add poseidon encryption implementation
- [\#147](https://github.com/Manta-Network/manta-rs/pull/147) Add benchmarks for Arkworks elliptic curve operations
- [\#163](https://github.com/Manta-Network/manta-rs/pull/163) Add `cargo-sort` to the CI pipeline for formatting `Cargo.toml` files

### Changed
- [\#152](https://github.com/Manta-Network/manta-rs/pull/152) Make `format` and `docs` as prerequisites for the rest of the CI pipeline

### Fixed
- [\#151](https://github.com/Manta-Network/manta-rs/pull/151) Split the `Sender` and `Receiver` logic out of the `transfer` module into new `sender` and `receiver` modules

## [0.5.2] - 2022-06-28
### Added
- [\#126](https://github.com/Manta-Network/manta-rs/pull/126) Add ECLAIR v0 scaffolding and deprecate old compiler patterns
- [\#128](https://github.com/Manta-Network/manta-rs/pull/128) Add more parameter loading utilities
- [\#130](https://github.com/Manta-Network/manta-rs/pull/130) Add the sage script and the hardcoded tests for the security of mds matrix
- [\#133](https://github.com/Manta-Network/manta-rs/pull/133) Add public input genenration to `Transfer`
- [\#136](https://github.com/Manta-Network/manta-rs/pull/136) Add pseudorandom permutation and sponge abstractions
- [\#134](https://github.com/Manta-Network/manta-rs/pull/134) Add signature scheme API and Schnorr signature implementaion
- [\#137](https://github.com/Manta-Network/manta-rs/pull/137) Add new encryption scheme APIs and duplex-sponge encryption

### Changed
- [\#132](https://github.com/Manta-Network/manta-rs/pull/132) Simplify algebra APIs and removing ECC-specific design
- [\#127](https://github.com/Manta-Network/manta-rs/pull/127) Remove the `CryptoRng` requirement from the `Sample` API

### Fixed
- [\#129](https://github.com/Manta-Network/manta-rs/pull/129) Reduce cost of signer key-search algorithm by adding dynamic pre-computation table

## [0.5.1] - 2022-06-17
### Added
- [\#90](https://github.com/Manta-Network/manta-rs/pull/90) Add Binary Compatibility Test for `manta-pay`
- [\#102](https://github.com/Manta-Network/manta-rs/pull/102) Add concrete parameters to `manta-parameters`
- [\#106](https://github.com/Manta-Network/manta-rs/pull/106) Add `load_parameter` as a library function

### Fixed
- [\#103](https://github.com/Manta-Network/manta-rs/pull/103) Remove download dependency from `manta-benchmark`

## [0.5.0] - 2022-06-09
### Added
- [\#93](https://github.com/Manta-Network/manta-rs/pull/93) Add Changelog and Update Contributing Guidelines

### Changed
- [\#86](https://github.com/Manta-Network/manta-rs/pull/86) Allow Wallet to Synchronize with Signer before talking to Ledger

### Fixed
- [\#94](https://github.com/Manta-Network/manta-rs/pull/94) Fix Tag-and-Release CI Pipeline

## [0.4.0] - 2022-06-08
### Added
- [\#68](https://github.com/Manta-Network/manta-rs/pull/68) Increase Likelihood of Low Probability Events in the Simulation
- [\#66](https://github.com/Manta-Network/manta-rs/pull/66) Add WASM Prover Benchmark
- [\#62](https://github.com/Manta-Network/manta-rs/pull/62) Add Recovery to the Simulation
- [\#57](https://github.com/Manta-Network/manta-rs/pull/57) Add Parameter Generation for Poseidon
- [\#53](https://github.com/Manta-Network/manta-rs/pull/53) Add `serde` implementaion to HD-KDF
- [\#48](https://github.com/Manta-Network/manta-rs/pull/48) Add Contribution Guidelines and Issue/PR Templates
- [\#34](https://github.com/Manta-Network/manta-rs/pull/34) Support Scalar Multiplication from Precomputed Table
- [\#3](https://github.com/Manta-Network/manta-rs/pull/3) Setup Initial Rust CI Pipeline

### Changed
- [\#64](https://github.com/Manta-Network/manta-rs/pull/64) Improve Synchronization Infrastructure
- [\#59](https://github.com/Manta-Network/manta-rs/pull/59) Improve Ledger API Flexibility and Encoding
- [\#58](https://github.com/Manta-Network/manta-rs/pull/58) Upgrade Simulation to an optional CLI
- [\#42](https://github.com/Manta-Network/manta-rs/pull/42) Convert back to `async` Wallet Interface for WASM

### Fixed
- [\#88](https://github.com/Manta-Network/manta-rs/pull/88) Downgrade Poseidon to fix Binary Incompatibility
- [\#38](https://github.com/Manta-Network/manta-rs/pull/38) Use Correct `AssetList` as `BalanceState` Implementation
- [\#33](https://github.com/Manta-Network/manta-rs/pull/33) Fix Receiving Key Encoding and Generalize Wallets

### Security
- [\#50](https://github.com/Manta-Network/manta-rs/pull/50) Remove Trapdoor from Circuit

[Unreleased]: https://github.com/Manta-Network/manta-rs/compare/v0.5.8...HEAD
[0.5.8]: https://github.com/Manta-Network/manta-rs/releases/tag/v0.5.8
[0.5.7]: https://github.com/Manta-Network/manta-rs/releases/tag/v0.5.7
[0.5.6]: https://github.com/Manta-Network/manta-rs/releases/tag/v0.5.6
[0.5.5]: https://github.com/Manta-Network/manta-rs/releases/tag/v0.5.5
[0.5.4]: https://github.com/Manta-Network/manta-rs/releases/tag/v0.5.4
[0.5.3]: https://github.com/Manta-Network/manta-rs/releases/tag/v0.5.3
[0.5.2]: https://github.com/Manta-Network/manta-rs/releases/tag/v0.5.2
[0.5.1]: https://github.com/Manta-Network/manta-rs/releases/tag/v0.5.1
[0.5.0]: https://github.com/Manta-Network/manta-rs/releases/tag/v0.5.0
[0.4.0]: https://github.com/Manta-Network/manta-rs/releases/tag/v0.4.0
