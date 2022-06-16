# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- [\#102](https://github.com/Manta-Network/manta-rs/pull/102) Add concrete parameters to `manta-parameters`
- [\#101](https://github.com/Manta-Network/manta-rs/pull/101) Add duplex encryption and Poseidon implementation

### Changed

### Deprecated

### Removed

### Fixed

### Security

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

[Unreleased]: https://github.com/Manta-Network/manta-rs/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/Manta-Network/manta-rs/releases/tag/v0.5.0
[0.4.0]: https://github.com/Manta-Network/manta-rs/releases/tag/v0.4.0
