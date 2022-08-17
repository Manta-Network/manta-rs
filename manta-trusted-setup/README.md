# manta-trusted-setup

## Server Creation

To crate a new server use the following command: 

```sh
cargo run --release --package manta-trusted-setup --bin groth16_phase2_server -- --backup_dir path_to_backup_directory --preprocessed_parameters path_to_preprocessed_parameters --registry path_to_registry create
```

Arguments are:

* `--backup_dir`: path to a directory for backing up each contribution
* `--preprocessed_parameters`: path to a file for preprocessed phase one parameters
* `--registry`: path to a file for a registry of all participants

## Server Recovery

To recover a server use the following command:

```sh
cargo run --release --package manta-trusted-setup --bin groth16_phase2_server -- --backup_dir path_to_backup_directory --recovery path_to_recovery_file recover
```

Arguments are:

* `--backup_dir`: path to a directory for backing up each contribution
* `--recovery`: path to a file for recovery

## Client Register

To register as a client, please use the following command:

```sh
cargo run --package manta-trusted-setup --bin groth16_phase2_client -- register
```

This would ask you to type in `twitter` and give you `public key`, `signature`, and `secret`.


## Client Contribute

To contribute as a client, please use the following command:

```sh
cargo run --package manta-trusted-setup --bin groth16_phase2_client -- contribute
```

This would ask you for the `secret` that you received during *client register*.

## Preparing Phase1 Parameters for Phase2

```sh
cargo run --release --package manta-trusted-setup --bin prepare_phase_two_parameters -- --accumulator path_to_phase_one_parameter --prepared_parameter path_to_prepared_phase_two_parameter
```

Arguments are:

* `--accumulator`: path to a file for phase one parameters
* `--prepared_parameter`: path to a file for storing the prepared phase two parameres

## Local Test

For a local test, please use the following command:

```sh
# Takes ~1 hour.
cargo run --release --package manta-trusted-setup --bin generate_phase_one_dummy_parameters

# Takes ~0.5 hour.
cargo run --release --package manta-trusted-setup --bin prepare_phase_two_parameters -- --accumulator dummy_phase_one_parameter.data --prepared_parameter prepared_phase_two_parameter.data

# Takes ~1 minute to load preprocessed parameters.
cargo run --release --package manta-trusted-setup --bin groth16_phase2_server -- --backup_dir . --preprocessed_parameters prepared_phase_two_parameter.data --registry dummy_register.csv create

# Takes ~3 minutes to contribute.
cargo run --release --package manta-trusted-setup --bin groth16_phase2_client -- contribute
```

We provide a `dummy_register.csv` containing $10$ participants whose secrets are:

| Name | Secret |
| --- | --- |
| Alice | 3crn189hhBziv9X6YvmPLnvZeyfj2EzSKTqNXLsVwdMBq7LFLts8xcKri6Gka5yyo4ra8qoKVhmKcstbhEXBD9ZM |
| Bob | 4W3ieMwX83qwBpcBTuLq97NhKDccLTNW2feEuB3r9LgUb7aSJejHUMQse7GJXoGfBp8kK8StwxN7siYobbiys73a |
| Charlie | 4zfXyHkrwiQaxMhvsdzVTfGkXqNA61NayVLGLgVNAcG4RqAF7csMNWwzGbfhvXPcsFtbx6vbSsMRT34UNXbFc7DL  |
| David | 2tgdpuVVsb4aN6pKLVTmyT5KHNukWGHpLKXDuPN4kuuzzCK2qRExq1hkgV2skNrseqhCPLfwrEhXPdPToJ6dwzKj |
| Evan | 4WyfmSP9ct4dr7iPiXJTzoDvg8LXPJsueJp1u9D6oP3kXKMdRBqX7KEBVkkiD8L8MgRjs5zFefbeV61CX6RrrkSF |
| Felix | 2wm2Yd46gCxBVefpB6bTFer3qKTLbNGgnNuC49Q1evuebzjbaptwD2AmkiLwvc2BtaSDA9NDZUBDCjkx9w3ZKxXi |
| Gavin | 5ec5PB6qg1RsnjxfS9QeneJJuQfJZkgjMu7nhAyCt1i3xCgSYYizoB6Dp1rnYJp5wmWFw2kHM8GmgsZL8oK93Ntg |
| Henry | 5QrmKpm89vGHQYX9g7ABV82Uok6MjMbBvJ5CyFmTvqaMsoYQ6R84PPMXDRTJLfuiSFankboRu17dDs2VdBWECCon |
| Iris | L9wX1qtZ8QUgScPqC4xbv7dn1knz4TddcGj43HMiUkZVGSDYwCMsFQvyhR9YHTBoTq3CCW4xt4zUy6ZG7SkYoig |
| Jordan | 2xiFiWQotgsMdAKqynKhEqQg7RcLxDfXsHR7fe3J5hTQ7yk7Gsq8LGLE2bb12rvFyth98ZVWfNyz9WsFRPQkQWL3 |
