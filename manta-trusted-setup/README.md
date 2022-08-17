# manta-trusted-setup

## Server Creation

To crate a new server use the following command: 

```sh
cargo run --release --package manta-trusted-setup --bin groth16_phase2_server -- --backup_dir path_to_backup_directory --registry path_to_registry create
```

Arguments are:

* `--backup_dir`: path to a directory for backing up each contribution
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
cargo run --release --package manta-trusted-setup --bin prepare_phase_two_parameters -- --accumulator path_to_phase_one_parameter
```

Arguments are:

* `--accumulator`: path to a file for phase one parameters

## Local Test

For a local test, please use the following command:

```sh
# Takes ~1 hour.
cargo run --release --package manta-trusted-setup --bin generate_phase_one_dummy_parameters

# Takes ~0.5 hour.
cargo run --release --package manta-trusted-setup --bin prepare_phase_two_parameters -- --accumulator dummy_phase_one_parameter.data

# Takes ~1 minute to load preprocessed parameters.
cargo run --release --package manta-trusted-setup --bin groth16_phase2_server -- --backup_dir . --registry dummy_register.csv create

# Takes ~3 minutes to contribute.
cargo run --release --package manta-trusted-setup --bin groth16_phase2_client -- contribute
```

We provide a `dummy_register.csv` containing $10$ participants whose secrets are:

| Name | Secret |
| --- | --- |
| Alice |  mouse earn flame bicycle column arena two nothing stairs confirm peasant table |
| Bob |  cupboard comfort fun pistol drink enroll laundry pluck silver tape clinic moon |
| Charlie |  evil insane fragile fog acid laugh target subway soft pattern edit monkey |
| David |  gauge update very gorilla stove shell index little custom manage shrug reflect |
| Evan |  worry indoor ready slogan trick eyebrow adult engine pupil feed series toe |
