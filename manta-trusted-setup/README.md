# manta-trusted-setup

## Server Creation

To crate a new server use the following command: 

```sh
cargo run --release --package manta-trusted-setup --bin groth16_phase2_server -- create path_to_registry path_to_backup_directory
```

## Server Recovery

To recover a server use the following command:

```sh
cargo run --release --package manta-trusted-setup --bin groth16_phase2_server -- recover path_to_recovery_file path_to_backup_directory
```

## Client Register

To register as a client, please use the following command:

```sh
cargo run --package manta-trusted-setup --bin groth16_phase2_client -- register
```

This would ask you to type in `twitter` and `email`. This will give you `public key`, `signature`, and `secret`.

## Client Contribute

To contribute as a client, please use the following command:

```sh
cargo run --package manta-trusted-setup --bin groth16_phase2_client -- contribute
```

This would ask you for the `secret` that you received during *client register*.

## Generating Dummy Phase1 Parameters

To generate dummy phase1 parameters, please use the following command:

```sh
cargo run --release --package manta-trusted-setup --bin generate_phase_one_dummy_parameters
```

## Preparing Phase1 Parameters for Phase2

```sh
cargo run --release --package manta-trusted-setup --bin prepare_phase_two_parameters -- path_to_phase_one_parameter
```

## Local Test

For a local test, please use the following command:

```sh
# Takes ~1 hour.
cargo run --release --package manta-trusted-setup --bin generate_phase_one_dummy_parameters

# Takes ~0.5 hour.
cargo run --release --package manta-trusted-setup --bin prepare_phase_two_parameters -- data/dummy_phase_one_parameter.data

# Takes ~1 minute to load preprocessed parameters.
cargo run --release --package manta-trusted-setup --bin groth16_phase2_server -- create data/dummy_register.csv data

# Takes ~3 minutes to contribute.
cargo run --release --package manta-trusted-setup --bin groth16_phase2_client -- contribute
```

We provide a `dummy_register.csv` containing $5$ participants whose secrets are:

| Name | Secret |
| --- | --- |
| Alice | theory traffic reject rain virus solution seat tip nuclear symptom dry number |
| Bob |  hollow sting riot invest patrol clock roof render still lock struggle salt |
| Charlie | boat fence mansion budget negative thumb spoon enlist grow extra badge banana |
| David | gown enroll caution desk swift soon scorpion ridge odor what near express |
| Evan | square grace retreat stick still learn fold polar sugar axis isolate polar |
