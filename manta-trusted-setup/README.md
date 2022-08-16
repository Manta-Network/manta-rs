# manta-trusted-setup

## Server Creation

To crate a new server use the following command: 

```sh
cargo run --release --package manta-trusted-setup --bin groth16_phase2_server -- --backup_dir . --accumulator path_to_phase_one_parameter --registry path_to_registry create
```

Arguments are:

* `--backup_dir`: path to a directory for backing up each contribution
* `--accumulator`: path to a file for phase one parameters
* `--registry`: path to a file for a registry of all participants

TODO: Use prepared parameters

## Server Recovery

TODO: Add documents

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
# cargo run --release --package manta-trusted-setup --bin prepare_phase_two_parameters -- --accumulator dummy_phase_one_parameter.data --prepared_parameter prepared_phase_two_parameter.data

# Takes ~??.
cargo run --release --package manta-trusted-setup --bin groth16_phase2_server -- --backup_dir . --accumulator dummy_phase_one_parameter.data --registry dummy_register.csv create

# Takes ~??.
cargo run --package manta-trusted-setup --bin groth16_phase2_client -- contribute
```

We provide a `dummy_register.csv` containing $10$ participants whose secrets are:

| Name | Secret |
| --- | --- |
| Alice | xjpj2nHwz7nwEG2S5kGYHzXDFBQoZNMmMxxEQRBCjccCtUyL5JpYicCdkrPf1SUAHixJK6uEzHLmwMsFz5bK7N4 |
| Bob |  4wJjki9duDjtzzSv6xGWy1FVpw14it86Niv1Z7mBN6VARJBitnyuTJfb79iQGE2xGiwc3usGmXaBV4BfNd5PwKji |
| Charlie |  t1qhNmShcoLmEmjq2od96HduZoRpgjXADEj1Q2fLcQJxQkfKerHd6J6d6NZBenHLGmSbAzSkooVT31Grdj4dNr3 |
| David |  35KLqW3aQNRhMe3dngc4ntQ1H5t1MvBRaFZQWFm4aY2nUy6G8exRcp63NP911xpX4Wv3TjFBS7zs6w715eBvFJJd |
| Evan |  LjMsMqtRijqBufWZH4yz1JawVdHnJB2VBffvdio4vs7Vf5KSAXq6c1VYBQa8HE44SHAvT4ZfHwy6a9afJQPx7SP |
| Felix | j626j2w74FhzGQBJx4CAtp4JQVNHxiw1mZaFjDHbYK2qmsJownw2gRp5j8VF4qi9UzY17QJZXLKUrJQrnVfwrMo |
| Gavin |  5dt7usXXqugtV7yAaGwjbC5PDtFhJgqk5MbBwJeZVBPjGEHuhGGLkcUQc7s14vGzKdVR9TgPbYjnQdQRADsNHsKE |
| Henry |  3knV55xzYApJK6Zq6h2yfMJG3rjs2Ds3sUEwtRoRy7SyEa3mWUi8dih9tMS4FMejCkkxyAn15WQQnJP6XEKGVFvD |
| Iris | 5o8Hc9HqecVzYkfzdQnQUTkm8g858tbaoaWApSKSkw4eWSRJkm12xjtRgaqDbaXYHxNWFUB1MsWNm7914QEjRmdY |
| Jordan |  3LT9QCLXxhE3pdYqDwHJxMgYPSatHSagnnDYKb7acJyrrQysBp2hX9HFjhUYJYg4c5NnUDqRonZKCsa9ay3FyYfL |
