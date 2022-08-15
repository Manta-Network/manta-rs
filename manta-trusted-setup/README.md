# manta-trusted-setup

```sh
cd manta-trusted-setup
cargo run --release --package manta-trusted-setup --bin generate_phase_one_dummy_parameters
cargo run --release --package manta-trusted-setup --bin groth16_phase2_server -- --backup_dir . --accumulator dummy_phase_one_parameter.data --registry dummy_register.csv create
cargo run --package manta-trusted-setup --bin groth16_phase2_client -- contribute
```

`dummy_register.csv` contains two participants Alice and Bob whose secrets are `xjpj2nHwz7nwEG2S5kGYHzXDFBQoZNMmMxxEQRBCjccCtUyL5JpYicCdkrPf1SUAHixJK6uEzHLmwMsFz5bK7N4` and `4wJjki9duDjtzzSv6xGWy1FVpw14it86Niv1Z7mBN6VARJBitnyuTJfb79iQGE2xGiwc3usGmXaBV4BfNd5PwKji`, respectively.

