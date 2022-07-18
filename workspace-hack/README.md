# Workspace Hack

This crate will never contain any code, it is just used by [`cargo-hakari`](https://github.com/facebookincubator/cargo-guppy/tree/main/tools/cargo-hakari) to speed up CI builds. See [their documentation](https://docs.rs/cargo-hakari/latest/cargo_hakari/about/index.html) for more on how workspace hacks work.

## Updating the Dependency List

When a dependency on `Cargo.toml` needs to be updated, the CI for a PR will fail because `cargo hakari generate --diff` will return with error code `1`. In this case, the `cargo hakari generate` command should be run on a local machine and the updates pushed to the relevant development branch. 
