## Release vX.Y.Z

**Each reviewer needs to check that these conditions are met before approving the PR.**

- [ ] Checked that the release is on the correct branch name of the form `release-vX.Y.Z` 
- [ ] Added the `changelog:skip` label and the relevant `release` label to this PR
- [ ] Updated the [`CHANGELOG.md`](https://github.com/manta-network/manta-rs/blob/main/CHANGELOG.md)
- [ ] Updated the version numbers in the `Cargo.toml` for each crate in the workspace
- [ ] Ran `cargo hakari disable` to disable the `workspace-hack` system and checked that `workspace-hack/Cargo.toml` has no dependencies
