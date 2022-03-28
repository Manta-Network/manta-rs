# Contributing

Thank you for contributing to the `manta-rs` codebase! Here are some guidelines to following when adding code or documentation to this repository.

## Style Guide

To keep code and documentation style consistent across all the code in the repository, we are adopting the following style guide. We begin with the formatting style enforced by the Nightly version of `rustfmt` with configuration specified in the [`.rustfmt.toml`](./.rustfmt.toml) file. Beyond what `rustfmt` currently enforces we have specified other rules below.

### General Gramatical Structures

### `Cargo.toml`

The `Cargo.toml` file should ahere to the following template:

```toml
[package]
name = "..."
version = "..."
edition = "..."
authors = ["Manta Network <contact@manta.network>"]
readme = "README.md"
license-file = "LICENSE"
repository = "https://github.com/Manta-Network/manta-rs"
homepage = "https://github.com/Manta-Network"
documentation = "https://github.com/Manta-Network/manta-rs"
categories = ["..."]
keywords = ["..."]
description = "..."
publish = false

[package.metadata.docs.rs]
# To build locally:
# RUSTDOCFLAGS="--cfg doc_cfg" cargo +nightly doc --all-features --open
all-features = true
rustdoc-args = ["--cfg", "doc_cfg"]

[badges]
is-it-maintained-issue-resolution = { repository = "Manta-Network/manta-rs" }
is-it-maintained-open-issues = { repository = "Manta-Network/manta-rs" }
maintenance = { status = "actively-developed" }

[[bin]]
...

[features]
...

[dependencies]
...

[dev-dependencies]
...

[build-dependencies]
...

[profile....]
...
```

Specifically, we have:

1. Use double quotes instead of single quotes.
2. Use the standard ordering of the `[package]` map.
3. `[[bin]]` before `[features]` before `[dependencies]` before `[dev-dependencies]` before `[build-dependencies]` before `[profile]` settings.
4. When selecting features for a `[features]` entry or when selecting the features on a dependency, order the features alphabetically.
5. Order dependencies alphabetically.
6. For a given dependency use the following structure with `optional` and `features` keys as needed:
    ```toml
    crate-name = { version = "...", optional = true, default-features = false, features = ["..."] }
    ```
    If the crate is a `path` or `git` dependency, replace those keys with the `version` key.
7. When adding a feature, add a doc string in title case and a newline between each feature.

### Feature Selection

When using features, be sure to attach a `doc_cfg` feature declaration as well unless the code is not exported to `pub`.

### Imports and Exports

Imports (`use`) and exports (`mod`) should be ordered as follows:

1. External Crate Declarations
2. Private Imports
3. Private Imports with Features
4. Private Exports
5. Private Exports with Features
6. Public Exports
7. Public Exports with Features
8. Reexports
9. Reexports with Features

Here's an example set of declarations:

```rust
extern crate crate_name;

use module::submodule::entry;

#[cfg(feature = "...")]
use module::feature_gated_submodule;

mod another_module;
mod module;
mod the_third_module;

#[cfg(feature = "...")]
mod feature_gated_module;

pub mod public_module;

#[cfg(feature = "...")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "...")))]
pub mod feature_gated_public_module;

pub use reexported_objects;

#[cfg(feature = "...")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "...")))]
pub use feature_gated_reexported_objects;
```

Ensure that there are newlines between each category. Be sure that if there are imports or exports that are feature-gated, that they are sorted by feature alphabetically. If there is a feature gated import that requires importing multiple objects use the following pattern:

```rust
#[cfg(feature = "...")]
use {
    thing1, thing2, thing3, thing4,
};
```

### Where Clauses

1. Always use where clauses instead of inline trait constraints. So instead of

    ```text
    fn function<T: Clone>(t: &T) -> T {
        t.clone()
    }
    ```

    you should use

    ```rust
    fn function<T>(t: &T) -> T
    where
        T: Clone,
    {
        t.clone()
    }
    ```

    This is also true for any part of the code where generic types can be declared, like in `fn`, `struct`, `enum`, `trait`, and `impl`. The only "exception" is for supertraits, so use:

    ```rust
    trait Trait: Clone + Default + Sized {}
    ```

    instead of using

    ```text
    trait Trait
    where
        Self: Clone + Default + Sized,
    {}
    ```

2. Order `where` clause entries by declaration order, then by associated types and then by other constraints. Here's an example

    ```rust
    fn function<A, B, C>(a: &A, b: &mut B) -> Option<C>
    where
        A: Clone + Iterator,
        B: Default + Eq,
        C: IntoIterator,
        A::Item: Clone,
        C::IntoIter: ExactSizeIterator,
        Object<B, C>: Copy,
    ```

    **NOTE**: This rule is not so strict, and these `where` clauses should be organized in a way that makes most sense but must follow this general rule.

3. Order each entries constraints alphabetically. Here's an example:

    ```rust
    F: 'a + Copy + Trait + FnOnce(T) -> S
    ```

    The ordering should be lifetimes first, then regular traits, then the function traits.

### Documentation

1. All module documentation should exist in the module itself in the header with `//!` doc strings.
2. Be sure to link all documentation that refers to objects in the code.
