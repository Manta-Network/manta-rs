// Copyright 2019-2022 Manta Network.
// This file is part of manta-rs.
//
// manta-rs is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// manta-rs is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with manta-rs.  If not, see <http://www.gnu.org/licenses/>.

//! WASM Transfer Benchmarks

use manta_benchmark::transfer::{self, Context, TransferPost};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::console;

wasm_bindgen_test_configure!(run_in_browser);

/// Number of Repeated Measurements to take
pub static REPEAT: usize = 3;

///
#[inline]
fn bench<F>(mut f: F, operation: &str)
where
    F: FnMut(&Context) -> TransferPost,
{
    let context = Context::new();
    let start_time = instant::Instant::now();
    for _ in 0..REPEAT {
        f(&context);
    }
    let end_time = instant::Instant::now();
    console::log_1(
        &format!(
            "{:?} Performance: {:?}",
            operation,
            ((end_time - start_time) / REPEAT as u32)
        )
        .into(),
    );
}

///
#[wasm_bindgen_test]
fn bench_prove_to_private() {
    bench(transfer::prove_to_private, "Prove `ToPrivate`");
}

///
#[wasm_bindgen_test]
fn bench_prove_private_transfer() {
    bench(transfer::prove_private_transfer, "Prove `PrivateTransfer`");
}

///
#[wasm_bindgen_test]
fn bench_prove_to_public() {
    bench(transfer::prove_to_public, "Prove `ToPublic`");
}
