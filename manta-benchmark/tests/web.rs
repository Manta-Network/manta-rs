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

use manta_benchmark::{prove_mint, prove_private_transfer, prove_reclaim, Context, Proof};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::console;

wasm_bindgen_test_configure!(run_in_browser);

static REPEAT: usize = 3;

fn bench<F>(mut f: F, operation: &str)
where
    F: FnMut(&Context) -> Proof,
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

#[wasm_bindgen_test]
fn bench_prove_mint() {
    bench(prove_mint, "Prove Mint");
}

#[wasm_bindgen_test]
fn bench_prove_private_transfer() {
    bench(prove_private_transfer, "Prove Private Transfer");
}

#[wasm_bindgen_test]
fn bench_prove_reclaim() {
    bench(prove_reclaim, "Prove Reclaim");
}
