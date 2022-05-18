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

use criterion::black_box;
use instant;
use manta_benchmark::{prove_mint, prove_private_transfer, prove_reclaim, Context};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::console;
wasm_bindgen_test_configure!(run_in_browser);

static REPEAT: usize = 1;

#[wasm_bindgen_test]
fn bench_construct_context() {
    let start_time = instant::Instant::now();
    for _ in 0..REPEAT {
        Context::new();
    }
    let end_time = instant::Instant::now();
    console::log_1(
        &format!(
            "Construct Context Performance: {:?} ms",
            ((end_time - start_time) / REPEAT as u32)
        )
        .into(),
    );
}

// #[wasm_bindgen_test]
// fn bench_prove_mint() {
//     let context = Context::new();
//     let start_time = instant::Instant::now();
//     for _ in 0..REPEAT {
//         prove_mint(&context);
//     }
//     let end_time = instant::Instant::now();
//     console::log_1(
//         &format!(
//             "Prove Mint Performance: {:?} ms",
//             ((end_time - start_time) / REPEAT as u32)
//         )
//         .into(),
//     );
// }

// #[wasm_bindgen_test]
// fn bench_prove_private_transfer() {
//     let context = black_box(Context::new());
//     let start_time = instant::Instant::now();
//     for _ in 0..REPEAT {
//         prove_private_transfer(&context);
//     }
//     let end_time = instant::Instant::now();
//     console::log_1(
//         &format!(
//             "Prove Private Transfer Performance: {:?} ms, REPEAT: {:?}, raw_latency: {:?} ms",
//             ((end_time - start_time) / REPEAT as u32), REPEAT, (end_time - start_time)
//         )
//         .into(),
//     );
// }

// #[wasm_bindgen_test]
// fn bench_prove_reclaim() {
//     let context = Context::new();
//     let start_time = instant::Instant::now();
//     for _ in 0..REPEAT {
//         prove_reclaim(&context);
//     }
//     let end_time = instant::Instant::now();
//     console::log_1(
//         &format!(
//             "Prove Reclaim Performance: {:?} ms",
//             ((end_time - start_time) / REPEAT as u32)
//         )
//         .into(),
//     );
// }
