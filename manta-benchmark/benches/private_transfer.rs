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

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use manta_accounting::asset::AssetId;
use manta_benchmark::payment;
use manta_crypto::rand::OsRng;
use manta_pay::crypto::parameters::generate_parameters;

fn bench_private_transfer(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench private transfer");

    let mut rng = OsRng;
    let (proving_context, verifying_context, parameters, utxo_accumulator_model) =
        generate_parameters(payment::SEED).unwrap();

    let asset_id: u32 = 8;
    let asset_0 = AssetId(asset_id).value(10_000);
    let asset_1 = AssetId(asset_id).value(20_000);
    let asset_0 = black_box(asset_0);
    let asset_1 = black_box(asset_1);
    let assets = vec![asset_0, asset_1];

    let input = (
        proving_context,
        verifying_context,
        parameters,
        utxo_accumulator_model,
        assets,
    );
    group.bench_function("bench private transfer", |b| {
        b.iter(|| {
            payment::bench_private_transfer_wrapper(
                &input.0,
                &input.1,
                &input.2,
                &input.3,
                input.4.clone(),
                &mut rng,
            )
        })
    });
}

criterion_group!(benches, bench_private_transfer);
criterion_main!(benches);
