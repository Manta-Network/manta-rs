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
use manta_pay::parameters::{generate_parameters, SEED};

pub fn prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench");
    let (proving_context, _verifying_context, parameters, utxo_accumulator_model) =
        generate_parameters(SEED).unwrap();
    let mut rng = OsRng;

    group.bench_function("mint prove", |b| {
        let asset_id: u32 = 8;
        let asset = AssetId(asset_id).value(100_000);
        let asset = black_box(asset);

        b.iter(|| {
            payment::prove_mint(
                &proving_context.mint,
                &parameters,
                &utxo_accumulator_model,
                asset,
                &mut rng,
            );
        })
    });
}

pub fn verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench");
    let (proving_context, verifying_context, parameters, utxo_accumulator_model) =
        generate_parameters(SEED).unwrap();
    let mut rng = OsRng;

    let asset_id: u32 = 8;
    let asset = AssetId(asset_id).value(100_000);

    let mint = payment::prove_mint(
        &proving_context.mint,
        &parameters,
        &utxo_accumulator_model,
        asset,
        &mut rng,
    );
    let mint = black_box(mint);

    group.bench_function("mint verify", |b| {
        b.iter(|| {
            payment::assert_valid_proof(&verifying_context.mint, &mint);
        })
    });
}

criterion_group!(mint, prove, verify);
criterion_main!(mint);
