use criterion::{black_box, criterion_group, criterion_main, Criterion};
use manta_accounting::asset::AssetId;
use manta_benchmark::{parameters, payment};
use manta_crypto::rand::OsRng;

pub fn bench_mint_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench mint prove");
    let (proving_context, _verifying_context, parameters, utxo_accumulator_model) =
        parameters::get_parameters().unwrap();
    let mut rng = OsRng;

    group.bench_function("bench mint proof generation", |b| {
        let asset_id: u32 = 8;
        let asset = AssetId(asset_id).value(100_000);
        let asset = black_box(asset);

        b.iter(|| {
            payment::bench_mint_prove(
                &proving_context.mint,
                &parameters,
                &utxo_accumulator_model,
                asset,
                &mut rng,
            );
        })
    });
}

pub fn bench_mint_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench mint verify");
    let (proving_context, verifying_context, parameters, utxo_accumulator_model) =
        parameters::get_parameters().unwrap();
    let mut rng = OsRng;

    let asset_id: u32 = 8;
    let asset = AssetId(asset_id).value(100_000);

    let mint = payment::bench_mint_prove(
        &proving_context.mint,
        &parameters,
        &utxo_accumulator_model,
        asset,
        &mut rng,
    );
    let mint = black_box(mint);

    group.bench_function("bench mint verify", |b| {
        b.iter(|| {
            payment::assert_valid_proof(&verifying_context.mint, &mint);
        })
    });
}

pub fn bench_mint_prove_and_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench mint prove and verify");

    let (proving_context, verifying_context, parameters, utxo_accumulator_model) =
        parameters::get_parameters().unwrap();
    let mut rng = OsRng;

    group.bench_function("bench mint prove and verify", |b| {
        let asset_id: u32 = 8;
        let asset = AssetId(asset_id).value(100_000);
        let asset = black_box(asset);

        b.iter(|| {
            payment::bench_mint_prove_and_verify(
                &proving_context.mint,
                &verifying_context.mint,
                &parameters,
                &utxo_accumulator_model,
                asset.clone(),
                &mut rng,
            );
        })
    });
}

// criterion_group!(benches, bench_mint_prove);
// criterion_group!(benches, bench_mint_verify);
criterion_group!(benches, bench_mint_prove_and_verify);
criterion_main!(benches);
