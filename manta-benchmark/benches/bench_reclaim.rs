use criterion::{black_box, criterion_group, criterion_main, Criterion};
use manta_accounting::asset::AssetId;
use manta_benchmark::{parameters, payment};
use manta_crypto::rand::OsRng;

fn bench_reclaim(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench reclaim");

    let mut rng = OsRng;
    let (proving_context, verifying_context, parameters, utxo_accumulator_model) =
        parameters::get_parameters().unwrap();

    group.bench_function("bench reclaim", |b| {
        let asset_id: u32 = 8;
        let asset_0 = AssetId(asset_id).value(10_000);
        let asset_1 = AssetId(asset_id).value(20_000);
        let asset_0 = black_box(asset_0);
        let asset_1 = black_box(asset_1);
        let assets = vec![asset_0, asset_1];

        b.iter(|| {
            payment::bench_reclaim_wrapper(
                &proving_context,
                &verifying_context,
                &parameters,
                &utxo_accumulator_model,
                assets.clone(),
                &mut rng,
            )
        })
    });
}

criterion_group!(benches, bench_reclaim);
criterion_main!(benches);
