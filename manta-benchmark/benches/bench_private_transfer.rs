use criterion::{black_box, criterion_group, criterion_main, Criterion};
use manta_accounting::asset::AssetId;
use manta_benchmark::{parameters, payment};
use manta_crypto::rand::OsRng;

fn bench_private_transfer(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench private transfer");

    let mut rng = OsRng;
    let (proving_context, verifying_context, parameters, utxo_accumulator_model) =
        parameters::get_parameters().unwrap();

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
