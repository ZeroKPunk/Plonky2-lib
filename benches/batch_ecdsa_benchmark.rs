use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use plonky2::plonk::circuit_data::CircuitConfig;
use Plonky2_lib::ecdsa::gadgets::ecdsa::test_batch_ecdsa_circuit_with_config;

fn ecdsa_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDSA_Benchmark_Group");
    group.sample_size(10); // 减少样本数量
    group.measurement_time(std::time::Duration::from_secs(60));
    group.bench_with_input(BenchmarkId::new("ECDSA_Circuit_Narrow", 1), &1, |b, &_| {
        b.iter(|| {
            let config = CircuitConfig::standard_ecc_config();
            test_batch_ecdsa_circuit_with_config(black_box(1), black_box(config));
        });
    });

    group.finish();
}

criterion_group!(benches, ecdsa_benchmark);
criterion_main!(benches);
