//! Benchmark: Nova IVC merge step folding.
//!
//! Measures:
//!   - Nova setup (one-time)
//!   - Single prove_step (per-fold)
//!   - IVC verification
//!   - N-step fold total
//!
//! Run: cargo bench --bench merge_bench

use ark_bn254::Fr;
use ark_ff::AdditiveGroup;
use criterion::{criterion_group, criterion_main, Criterion};
use folding_schemes::FoldingScheme;
use railgun_merge_ivc::{
    MergeExternalInputs, MergeStepCircuit, NovaParams,
    poseidon_config::nova_poseidon_config,
};
use rand::{SeedableRng, rngs::StdRng};

fn bench_nova_setup(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(42);
    let poseidon_config = nova_poseidon_config();

    c.bench_function("nova_setup", |b| {
        b.iter(|| {
            NovaParams::<MergeStepCircuit<Fr>>::rand(poseidon_config.clone(), &mut rng)
                .expect("setup");
        });
    });
}

fn bench_prove_step(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(42);
    let poseidon_config = nova_poseidon_config();
    let params = NovaParams::<MergeStepCircuit<Fr>>::rand(poseidon_config, &mut rng)
        .expect("setup");

    let z0 = vec![Fr::from(12345u64), Fr::from(1u64), Fr::zero()];
    let mut nova = params.initial_nova(z0).expect("init");

    c.bench_function("prove_step_single", |b| {
        b.iter(|| {
            let ext = MergeExternalInputs {
                is_dummy: false,
                right_root: Fr::from(67890u64),
                right_count: Fr::from(4u64),
            };
            nova.prove_step(&mut rng, ext, None).expect("step");
        });
    });
}

fn bench_ivc_verify(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(42);
    let poseidon_config = nova_poseidon_config();
    let params = NovaParams::<MergeStepCircuit<Fr>>::rand(poseidon_config, &mut rng)
        .expect("setup");

    let z0 = vec![Fr::from(12345u64), Fr::from(1u64), Fr::zero()];
    let mut nova = params.initial_nova(z0).expect("init");

    // Fold 4 steps
    for i in 0..4 {
        let ext = MergeExternalInputs {
            is_dummy: false,
            right_root: Fr::from(1000u64 + i),
            right_count: Fr::from(4u64),
        };
        nova.prove_step(&mut rng, ext, None).expect("step");
    }

    let ivc_proof = nova.ivc_proof();

    c.bench_function("ivc_verify_4steps", |b| {
        b.iter(|| {
            params.verify(ivc_proof.clone()).expect("verify");
        });
    });
}

fn bench_fold_n_steps(c: &mut Criterion) {
    let mut group = c.benchmark_group("fold_n_steps");
    group.sample_size(10);

    let mut rng = StdRng::seed_from_u64(42);
    let poseidon_config = nova_poseidon_config();
    let params = NovaParams::<MergeStepCircuit<Fr>>::rand(poseidon_config, &mut rng)
        .expect("setup");

    for n in [2, 4, 8, 16, 32] {
        group.bench_function(format!("fold_{}_steps", n), |b| {
            b.iter(|| {
                let z0 = vec![Fr::from(1u64), Fr::from(1u64), Fr::zero()];
                let mut nova = params.initial_nova(z0).expect("init");
                for i in 0..n {
                    let ext = MergeExternalInputs {
                        is_dummy: false,
                        right_root: Fr::from(1000u64 + i as u64),
                        right_count: Fr::from(4u64),
                    };
                    nova.prove_step(&mut rng, ext, None).expect("step");
                }
                let ivc_proof = nova.ivc_proof();
                params.verify(ivc_proof).expect("verify");
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_nova_setup,
    bench_prove_step,
    bench_ivc_verify,
    bench_fold_n_steps,
);
criterion_main!(benches);
