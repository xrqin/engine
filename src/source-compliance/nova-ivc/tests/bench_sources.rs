//! Benchmark: Nova IVC R_MERGE_N prove + verify for source count 1 -> 1024
//!
//! Run: cargo test --release --test bench_sources -- --nocapture

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, PrimeField};
use folding_schemes::FoldingScheme;
use railgun_merge_ivc::{
    MergeExternalInputs, MergeStepCircuit, NovaParams,
    poseidon_config::nova_poseidon_config,
};
use rand::{SeedableRng, rngs::StdRng};
use std::time::Instant;

/// Each "source" is represented by one merge step folding a tree with `batch_size` primes.
/// Total source count ≈ batch_size + N_steps * batch_size.
fn run_benchmark(
    n_steps: usize,
    batch_size: u64,
    label: &str,
    params: &NovaParams<MergeStepCircuit<Fr>>,
) {
    let mut rng = StdRng::seed_from_u64(42 + n_steps as u64);

    let z_0 = vec![
        Fr::from(1u64),
        Fr::from(batch_size),
        <Fr as AdditiveGroup>::ZERO,
    ];

    // --- PROVE ---
    let prove_start = Instant::now();
    let mut nova = params.initial_nova(z_0).expect("Nova init");

    for i in 0..n_steps {
        let ext = MergeExternalInputs {
            is_dummy: false,
            right_root: Fr::from(1000u64 + i as u64),
            right_count: Fr::from(batch_size),
        };
        nova.prove_step(&mut rng, ext, None)
            .unwrap_or_else(|e| panic!("prove_step[{}]: {}", i, e));
    }
    let prove_elapsed = prove_start.elapsed();

    // --- VERIFY ---
    let ivc_proof = nova.ivc_proof();
    let verify_start = Instant::now();
    params.verify(ivc_proof).expect("IVC verify");
    let verify_elapsed = verify_start.elapsed();

    // --- FINAL STATE ---
    let final_state = nova.state();
    let _total_count: u64 = final_state[1].into_bigint().as_ref()[0];

    println!(
        "  | {:>7} | {:>7} | {:>5} | {:>11.2} ms | {:>11.2} ms | {:>8.2} ms/step |",
        label,
        n_steps,
        batch_size,
        prove_elapsed.as_secs_f64() * 1000.0,
        verify_elapsed.as_secs_f64() * 1000.0,
        prove_elapsed.as_secs_f64() * 1000.0 / n_steps.max(1) as f64,
    );
}

#[test]
fn bench_nova_ivc_source_counts() {
    let mut rng = StdRng::seed_from_u64(42);
    let poseidon_config = nova_poseidon_config();

    println!("\n  === Nova IVC Setup ===");
    let setup_start = Instant::now();
    let params = NovaParams::<MergeStepCircuit<Fr>>::rand(poseidon_config, &mut rng)
        .expect("Nova setup");
    let setup_elapsed = setup_start.elapsed();
    println!("  Setup time: {:.2} ms", setup_elapsed.as_secs_f64() * 1000.0);

    // === Batch=4 (original) ===
    println!("\n  === Nova IVC Benchmark: batch_size=4 (原始) ===");
    println!("  +---------+---------+-------+---------------+---------------+-----------------+");
    println!("  | Sources | N Steps | Batch | IVC Prove     | IVC Verify    | Per-Step Cost   |");
    println!("  +---------+---------+-------+---------------+---------------+-----------------+");

    for &(n_steps, label) in &[
        (15usize, "64"),
        (31,  "128"),
        (63,  "256"),
        (127, "512"),
        (255, "1024"),
    ] {
        run_benchmark(n_steps, 4, label, &params);
    }

    println!("  +---------+---------+-------+---------------+---------------+-----------------+");

    // === Batch=32 ===
    println!("\n  === Nova IVC Benchmark: batch_size=32 ===");
    println!("  +---------+---------+-------+---------------+---------------+-----------------+");
    println!("  | Sources | N Steps | Batch | IVC Prove     | IVC Verify    | Per-Step Cost   |");
    println!("  +---------+---------+-------+---------------+---------------+-----------------+");

    for &(n_steps, label) in &[
        (1usize,  "64"),     // 32 + 1*32 = 64
        (3,   "128"),    // 32 + 3*32 = 128
        (7,   "256"),    // 32 + 7*32 = 256
        (15,  "512"),    // 32 + 15*32 = 512
        (31,  "1024"),   // 32 + 31*32 = 1024
    ] {
        run_benchmark(n_steps, 32, label, &params);
    }

    println!("  +---------+---------+-------+---------------+---------------+-----------------+");
    println!("  (Nova IVC on BN254/Grumpkin via Sonobe, release mode, Apple Silicon)");
    println!("  注: 步电路不变 (2 Poseidon/step), batch_size 只影响步数, 不影响每步约束数\n");
}
