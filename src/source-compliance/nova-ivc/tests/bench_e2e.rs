//! End-to-end benchmark: SCAN_A + SCAN_B + MERGE2 for a 2-input transfer
//!
//! Simulates the full merge flow: two input notes each with N/2 sources,
//! SCAN each, then MERGE2 the union.
//!
//! Run: cargo test --release --test bench_e2e -- --nocapture

use ark_bn254::Fr;
use ark_ff::AdditiveGroup;
use folding_schemes::FoldingScheme;
use railgun_merge_ivc::{
    NovaParams,
    poseidon_config::nova_poseidon_config,
    scan_step_circuit::{ScanExternalInputs, ScanStepCircuit},
    merge2_step_circuit::{Merge2ExternalInputs, Merge2StepCircuit},
};
use rand::{SeedableRng, rngs::StdRng};
use std::time::Instant;

const D: usize = 10;
const B_SCAN: usize = 32;
const B_MERGE: usize = 32;

type SC = ScanStepCircuit<Fr, D, B_SCAN>;
type MC = Merge2StepCircuit<Fr, D, B_MERGE>;

fn run_scan(
    params: &NovaParams<SC>,
    rng: &mut StdRng,
    n_sources: usize,
    offset: usize,
) -> f64 {
    let mut z_0 = vec![Fr::ZERO; D + 5];
    z_0[D + 3] = Fr::from(999u64);

    let n_steps = (n_sources + B_SCAN - 1) / B_SCAN;
    let start = Instant::now();
    let mut nova = params.initial_nova(z_0).unwrap();

    for step in 0..n_steps {
        let base = step * B_SCAN;
        let mut sources = [Fr::ZERO; B_SCAN];
        let mut valids = [false; B_SCAN];
        for j in 0..B_SCAN {
            let idx = base + j;
            if idx < n_sources {
                sources[j] = Fr::from((offset + idx + 1) as u64 * 100);
                valids[j] = true;
            }
        }
        let ext = ScanExternalInputs { sources, valids, is_final: false };
        nova.prove_step(&mut *rng, ext, None).unwrap();
    }

    let elapsed = start.elapsed().as_secs_f64() * 1000.0;

    // Verify
    let ivc_proof = nova.ivc_proof();
    params.verify(ivc_proof).unwrap();

    elapsed
}

fn run_merge2(
    params: &NovaParams<MC>,
    rng: &mut StdRng,
    union_size: usize,
) -> f64 {
    let mut z_0 = vec![Fr::ZERO; D + 5];
    z_0[D + 3] = Fr::from(999u64);

    let n_steps = (union_size + B_MERGE - 1) / B_MERGE;
    let start = Instant::now();
    let mut nova = params.initial_nova(z_0).unwrap();

    for step in 0..n_steps {
        let base = step * B_MERGE;
        let mut has_a = [false; B_MERGE];
        let mut val_a = [Fr::ZERO; B_MERGE];
        let has_b = [false; B_MERGE];
        let val_b = [Fr::ZERO; B_MERGE];
        for j in 0..B_MERGE {
            let idx = base + j;
            if idx < union_size {
                has_a[j] = true;
                val_a[j] = Fr::from((idx + 1) as u64 * 100);
            }
        }
        let ext = Merge2ExternalInputs { has_a, val_a, has_b, val_b, is_final: false };
        nova.prove_step(&mut *rng, ext, None).unwrap();
    }

    let elapsed = start.elapsed().as_secs_f64() * 1000.0;

    let ivc_proof = nova.ivc_proof();
    params.verify(ivc_proof).unwrap();

    elapsed
}

#[test]
fn bench_e2e_full_merge() {
    let mut rng = StdRng::seed_from_u64(42);
    let poseidon_config = nova_poseidon_config();

    // Setup both circuits (one-time)
    println!("\n  === End-to-End: SCAN_A + SCAN_B + MERGE2 (B=32, D=10) ===\n");

    print!("  Setting up SCAN circuit...");
    let scan_setup_start = Instant::now();
    let scan_params = NovaParams::<SC>::rand(poseidon_config.clone(), &mut rng).unwrap();
    println!(" {:.1}s", scan_setup_start.elapsed().as_secs_f64());

    print!("  Setting up MERGE2 circuit...");
    let merge_setup_start = Instant::now();
    let merge_params = NovaParams::<MC>::rand(poseidon_config, &mut rng).unwrap();
    println!(" {:.1}s", merge_setup_start.elapsed().as_secs_f64());

    println!();
    println!("  +----------+----------+----------+----------+----------+----------+----------+");
    println!("  | Union sz | N_a+N_b  | SCAN_A   | SCAN_B   | MERGE2   | Total    | Verify   |");
    println!("  +----------+----------+----------+----------+----------+----------+----------+");

    for &total_sources in &[64usize, 128, 256, 512, 1024] {
        let n_a = total_sources / 2;
        let n_b = total_sources - n_a; // handles odd

        let total_start = Instant::now();

        let scan_a_ms = run_scan(&scan_params, &mut rng, n_a, 0);
        let scan_b_ms = run_scan(&scan_params, &mut rng, n_b, n_a);
        let merge_ms = run_merge2(&merge_params, &mut rng, total_sources);

        let total_ms = total_start.elapsed().as_secs_f64() * 1000.0;

        // Verification is already done inside run_scan/run_merge2.
        // The "verify" column shows the overhead beyond prove.
        let prove_total = scan_a_ms + scan_b_ms + merge_ms;
        let verify_overhead = total_ms - prove_total;

        println!(
            "  | {:>8} | {:>3}+{:<4} | {:>7.1}s | {:>7.1}s | {:>7.1}s | {:>7.1}s | {:>7.0}ms |",
            total_sources,
            n_a, n_b,
            scan_a_ms / 1000.0,
            scan_b_ms / 1000.0,
            merge_ms / 1000.0,
            prove_total / 1000.0,
            verify_overhead,
        );
    }

    println!("  +----------+----------+----------+----------+----------+----------+----------+");
    println!("  (ScanStepCircuit + Merge2StepCircuit, B=32, D=10, Nova on BN254/Grumpkin)");
    println!("  2-input transfer: each note has N/2 sources, union = N (worst case, no overlap)");
    println!();
}
