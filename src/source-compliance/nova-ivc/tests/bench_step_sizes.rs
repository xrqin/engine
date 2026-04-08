//! Benchmark: varying B_SCAN and B_MERGE step sizes
//!
//! Tests SCAN with B=8,16,32 and MERGE2 with B=4,8,16,32
//! All with D=10, targeting 256 sources to compare throughput.
//!
//! Run: cargo test --release --test bench_step_sizes -- --nocapture

use ark_bn254::Fr;
use ark_ff::AdditiveGroup;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::gr1cs::ConstraintSystem;
use folding_schemes::{frontend::FCircuit, FoldingScheme};
use railgun_merge_ivc::{
    NovaParams,
    poseidon_config::nova_poseidon_config,
    scan_step_circuit::{ScanExternalInputs, ScanStepCircuit, ScanExternalInputsVar},
    merge2_step_circuit::{Merge2ExternalInputs, Merge2StepCircuit, Merge2ExternalInputsVar},
};
use rand::{SeedableRng, rngs::StdRng};
use std::time::Instant;

// ============================================================
// Helper: measure constraint count for a given FCircuit
// ============================================================

fn count_scan_constraints<const D: usize, const B: usize>() -> usize {
    let poseidon_config = nova_poseidon_config();
    let circuit = ScanStepCircuit::<Fr, D, B>::new(poseidon_config).unwrap();
    let cs = ConstraintSystem::<Fr>::new_ref();
    let z_i: Vec<_> = (0..circuit.state_len())
        .map(|_| FpVar::new_witness(cs.clone(), || Ok(Fr::ZERO)).unwrap())
        .collect();
    let ext = ScanExternalInputs::<Fr, B>::default();
    let ext_var = <ScanExternalInputsVar<Fr, B> as AllocVar<_, _>>::new_variable(
        cs.clone(), || Ok(&ext), ark_r1cs_std::alloc::AllocationMode::Witness,
    ).unwrap();
    let _ = circuit.generate_step_constraints(cs.clone(), 0, z_i, ext_var).unwrap();
    cs.num_constraints()
}

fn count_merge2_constraints<const D: usize, const B: usize>() -> usize {
    let poseidon_config = nova_poseidon_config();
    let circuit = Merge2StepCircuit::<Fr, D, B>::new(poseidon_config).unwrap();
    let cs = ConstraintSystem::<Fr>::new_ref();
    let z_i: Vec<_> = (0..circuit.state_len())
        .map(|_| FpVar::new_witness(cs.clone(), || Ok(Fr::ZERO)).unwrap())
        .collect();
    let ext = Merge2ExternalInputs::<Fr, B>::default();
    let ext_var = <Merge2ExternalInputsVar<Fr, B> as AllocVar<_, _>>::new_variable(
        cs.clone(), || Ok(&ext), ark_r1cs_std::alloc::AllocationMode::Witness,
    ).unwrap();
    let _ = circuit.generate_step_constraints(cs.clone(), 0, z_i, ext_var).unwrap();
    cs.num_constraints()
}

// ============================================================
// Helper: run Nova IVC for SCAN with given B
// ============================================================

fn run_scan_bench<const D: usize, const B: usize>(n_sources: usize, label: &str) {
    type SC<const D2: usize, const B2: usize> = ScanStepCircuit<Fr, D2, B2>;

    let mut rng = StdRng::seed_from_u64(42);
    let poseidon_config = nova_poseidon_config();

    let setup_start = Instant::now();
    let params = NovaParams::<SC<D, B>>::rand(poseidon_config, &mut rng).expect("setup");
    let setup_ms = setup_start.elapsed().as_secs_f64() * 1000.0;

    let z_0 = {
        let mut v = vec![Fr::ZERO; D + 5];
        v[D + 3] = Fr::from(999u64);
        v
    };

    let n_steps = (n_sources + B - 1) / B;

    let prove_start = Instant::now();
    let mut nova = params.initial_nova(z_0).expect("init");

    for step in 0..n_steps {
        let base = step * B;
        let mut sources = vec![Fr::ZERO; B];
        let mut valids = vec![false; B];
        for j in 0..B {
            let idx = base + j;
            if idx < n_sources {
                sources[j] = Fr::from((idx + 1) as u64 * 100);
                valids[j] = true;
            }
        }
        // Convert to arrays
        let src_arr: [Fr; B] = sources.try_into().unwrap();
        let val_arr: [bool; B] = valids.try_into().unwrap();
        let ext = ScanExternalInputs::<Fr, B> {
            sources: src_arr,
            valids: val_arr,
            is_final: false,
        };
        nova.prove_step(&mut rng, ext, None)
            .unwrap_or_else(|e| panic!("step[{}]: {}", step, e));
    }
    let prove_ms = prove_start.elapsed().as_secs_f64() * 1000.0;

    let ivc_proof = nova.ivc_proof();
    let verify_start = Instant::now();
    params.verify(ivc_proof).expect("verify");
    let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;

    println!(
        "  | SCAN  | B={:<3} | {:>4} | {:>5} | {:>10.1} | {:>10.1} | {:>8.1} | {:>8.1} |",
        B, label, n_steps, setup_ms, prove_ms, verify_ms,
        prove_ms / n_steps as f64,
    );
}

fn run_merge2_bench<const D: usize, const B: usize>(union_size: usize, label: &str) {
    type MC<const D2: usize, const B2: usize> = Merge2StepCircuit<Fr, D2, B2>;

    let mut rng = StdRng::seed_from_u64(42);
    let poseidon_config = nova_poseidon_config();

    let setup_start = Instant::now();
    let params = NovaParams::<MC<D, B>>::rand(poseidon_config, &mut rng).expect("setup");
    let setup_ms = setup_start.elapsed().as_secs_f64() * 1000.0;

    let z_0 = {
        let mut v = vec![Fr::ZERO; D + 5];
        v[D + 3] = Fr::from(999u64);
        v
    };

    let n_steps = (union_size + B - 1) / B;

    let prove_start = Instant::now();
    let mut nova = params.initial_nova(z_0).expect("init");

    for step in 0..n_steps {
        let base = step * B;
        let mut has_a = vec![false; B];
        let mut val_a = vec![Fr::ZERO; B];
        let has_b = vec![false; B];
        let val_b = vec![Fr::ZERO; B];
        for j in 0..B {
            let idx = base + j;
            if idx < union_size {
                has_a[j] = true;
                val_a[j] = Fr::from((idx + 1) as u64 * 100);
            }
        }
        let ext = Merge2ExternalInputs::<Fr, B> {
            has_a: has_a.try_into().unwrap(),
            val_a: val_a.try_into().unwrap(),
            has_b: has_b.try_into().unwrap(),
            val_b: val_b.try_into().unwrap(),
            is_final: false,
        };
        nova.prove_step(&mut rng, ext, None)
            .unwrap_or_else(|e| panic!("step[{}]: {}", step, e));
    }
    let prove_ms = prove_start.elapsed().as_secs_f64() * 1000.0;

    let ivc_proof = nova.ivc_proof();
    let verify_start = Instant::now();
    params.verify(ivc_proof).expect("verify");
    let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;

    println!(
        "  | MERGE | B={:<3} | {:>4} | {:>5} | {:>10.1} | {:>10.1} | {:>8.1} | {:>8.1} |",
        B, label, n_steps, setup_ms, prove_ms, verify_ms,
        prove_ms / n_steps as f64,
    );
}

// ============================================================
// Constraint count comparison
// ============================================================

#[test]
fn bench_constraint_counts() {
    println!("\n  === Constraint Counts (D=10) ===");
    println!("  +-------+------+--------------+");
    println!("  | Mode  |  B   | Constraints  |");
    println!("  +-------+------+--------------+");
    println!("  | SCAN  |    8 | {:>12} |", count_scan_constraints::<10, 8>());
    println!("  | SCAN  |   16 | {:>12} |", count_scan_constraints::<10, 16>());
    println!("  | SCAN  |   32 | {:>12} |", count_scan_constraints::<10, 32>());
    println!("  | MERGE |    4 | {:>12} |", count_merge2_constraints::<10, 4>());
    println!("  | MERGE |    8 | {:>12} |", count_merge2_constraints::<10, 8>());
    println!("  | MERGE |   16 | {:>12} |", count_merge2_constraints::<10, 16>());
    println!("  | MERGE |   32 | {:>12} |", count_merge2_constraints::<10, 32>());
    println!("  +-------+------+--------------+");
}

// ============================================================
// Nova IVC: SCAN varying B, 256 sources
// ============================================================

#[test]
fn bench_scan_b8() { run_scan_bench::<10, 8>(256, "256"); }

#[test]
fn bench_scan_b16() { run_scan_bench::<10, 16>(256, "256"); }

#[test]
fn bench_scan_b32() { run_scan_bench::<10, 32>(256, "256"); }

// ============================================================
// Nova IVC: MERGE2 varying B, 256 union
// ============================================================

#[test]
fn bench_merge2_b4() { run_merge2_bench::<10, 4>(256, "256"); }

#[test]
fn bench_merge2_b8() { run_merge2_bench::<10, 8>(256, "256"); }

#[test]
fn bench_merge2_b16() { run_merge2_bench::<10, 16>(256, "256"); }

#[test]
fn bench_merge2_b32() { run_merge2_bench::<10, 32>(256, "256"); }
