//! End-to-end benchmark: 4-way parallel (SCAN_A ∥ SCAN_B ∥ MERGE2 ∥ CLEAN_CHECK)
//!
//! Run: cargo test --release --test bench_e2e_parallel -- --nocapture

use ark_bn254::Fr;
use ark_ff::AdditiveGroup;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::gr1cs::ConstraintSystem;
use folding_schemes::{frontend::FCircuit, FoldingScheme};
use railgun_merge_ivc::{
    NovaParams,
    poseidon_config::nova_poseidon_config,
    scan_step_circuit::{ScanExternalInputs, ScanStepCircuit},
    merge2_step_circuit::{Merge2ExternalInputs, Merge2StepCircuit},
    clean_check_step_circuit::{CleanCheckStepInputs, CleanCheckStepCircuit, CleanCheckStepInputsVar},
};
use rand::{SeedableRng, rngs::StdRng};
use std::time::Instant;

const D: usize = 10;
const B_SCAN: usize = 32;
const B_MERGE: usize = 32;
const B_CLEAN: usize = 32;
const DEPTH: usize = 20;

type SC = ScanStepCircuit<Fr, D, B_SCAN>;
type MC = Merge2StepCircuit<Fr, D, B_MERGE>;
type CC = CleanCheckStepCircuit<Fr, B_CLEAN>;

/// Measure CleanCheckStepCircuit constraint count
#[test]
fn bench_clean_check_step_constraints() {
    let poseidon_config = nova_poseidon_config();
    let circuit = CC::new(poseidon_config).unwrap();
    let cs = ConstraintSystem::<Fr>::new_ref();

    let z_i: Vec<_> = (0..circuit.state_len())
        .map(|_| FpVar::new_witness(cs.clone(), || Ok(Fr::ZERO)).unwrap())
        .collect();
    let ext = CleanCheckStepInputs::<Fr, B_CLEAN>::default();
    let ext_var = <CleanCheckStepInputsVar<Fr, B_CLEAN> as AllocVar<_, _>>::new_variable(
        cs.clone(), || Ok(&ext), ark_r1cs_std::alloc::AllocationMode::Witness,
    ).unwrap();
    let _ = circuit.generate_step_constraints(cs.clone(), 0, z_i, ext_var).unwrap();

    println!("\n  CleanCheckStepCircuit<B={}, DEPTH={}> constraints: {}", B_CLEAN, DEPTH, cs.num_constraints());
    println!("  (satisfied: {})", cs.is_satisfied().unwrap());
}

fn run_scan(params: &NovaParams<SC>, rng: &mut StdRng, n_sources: usize, offset: usize) -> f64 {
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
        nova.prove_step(&mut *rng, ScanExternalInputs { sources, valids, is_final: false }, None).unwrap();
    }
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    let ivc = nova.ivc_proof();
    params.verify(ivc).unwrap();
    elapsed
}

fn run_merge2(params: &NovaParams<MC>, rng: &mut StdRng, union_size: usize) -> f64 {
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
        nova.prove_step(&mut *rng, Merge2ExternalInputs { has_a, val_a, has_b, val_b, is_final: false }, None).unwrap();
    }
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    let ivc = nova.ivc_proof();
    params.verify(ivc).unwrap();
    elapsed
}

fn run_clean_check(params: &NovaParams<CC>, rng: &mut StdRng, n_sources: usize) -> f64 {
    let z_0 = vec![Fr::from(12345u64), Fr::ZERO, Fr::ZERO]; // [clean_root, checked, ok]
    let n_steps = (n_sources + B_CLEAN - 1) / B_CLEAN;
    let start = Instant::now();
    let mut nova = params.initial_nova(z_0).unwrap();
    for step in 0..n_steps {
        let base = step * B_CLEAN;
        let mut sources = [Fr::ZERO; B_CLEAN];
        let mut actives = [false; B_CLEAN];
        let mut siblings = vec![Fr::ZERO; B_CLEAN * DEPTH];
        let mut directions = vec![false; B_CLEAN * DEPTH];
        for j in 0..B_CLEAN {
            let idx = base + j;
            if idx < n_sources {
                sources[j] = Fr::from((idx + 1) as u64 * 100);
                actives[j] = false; // inactive = skip membership check (dummy data)
            }
        }
        nova.prove_step(
            &mut *rng,
            CleanCheckStepInputs { sources, actives, siblings, directions },
            None,
        ).unwrap();
    }
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    let ivc = nova.ivc_proof();
    params.verify(ivc).unwrap();
    elapsed
}

#[test]
fn bench_e2e_4way_parallel() {
    let mut rng = StdRng::seed_from_u64(42);
    let poseidon_config = nova_poseidon_config();

    println!("\n  === 4-Way Parallel: SCAN_A ∥ SCAN_B ∥ MERGE2 ∥ CLEAN_CHECK (B=32) ===\n");

    print!("  Setup SCAN...");
    let t = Instant::now();
    let scan_params = NovaParams::<SC>::rand(poseidon_config.clone(), &mut rng).unwrap();
    println!(" {:.1}s", t.elapsed().as_secs_f64());

    print!("  Setup MERGE2...");
    let t = Instant::now();
    let merge_params = NovaParams::<MC>::rand(poseidon_config.clone(), &mut rng).unwrap();
    println!(" {:.1}s", t.elapsed().as_secs_f64());

    print!("  Setup CLEAN_CHECK...");
    let t = Instant::now();
    let clean_params = NovaParams::<CC>::rand(poseidon_config, &mut rng).unwrap();
    println!(" {:.1}s", t.elapsed().as_secs_f64());

    println!();
    println!("  +------+--------+--------+--------+----------+----------+---------+");
    println!("  | Srcs | SCAN_A | SCAN_B | MERGE2 | CLEAN_CK | 4way max | Verify  |");
    println!("  +------+--------+--------+--------+----------+----------+---------+");

    for &total in &[64usize, 128, 256, 512, 1024] {
        let n_a = total / 2;
        let n_b = total - n_a;

        let total_start = Instant::now();

        let sa = run_scan(&scan_params, &mut rng, n_a, 0);
        let sb = run_scan(&scan_params, &mut rng, n_b, n_a);
        let mg = run_merge2(&merge_params, &mut rng, total);
        let cc = run_clean_check(&clean_params, &mut rng, total);

        let total_wall = total_start.elapsed().as_secs_f64() * 1000.0;
        let four_way = sa.max(sb).max(mg).max(cc);
        let verify_overhead = total_wall - sa - sb - mg - cc;

        println!(
            "  | {:>4} | {:>5.1}s | {:>5.1}s | {:>5.1}s | {:>7.1}s | {:>7.1}s | {:>5.0}ms |",
            total,
            sa / 1000.0, sb / 1000.0, mg / 1000.0, cc / 1000.0,
            four_way / 1000.0,
            verify_overhead.max(0.0),
        );
    }

    println!("  +------+--------+--------+--------+----------+----------+---------+");
    println!("  4way max = max(SCAN_A, SCAN_B, MERGE2, CLEAN_CHECK)");
    println!("  All proofs independent, can run on 4 cores in parallel.");
    println!("  Verify = 4 × Nova IVC verify (~400ms total).");
    println!();
}
