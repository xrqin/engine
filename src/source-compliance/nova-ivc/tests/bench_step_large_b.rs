//! Benchmark: B=128,256 step sizes to find the inflection point
//!
//! Run: cargo test --release --test bench_step_large_b -- --nocapture

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

fn run_scan<const B: usize>(n_sources: usize) {
    let mut rng = StdRng::seed_from_u64(42);
    let poseidon_config = nova_poseidon_config();

    // Constraint count
    let circuit = ScanStepCircuit::<Fr, 10, B>::new(poseidon_config.clone()).unwrap();
    let cs = ConstraintSystem::<Fr>::new_ref();
    let z_i: Vec<_> = (0..circuit.state_len())
        .map(|_| FpVar::new_witness(cs.clone(), || Ok(Fr::ZERO)).unwrap())
        .collect();
    let ext = ScanExternalInputs::<Fr, B>::default();
    let ext_var = <ScanExternalInputsVar<Fr, B> as AllocVar<_, _>>::new_variable(
        cs.clone(), || Ok(&ext), ark_r1cs_std::alloc::AllocationMode::Witness,
    ).unwrap();
    let _ = circuit.generate_step_constraints(cs.clone(), 0, z_i, ext_var).unwrap();
    let constraints = cs.num_constraints();

    // Nova IVC
    let setup_start = Instant::now();
    let params = NovaParams::<ScanStepCircuit<Fr, 10, B>>::rand(poseidon_config, &mut rng).unwrap();
    let setup_ms = setup_start.elapsed().as_secs_f64() * 1000.0;

    let mut z_0 = vec![Fr::ZERO; 15];
    z_0[13] = Fr::from(999u64);

    let n_steps = (n_sources + B - 1) / B;

    let prove_start = Instant::now();
    let mut nova = params.initial_nova(z_0).unwrap();
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
        let ext = ScanExternalInputs::<Fr, B> {
            sources: sources.try_into().unwrap(),
            valids: valids.try_into().unwrap(),
            is_final: false,
        };
        nova.prove_step(&mut rng, ext, None).unwrap();
    }
    let prove_ms = prove_start.elapsed().as_secs_f64() * 1000.0;

    let ivc_proof = nova.ivc_proof();
    let verify_start = Instant::now();
    params.verify(ivc_proof).unwrap();
    let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;

    println!(
        "  | SCAN  | B={:<4}| {:>6}K | {:>3} | {:>8.0} | {:>8.0} | {:>7.0} | {:>7.0} |",
        B, constraints / 1000, n_steps, setup_ms, prove_ms, verify_ms,
        prove_ms / n_steps as f64,
    );
}

fn run_merge2<const B: usize>(union_size: usize) {
    let mut rng = StdRng::seed_from_u64(42);
    let poseidon_config = nova_poseidon_config();

    // Constraint count
    let circuit = Merge2StepCircuit::<Fr, 10, B>::new(poseidon_config.clone()).unwrap();
    let cs = ConstraintSystem::<Fr>::new_ref();
    let z_i: Vec<_> = (0..circuit.state_len())
        .map(|_| FpVar::new_witness(cs.clone(), || Ok(Fr::ZERO)).unwrap())
        .collect();
    let ext = Merge2ExternalInputs::<Fr, B>::default();
    let ext_var = <Merge2ExternalInputsVar<Fr, B> as AllocVar<_, _>>::new_variable(
        cs.clone(), || Ok(&ext), ark_r1cs_std::alloc::AllocationMode::Witness,
    ).unwrap();
    let _ = circuit.generate_step_constraints(cs.clone(), 0, z_i, ext_var).unwrap();
    let constraints = cs.num_constraints();

    // Nova IVC
    let setup_start = Instant::now();
    let params = NovaParams::<Merge2StepCircuit<Fr, 10, B>>::rand(poseidon_config, &mut rng).unwrap();
    let setup_ms = setup_start.elapsed().as_secs_f64() * 1000.0;

    let mut z_0 = vec![Fr::ZERO; 15];
    z_0[13] = Fr::from(999u64);

    let n_steps = (union_size + B - 1) / B;

    let prove_start = Instant::now();
    let mut nova = params.initial_nova(z_0).unwrap();
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
        nova.prove_step(&mut rng, ext, None).unwrap();
    }
    let prove_ms = prove_start.elapsed().as_secs_f64() * 1000.0;

    let ivc_proof = nova.ivc_proof();
    let verify_start = Instant::now();
    params.verify(ivc_proof).unwrap();
    let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;

    println!(
        "  | MERGE | B={:<4}| {:>6}K | {:>3} | {:>8.0} | {:>8.0} | {:>7.0} | {:>7.0} |",
        B, constraints / 1000, n_steps, setup_ms, prove_ms, verify_ms,
        prove_ms / n_steps as f64,
    );
}

#[test]
fn bench_large_b_scan() {
    println!("\n  === SCAN: 256 sources, varying B ===");
    println!("  +-------+------+---------+-----+----------+----------+---------+---------+");
    println!("  | Mode  |  B   | Constr  | Stp | Setup ms | Prove ms | Vfy ms  | ms/step |");
    println!("  +-------+------+---------+-----+----------+----------+---------+---------+");
    run_scan::<32>(256);
    run_scan::<64>(256);
    run_scan::<128>(256);
    run_scan::<256>(256);
    println!("  +-------+------+---------+-----+----------+----------+---------+---------+");
}

#[test]
fn bench_large_b_merge2() {
    println!("\n  === MERGE2: 256 union, varying B ===");
    println!("  +-------+------+---------+-----+----------+----------+---------+---------+");
    println!("  | Mode  |  B   | Constr  | Stp | Setup ms | Prove ms | Vfy ms  | ms/step |");
    println!("  +-------+------+---------+-----+----------+----------+---------+---------+");
    run_merge2::<32>(256);
    run_merge2::<64>(256);
    run_merge2::<128>(256);
    run_merge2::<256>(256);
    println!("  +-------+------+---------+-----+----------+----------+---------+---------+");
}
