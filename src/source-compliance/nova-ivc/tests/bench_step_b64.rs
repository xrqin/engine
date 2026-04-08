//! Benchmark: B=64 step size for SCAN and MERGE2
//!
//! Run: cargo test --release --test bench_step_b64 -- --nocapture

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

#[test]
fn bench_b64_constraint_counts() {
    let poseidon_config = nova_poseidon_config();

    // SCAN B=64
    {
        let circuit = ScanStepCircuit::<Fr, 10, 64>::new(poseidon_config.clone()).unwrap();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let z_i: Vec<_> = (0..circuit.state_len())
            .map(|_| FpVar::new_witness(cs.clone(), || Ok(Fr::ZERO)).unwrap())
            .collect();
        let ext = ScanExternalInputs::<Fr, 64>::default();
        let ext_var = <ScanExternalInputsVar<Fr, 64> as AllocVar<_, _>>::new_variable(
            cs.clone(), || Ok(&ext), ark_r1cs_std::alloc::AllocationMode::Witness,
        ).unwrap();
        let _ = circuit.generate_step_constraints(cs.clone(), 0, z_i, ext_var).unwrap();
        println!("  SCAN  B=64: {} constraints", cs.num_constraints());
    }

    // MERGE2 B=64
    {
        let circuit = Merge2StepCircuit::<Fr, 10, 64>::new(poseidon_config.clone()).unwrap();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let z_i: Vec<_> = (0..circuit.state_len())
            .map(|_| FpVar::new_witness(cs.clone(), || Ok(Fr::ZERO)).unwrap())
            .collect();
        let ext = Merge2ExternalInputs::<Fr, 64>::default();
        let ext_var = <Merge2ExternalInputsVar<Fr, 64> as AllocVar<_, _>>::new_variable(
            cs.clone(), || Ok(&ext), ark_r1cs_std::alloc::AllocationMode::Witness,
        ).unwrap();
        let _ = circuit.generate_step_constraints(cs.clone(), 0, z_i, ext_var).unwrap();
        println!("  MERGE B=64: {} constraints", cs.num_constraints());
    }
}

#[test]
fn bench_scan_b64() {
    let mut rng = StdRng::seed_from_u64(42);
    let poseidon_config = nova_poseidon_config();

    let setup_start = Instant::now();
    let params = NovaParams::<ScanStepCircuit<Fr, 10, 64>>::rand(poseidon_config, &mut rng).unwrap();
    let setup_ms = setup_start.elapsed().as_secs_f64() * 1000.0;

    let mut z_0 = vec![Fr::ZERO; 15];
    z_0[13] = Fr::from(999u64);

    let n_sources = 256usize;
    let n_steps = (n_sources + 63) / 64; // = 4

    let prove_start = Instant::now();
    let mut nova = params.initial_nova(z_0).unwrap();

    for step in 0..n_steps {
        let base = step * 64;
        let mut sources = [Fr::ZERO; 64];
        let mut valids = [false; 64];
        for j in 0..64 {
            let idx = base + j;
            if idx < n_sources {
                sources[j] = Fr::from((idx + 1) as u64 * 100);
                valids[j] = true;
            }
        }
        let ext = ScanExternalInputs { sources, valids, is_final: false };
        nova.prove_step(&mut rng, ext, None).unwrap();
    }
    let prove_ms = prove_start.elapsed().as_secs_f64() * 1000.0;

    let ivc_proof = nova.ivc_proof();
    let verify_start = Instant::now();
    params.verify(ivc_proof).unwrap();
    let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;

    println!(
        "  SCAN  B=64 | 256 src | {} steps | setup {:.0}ms | prove {:.0}ms | verify {:.0}ms | {:.0}ms/step",
        n_steps, setup_ms, prove_ms, verify_ms, prove_ms / n_steps as f64,
    );
}

#[test]
fn bench_merge2_b64() {
    let mut rng = StdRng::seed_from_u64(42);
    let poseidon_config = nova_poseidon_config();

    let setup_start = Instant::now();
    let params = NovaParams::<Merge2StepCircuit<Fr, 10, 64>>::rand(poseidon_config, &mut rng).unwrap();
    let setup_ms = setup_start.elapsed().as_secs_f64() * 1000.0;

    let mut z_0 = vec![Fr::ZERO; 15];
    z_0[13] = Fr::from(999u64);

    let union_size = 256usize;
    let n_steps = (union_size + 63) / 64; // = 4

    let prove_start = Instant::now();
    let mut nova = params.initial_nova(z_0).unwrap();

    for step in 0..n_steps {
        let base = step * 64;
        let mut has_a = [false; 64];
        let mut val_a = [Fr::ZERO; 64];
        let has_b = [false; 64];
        let val_b = [Fr::ZERO; 64];
        for j in 0..64 {
            let idx = base + j;
            if idx < union_size {
                has_a[j] = true;
                val_a[j] = Fr::from((idx + 1) as u64 * 100);
            }
        }
        let ext = Merge2ExternalInputs { has_a, val_a, has_b, val_b, is_final: false };
        nova.prove_step(&mut rng, ext, None).unwrap();
    }
    let prove_ms = prove_start.elapsed().as_secs_f64() * 1000.0;

    let ivc_proof = nova.ivc_proof();
    let verify_start = Instant::now();
    params.verify(ivc_proof).unwrap();
    let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;

    println!(
        "  MERGE B=64 | 256 uni | {} steps | setup {:.0}ms | prove {:.0}ms | verify {:.0}ms | {:.0}ms/step",
        n_steps, setup_ms, prove_ms, verify_ms, prove_ms / n_steps as f64,
    );
}
