//! Benchmark: ScanStepCircuit and Merge2StepCircuit via Nova IVC
//!
//! Run: cargo test --release --test bench_scan_merge2 -- --nocapture

use ark_bn254::Fr;
use ark_ff::AdditiveGroup;
use ark_relations::gr1cs::ConstraintSystem;
use folding_schemes::FoldingScheme;
use railgun_merge_ivc::{
    NovaParams,
    poseidon_config::nova_poseidon_config,
    scan_step_circuit::{ScanExternalInputs, ScanStepCircuit},
    merge2_step_circuit::{Merge2ExternalInputs, Merge2StepCircuit},
};
use rand::{SeedableRng, rngs::StdRng};
use std::time::Instant;

/// Measure constraint count for ScanStepCircuit.
#[test]
fn bench_scan_constraint_count() {
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
    use folding_schemes::frontend::FCircuit;

    let poseidon_config = nova_poseidon_config();

    // D=10, B=8 (standard params)
    type ScanCircuit = ScanStepCircuit<Fr, 10, 8>;
    let circuit = ScanCircuit::new(poseidon_config.clone()).unwrap();

    let cs = ConstraintSystem::<Fr>::new_ref();
    let state_len = circuit.state_len(); // D + 5 = 15

    // Create dummy z_i
    let z_i: Vec<_> = (0..state_len)
        .map(|_| FpVar::new_witness(cs.clone(), || Ok(Fr::ZERO)).unwrap())
        .collect();

    // Create dummy external inputs
    let ext = ScanExternalInputs::<Fr, 8>::default();
    let ext_var = <railgun_merge_ivc::scan_step_circuit::ScanExternalInputsVar<Fr, 8>
        as ark_r1cs_std::alloc::AllocVar<_, _>>::new_variable(
        cs.clone(),
        || Ok(&ext),
        ark_r1cs_std::alloc::AllocationMode::Witness,
    )
    .unwrap();

    let _z_out = circuit
        .generate_step_constraints(cs.clone(), 0, z_i, ext_var)
        .unwrap();

    println!(
        "\n  ScanStepCircuit<D=10, B=8> constraints: {}",
        cs.num_constraints()
    );
    println!("  (satisfied: {})", cs.is_satisfied().unwrap());
}

/// Measure constraint count for Merge2StepCircuit.
#[test]
fn bench_merge2_constraint_count() {
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
    use folding_schemes::frontend::FCircuit;

    let poseidon_config = nova_poseidon_config();

    type Merge2Circuit = Merge2StepCircuit<Fr, 10, 4>;
    let circuit = Merge2Circuit::new(poseidon_config.clone()).unwrap();

    let cs = ConstraintSystem::<Fr>::new_ref();
    let state_len = circuit.state_len();

    let z_i: Vec<_> = (0..state_len)
        .map(|_| FpVar::new_witness(cs.clone(), || Ok(Fr::ZERO)).unwrap())
        .collect();

    let ext = Merge2ExternalInputs::<Fr, 4>::default();
    let ext_var = <railgun_merge_ivc::merge2_step_circuit::Merge2ExternalInputsVar<Fr, 4>
        as ark_r1cs_std::alloc::AllocVar<_, _>>::new_variable(
        cs.clone(),
        || Ok(&ext),
        ark_r1cs_std::alloc::AllocationMode::Witness,
    )
    .unwrap();

    let _z_out = circuit
        .generate_step_constraints(cs.clone(), 0, z_i, ext_var)
        .unwrap();

    println!(
        "\n  Merge2StepCircuit<D=10, B=4> constraints: {}",
        cs.num_constraints()
    );
    println!("  (satisfied: {})", cs.is_satisfied().unwrap());
}

/// Nova IVC benchmark for ScanStepCircuit.
#[test]
fn bench_scan_nova_ivc() {
    type ScanCircuit = ScanStepCircuit<Fr, 10, 8>;

    let mut rng = StdRng::seed_from_u64(42);
    let poseidon_config = nova_poseidon_config();

    println!("\n  === SCAN Nova IVC Setup ===");
    let setup_start = Instant::now();
    let params = NovaParams::<ScanCircuit>::rand(poseidon_config, &mut rng)
        .expect("Nova setup");
    println!("  Setup time: {:.2} ms", setup_start.elapsed().as_secs_f64() * 1000.0);

    // State: frontier[10] + count + last + has_last + target_root + target_count
    // Initialize with all zeros; target_root/count will be checked on final step only
    let mut z_0 = vec![Fr::ZERO; 15]; // D(10) + 5
    // Set target_root and target_count to dummy values (not checked unless is_final=true)
    z_0[13] = Fr::from(999u64); // target_root placeholder
    z_0[14] = Fr::from(0u64);   // target_count (will be updated externally)

    println!("\n  === SCAN Nova IVC Benchmark ===");
    println!("  D=10, B_SCAN=8 sources/step");
    println!("  +----------+-------+---------------+---------------+-----------------+");
    println!("  | Sources  | Steps | IVC Prove     | IVC Verify    | Per-Step Cost   |");
    println!("  +----------+-------+---------------+---------------+-----------------+");

    for &(n_sources, label) in &[
        (8usize,   "8"),
        (32,  "32"),
        (64,  "64"),
        (128, "128"),
        (256, "256"),
    ] {
        let n_steps = (n_sources + 7) / 8; // ceil(n_sources / B_SCAN)

        let prove_start = Instant::now();
        let mut nova = params.initial_nova(z_0.clone()).expect("Nova init");

        for step in 0..n_steps {
            let is_last = step == n_steps - 1;
            let base = step * 8;
            let mut sources = [Fr::ZERO; 8];
            let mut valids = [false; 8];
            for j in 0..8 {
                let idx = base + j;
                if idx < n_sources {
                    sources[j] = Fr::from((idx + 1) as u64 * 100); // sorted, unique
                    valids[j] = true;
                }
            }
            let ext = ScanExternalInputs {
                sources,
                valids,
                is_final: false, // Don't check target (we'd need correct target for that)
            };
            nova.prove_step(&mut rng, ext, None)
                .unwrap_or_else(|e| panic!("scan prove_step[{}]: {}", step, e));
        }
        let prove_elapsed = prove_start.elapsed();

        let ivc_proof = nova.ivc_proof();
        let verify_start = Instant::now();
        params.verify(ivc_proof).expect("IVC verify");
        let verify_elapsed = verify_start.elapsed();

        println!(
            "  | {:>8} | {:>5} | {:>11.2} ms | {:>11.2} ms | {:>8.2} ms/step |",
            label,
            n_steps,
            prove_elapsed.as_secs_f64() * 1000.0,
            verify_elapsed.as_secs_f64() * 1000.0,
            prove_elapsed.as_secs_f64() * 1000.0 / n_steps as f64,
        );
    }

    println!("  +----------+-------+---------------+---------------+-----------------+");
    println!("  (ScanStepCircuit<D=10, B=8> via Nova on BN254/Grumpkin, release mode)\n");
}

/// Nova IVC benchmark for Merge2StepCircuit.
#[test]
fn bench_merge2_nova_ivc() {
    type Merge2Circuit = Merge2StepCircuit<Fr, 10, 4>;

    let mut rng = StdRng::seed_from_u64(42);
    let poseidon_config = nova_poseidon_config();

    println!("\n  === MERGE2 Nova IVC Setup ===");
    let setup_start = Instant::now();
    let params = NovaParams::<Merge2Circuit>::rand(poseidon_config, &mut rng)
        .expect("Nova setup");
    println!("  Setup time: {:.2} ms", setup_start.elapsed().as_secs_f64() * 1000.0);

    let mut z_0 = vec![Fr::ZERO; 15]; // D(10) + 5
    z_0[13] = Fr::from(999u64);
    z_0[14] = Fr::from(0u64);

    println!("\n  === MERGE2 Nova IVC Benchmark ===");
    println!("  D=10, B_MERGE=4 micro-merges/step");
    println!("  +----------+-------+---------------+---------------+-----------------+");
    println!("  | Union sz | Steps | IVC Prove     | IVC Verify    | Per-Step Cost   |");
    println!("  +----------+-------+---------------+---------------+-----------------+");

    for &(union_size, label) in &[
        (8usize,   "8"),
        (32,  "32"),
        (64,  "64"),
        (128, "128"),
        (256, "256"),
    ] {
        let n_steps = (union_size + 3) / 4; // ceil(union_size / B_MERGE)

        let prove_start = Instant::now();
        let mut nova = params.initial_nova(z_0.clone()).expect("Nova init");

        for step in 0..n_steps {
            let base = step * 4;
            let mut has_a = [false; 4];
            let mut val_a = [Fr::ZERO; 4];
            let mut has_b = [false; 4];
            let mut val_b = [Fr::ZERO; 4];

            for j in 0..4 {
                let idx = base + j;
                if idx < union_size {
                    // Simulate: all values come from stream A (simple case)
                    has_a[j] = true;
                    val_a[j] = Fr::from((idx + 1) as u64 * 100);
                }
            }

            let ext = Merge2ExternalInputs {
                has_a,
                val_a,
                has_b,
                val_b,
                is_final: false,
            };
            nova.prove_step(&mut rng, ext, None)
                .unwrap_or_else(|e| panic!("merge2 prove_step[{}]: {}", step, e));
        }
        let prove_elapsed = prove_start.elapsed();

        let ivc_proof = nova.ivc_proof();
        let verify_start = Instant::now();
        params.verify(ivc_proof).expect("IVC verify");
        let verify_elapsed = verify_start.elapsed();

        println!(
            "  | {:>8} | {:>5} | {:>11.2} ms | {:>11.2} ms | {:>8.2} ms/step |",
            label,
            n_steps,
            prove_elapsed.as_secs_f64() * 1000.0,
            verify_elapsed.as_secs_f64() * 1000.0,
            prove_elapsed.as_secs_f64() * 1000.0 / n_steps as f64,
        );
    }

    println!("  +----------+-------+---------------+---------------+-----------------+");
    println!("  (Merge2StepCircuit<D=10, B=4> via Nova on BN254/Grumpkin, release mode)\n");
}
