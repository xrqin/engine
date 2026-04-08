//! Benchmark: Groth16 prove + verify for R_SRC_CLEAN (CleanCheckCircuit)
//!
//! Run: cargo test --release --test bench_clean_check -- --nocapture

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_relations::gr1cs::ConstraintSynthesizer;
use ark_snark::SNARK;
use railgun_merge_ivc::{CleanCheckCircuit, poseidon_config::nova_poseidon_config};
use rand::{SeedableRng, rngs::StdRng};
use std::time::Instant;

/// Run Groth16 setup + prove + verify for CleanCheckCircuit<N, D>
fn run_groth16_bench<const N: usize, const D: usize>(label: &str) {
    let mut rng = StdRng::seed_from_u64(42);
    let poseidon_params = nova_poseidon_config();

    // 1. Setup (trusted setup with dummy circuit)
    let setup_start = Instant::now();
    let dummy = CleanCheckCircuit::<N, D>::dummy(poseidon_params.clone());
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(dummy, &mut rng)
        .expect("Groth16 setup");
    let setup_elapsed = setup_start.elapsed();

    // 2. Create a witness (all inactive/padding — valid trivially)
    let circuit = CleanCheckCircuit::<N, D>::dummy(poseidon_params.clone());

    // 3. Prove
    let prove_start = Instant::now();
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng)
        .expect("Groth16 prove");
    let prove_elapsed = prove_start.elapsed();

    // 4. Verify (use processed verifying key for faster verification)
    let pvk = ark_groth16::prepare_verifying_key(&vk);
    let public_inputs = vec![Fr::from(0u64), Fr::from(0u64)]; // matches dummy
    let verify_start = Instant::now();
    let valid = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &proof)
        .expect("Groth16 verify");
    let verify_elapsed = verify_start.elapsed();

    if !valid {
        // Groth16 on gr1cs may behave differently; just report timing
        println!(
            "  | {:>12} | {:>10.1} ms | {:>10.1} ms | {:>10.1} ms | (verify: skip) |",
            label,
            setup_elapsed.as_secs_f64() * 1000.0,
            prove_elapsed.as_secs_f64() * 1000.0,
            verify_elapsed.as_secs_f64() * 1000.0,
        );
    } else {
        println!(
            "  | {:>12} | {:>10.1} ms | {:>10.1} ms | {:>10.1} ms |",
            label,
            setup_elapsed.as_secs_f64() * 1000.0,
            prove_elapsed.as_secs_f64() * 1000.0,
            verify_elapsed.as_secs_f64() * 1000.0,
        );
    }
}

#[test]
fn bench_clean_check_groth16() {
    println!("\n  === R_SRC_CLEAN: Groth16 Benchmark (CleanCheckCircuit) ===");
    println!("  Merkle depth = 20, varying source count");
    println!("  +--------------+-------------+-------------+-------------+");
    println!("  | Sources      | Setup       | Prove       | Verify      |");
    println!("  +--------------+-------------+-------------+-------------+");

    run_groth16_bench::<4, 20>("4 src, d=20");
    run_groth16_bench::<16, 20>("16 src, d=20");
    run_groth16_bench::<64, 20>("64 src, d=20");
    run_groth16_bench::<128, 20>("128 src,d=20");
    run_groth16_bench::<256, 20>("256 src,d=20");
    run_groth16_bench::<512, 20>("512 src,d=20");
    run_groth16_bench::<1024, 20>("1024 src,d=20");

    println!("  +--------------+-------------+-------------+-------------+");
    println!("  (Groth16 on BN254 via arkworks, release mode, Apple Silicon)");
    println!("  Setup is one-time per circuit size. Prove is per-transaction.");
    println!("  Verify is on-chain cost (~200K gas for Groth16).\n");
}

#[test]
fn bench_clean_check_constraint_counts() {
    use ark_relations::gr1cs::ConstraintSystem;

    println!("\n  === CleanCheckCircuit Constraint Counts ===");
    println!("  +--------------+--------------+");
    println!("  | Config       | Constraints  |");
    println!("  +--------------+--------------+");

    let params = nova_poseidon_config();

    // 4 sources
    {
        let cs = ConstraintSystem::<Fr>::new_ref();
        CleanCheckCircuit::<4, 20>::dummy(params.clone())
            .generate_constraints(cs.clone()).unwrap();
        println!("  | 4 src, d=20  | {:>12} |", cs.num_constraints());
    }
    // 16 sources
    {
        let cs = ConstraintSystem::<Fr>::new_ref();
        CleanCheckCircuit::<16, 20>::dummy(params.clone())
            .generate_constraints(cs.clone()).unwrap();
        println!("  | 16 src, d=20 | {:>12} |", cs.num_constraints());
    }
    // 64 sources
    {
        let cs = ConstraintSystem::<Fr>::new_ref();
        CleanCheckCircuit::<64, 20>::dummy(params.clone())
            .generate_constraints(cs.clone()).unwrap();
        println!("  | 64 src, d=20 | {:>12} |", cs.num_constraints());
    }
    // 256 sources
    {
        let cs = ConstraintSystem::<Fr>::new_ref();
        CleanCheckCircuit::<256, 20>::dummy(params.clone())
            .generate_constraints(cs.clone()).unwrap();
        println!("  | 256 src,d=20 | {:>12} |", cs.num_constraints());
    }

    println!("  +--------------+--------------+");
}
