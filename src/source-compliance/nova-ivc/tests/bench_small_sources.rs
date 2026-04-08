//! Benchmark: optimal B for small source counts (4-64)
//!
//! Run: cargo test --release --test bench_small_sources -- --nocapture

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

fn run_scan<const B: usize>(n_sources: usize, params: &NovaParams<ScanStepCircuit<Fr, D, B>>) -> f64 {
    let mut rng = StdRng::seed_from_u64(42 + n_sources as u64);
    let mut z_0 = vec![Fr::ZERO; D + 5];
    z_0[D + 3] = Fr::from(999u64);
    let n_steps = (n_sources + B - 1) / B;
    let start = Instant::now();
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
        nova.prove_step(
            &mut rng,
            ScanExternalInputs { sources: sources.try_into().unwrap(), valids: valids.try_into().unwrap(), is_final: false },
            None,
        ).unwrap();
    }
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    let ivc = nova.ivc_proof();
    params.verify(ivc).unwrap();
    elapsed
}

fn run_merge2<const B: usize>(union_size: usize, params: &NovaParams<Merge2StepCircuit<Fr, D, B>>) -> f64 {
    let mut rng = StdRng::seed_from_u64(42 + union_size as u64);
    let mut z_0 = vec![Fr::ZERO; D + 5];
    z_0[D + 3] = Fr::from(999u64);
    let n_steps = (union_size + B - 1) / B;
    let start = Instant::now();
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
        nova.prove_step(
            &mut rng,
            Merge2ExternalInputs { has_a: has_a.try_into().unwrap(), val_a: val_a.try_into().unwrap(), has_b: has_b.try_into().unwrap(), val_b: val_b.try_into().unwrap(), is_final: false },
            None,
        ).unwrap();
    }
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    let ivc = nova.ivc_proof();
    params.verify(ivc).unwrap();
    elapsed
}

#[test]
fn bench_scan_small() {
    let poseidon_config = nova_poseidon_config();
    let mut rng = StdRng::seed_from_u64(42);

    println!("\n  === SCAN: small source counts, varying B ===");

    // Setup all B variants
    print!("  Setup B=4...");
    let p4 = NovaParams::<ScanStepCircuit<Fr, D, 4>>::rand(poseidon_config.clone(), &mut rng).unwrap();
    print!(" B=8...");
    let p8 = NovaParams::<ScanStepCircuit<Fr, D, 8>>::rand(poseidon_config.clone(), &mut rng).unwrap();
    print!(" B=16...");
    let p16 = NovaParams::<ScanStepCircuit<Fr, D, 16>>::rand(poseidon_config.clone(), &mut rng).unwrap();
    print!(" B=32...");
    let p32 = NovaParams::<ScanStepCircuit<Fr, D, 32>>::rand(poseidon_config.clone(), &mut rng).unwrap();
    println!(" done\n");

    println!("  +------+----------+----------+----------+----------+");
    println!("  | Srcs |   B=4    |   B=8    |   B=16   |   B=32   |");
    println!("  +------+----------+----------+----------+----------+");

    for &n in &[4usize, 8, 16, 32, 48, 64] {
        let t4 = run_scan::<4>(n, &p4);
        let t8 = run_scan::<8>(n, &p8);
        let t16 = run_scan::<16>(n, &p16);
        let t32 = run_scan::<32>(n, &p32);

        let min = t4.min(t8).min(t16).min(t32);
        let mark = |t: f64| if (t - min).abs() < 50.0 { "*" } else { " " };

        println!(
            "  | {:>4} | {:>6.1}s{} | {:>6.1}s{} | {:>6.1}s{} | {:>6.1}s{} |",
            n,
            t4/1000.0, mark(t4),
            t8/1000.0, mark(t8),
            t16/1000.0, mark(t16),
            t32/1000.0, mark(t32),
        );
    }
    println!("  +------+----------+----------+----------+----------+");
    println!("  (* = fastest for that row)\n");
}

#[test]
fn bench_merge2_small() {
    let poseidon_config = nova_poseidon_config();
    let mut rng = StdRng::seed_from_u64(42);

    println!("\n  === MERGE2: small union sizes, varying B ===");

    print!("  Setup B=4...");
    let p4 = NovaParams::<Merge2StepCircuit<Fr, D, 4>>::rand(poseidon_config.clone(), &mut rng).unwrap();
    print!(" B=8...");
    let p8 = NovaParams::<Merge2StepCircuit<Fr, D, 8>>::rand(poseidon_config.clone(), &mut rng).unwrap();
    print!(" B=16...");
    let p16 = NovaParams::<Merge2StepCircuit<Fr, D, 16>>::rand(poseidon_config.clone(), &mut rng).unwrap();
    print!(" B=32...");
    let p32 = NovaParams::<Merge2StepCircuit<Fr, D, 32>>::rand(poseidon_config.clone(), &mut rng).unwrap();
    println!(" done\n");

    println!("  +------+----------+----------+----------+----------+");
    println!("  | Union|   B=4    |   B=8    |   B=16   |   B=32   |");
    println!("  +------+----------+----------+----------+----------+");

    for &n in &[4usize, 8, 16, 32, 48, 64] {
        let t4 = run_merge2::<4>(n, &p4);
        let t8 = run_merge2::<8>(n, &p8);
        let t16 = run_merge2::<16>(n, &p16);
        let t32 = run_merge2::<32>(n, &p32);

        let min = t4.min(t8).min(t16).min(t32);
        let mark = |t: f64| if (t - min).abs() < 50.0 { "*" } else { " " };

        println!(
            "  | {:>4} | {:>6.1}s{} | {:>6.1}s{} | {:>6.1}s{} | {:>6.1}s{} |",
            n,
            t4/1000.0, mark(t4),
            t8/1000.0, mark(t8),
            t16/1000.0, mark(t16),
            t32/1000.0, mark(t32),
        );
    }
    println!("  +------+----------+----------+----------+----------+");
    println!("  (* = fastest for that row)\n");
}
