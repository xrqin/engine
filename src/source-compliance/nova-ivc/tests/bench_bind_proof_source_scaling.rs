//! Benchmark: reusable bind proof sorted-scan proxy source-count scaling.
//!
//! Run:
//!   cargo test --release --test bench_bind_proof_source_scaling -- --nocapture
//!
//! Full profile:
//!   RAILGUN_BENCH_BIND_SCALING=1 RAILGUN_BENCH_MAX_EXP=16 \
//!     RAILGUN_BENCH_BIND_BATCH=32 \
//!     cargo test --release --test bench_bind_proof_source_scaling -- --nocapture
//!
//! This benchmark measures a cold/offline bind proof proxy:
//! - strict sorted-unique adjacent scan;
//! - rolling descriptor digest;
//! - rolling note-cache digest.
//!
//! It is not the full production R_ACC_BIND_NOTE relation.

use ark_bn254::Fr;
use ark_ff::AdditiveGroup;
use folding_schemes::FoldingScheme;
use railgun_merge_ivc::{
    bind_sorted_scan_step_circuit::{BindSortedScanStepCircuit, BindSortedScanStepInputs},
    poseidon_config::nova_poseidon_config,
    NovaParams,
};
use rand::{rngs::StdRng, SeedableRng};
use std::{env, fs, time::Instant};

const FIRST_EXP: usize = 10;
const LAST_EXP: usize = 16;

#[derive(Clone, Debug)]
struct Row {
    exp: usize,
    source_count: usize,
    steps: usize,
    batch: usize,
    setup_ms: f64,
    witness_build_ms: f64,
    prove_ms: f64,
    verify_ms: f64,
    status: &'static str,
}

fn selected_exponents() -> Vec<usize> {
    let full = env::var("RAILGUN_BENCH_BIND_SCALING").ok().as_deref() == Some("1");
    let min_exp = env::var("RAILGUN_BENCH_MIN_EXP")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(FIRST_EXP)
        .clamp(FIRST_EXP, LAST_EXP);
    let max_exp = if full {
        env::var("RAILGUN_BENCH_MAX_EXP")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(LAST_EXP)
            .clamp(FIRST_EXP, LAST_EXP)
    } else {
        12
    };
    (min_exp.min(max_exp)..=max_exp).collect()
}

fn selected_batch() -> usize {
    env::var("RAILGUN_BENCH_BIND_BATCH")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(32)
}

fn make_sources(source_count: usize) -> Vec<Fr> {
    (0..source_count)
        .map(|idx| Fr::from((idx + 1) as u64 * 100))
        .collect()
}

fn build_inputs<const B: usize>(sources: &[Fr]) -> Vec<BindSortedScanStepInputs<Fr, B>> {
    let n_steps = (sources.len() + B - 1) / B;
    let mut inputs = Vec::with_capacity(n_steps);
    for step in 0..n_steps {
        let base = step * B;
        let mut input = BindSortedScanStepInputs::<Fr, B>::default();
        for j in 0..B {
            let idx = base + j;
            if idx < sources.len() {
                input.sources[j] = sources[idx];
                input.actives[j] = true;
            }
        }
        inputs.push(input);
    }
    inputs
}

fn bench_one<const B: usize>(
    params: &NovaParams<BindSortedScanStepCircuit<Fr, B>>,
    rng: &mut StdRng,
    setup_ms: f64,
    source_count: usize,
) -> Row {
    let sources = make_sources(source_count);

    let witness_start = Instant::now();
    let inputs = build_inputs::<B>(&sources);
    let witness_build_ms = witness_start.elapsed().as_secs_f64() * 1000.0;

    let z_0 = vec![Fr::ZERO, Fr::ZERO, Fr::ZERO, Fr::ZERO, Fr::from(1u64)];
    let prove_start = Instant::now();
    let mut nova = params.initial_nova(z_0).expect("initial Nova");
    for input in inputs {
        nova.prove_step(&mut *rng, input, None).expect("prove step");
    }
    let prove_ms = prove_start.elapsed().as_secs_f64() * 1000.0;

    let ivc = nova.ivc_proof();
    let verify_start = Instant::now();
    params.verify(ivc).expect("verify Nova proof");
    let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;

    Row {
        exp: source_count.trailing_zeros() as usize,
        source_count,
        steps: (source_count + B - 1) / B,
        batch: B,
        setup_ms,
        witness_build_ms,
        prove_ms,
        verify_ms,
        status: "measured",
    }
}

fn run_profile<const B: usize>(exps: &[usize]) -> Vec<Row> {
    let mut rng = StdRng::seed_from_u64(42 + B as u64);
    let poseidon_config = nova_poseidon_config();
    let setup_start = Instant::now();
    let params = NovaParams::<BindSortedScanStepCircuit<Fr, B>>::rand(poseidon_config, &mut rng)
        .expect("Nova params");
    let setup_ms = setup_start.elapsed().as_secs_f64() * 1000.0;

    let mut rows = Vec::new();
    for exp in exps {
        let row = bench_one::<B>(&params, &mut rng, setup_ms, 1usize << exp);
        rows.push(row);
        write_json(&rows);
    }
    rows
}

fn write_json(rows: &[Row]) {
    let mut json = String::new();
    json.push_str("{\n");
    json.push_str("  \"relation\": \"R_BIND_SORTED_SCAN_PROXY\",\n");
    json.push_str("  \"rows\": [\n");
    for (i, row) in rows.iter().enumerate() {
        let comma = if i + 1 == rows.len() { "" } else { "," };
        json.push_str(&format!(
            "    {{ \"exp\": {}, \"sourceCount\": {}, \"steps\": {}, \"batch\": {}, \"setupMs\": {:.3}, \"witnessBuildMs\": {:.3}, \"proveMs\": {:.3}, \"verifyMs\": {:.3}, \"proveMsPerSource\": {:.6}, \"peakMemoryMB\": null, \"status\": \"{}\" }}{}\n",
            row.exp,
            row.source_count,
            row.steps,
            row.batch,
            row.setup_ms,
            row.witness_build_ms,
            row.prove_ms,
            row.verify_ms,
            row.prove_ms / row.source_count as f64,
            row.status,
            comma
        ));
    }
    json.push_str("  ]\n");
    json.push_str("}\n");
    let _ = fs::write("/tmp/railgun-bind-proof-source-scaling.json", json);
}

fn format_secs(ms: f64) -> String {
    format!("{:.2}s", ms / 1000.0)
}

fn print_rows(rows: &[Row]) {
    println!("  +-----+---------+--------+-------+----------+----------+----------+----------+------------+");
    println!("  | exp | sources | steps  | batch | setup    | witness  | prove    | verify   | per-source |");
    println!("  +-----+---------+--------+-------+----------+----------+----------+----------+------------+");
    for row in rows {
        println!(
            "  | {:>3} | {:>7} | {:>6} | {:>5} | {:>8} | {:>8} | {:>8} | {:>7.1}ms | {:>8.3}ms |",
            row.exp,
            row.source_count,
            row.steps,
            row.batch,
            format_secs(row.setup_ms),
            format!("{:.3}ms", row.witness_build_ms),
            format_secs(row.prove_ms),
            row.verify_ms,
            row.prove_ms / row.source_count as f64,
        );
    }
    println!("  +-----+---------+--------+-------+----------+----------+----------+----------+------------+");
}

#[test]
fn bench_bind_proof_source_scaling() {
    let exps = selected_exponents();
    let batch = selected_batch();
    let full = env::var("RAILGUN_BENCH_BIND_SCALING").ok().as_deref() == Some("1");

    println!("\n  === Bind proof sorted-scan proxy source-count scaling ===");
    println!("  exps={exps:?}, requested_batch={batch}, full_profile={full}");
    println!("  Note: this is a cold/offline R_BIND_SORTED_SCAN_PROXY benchmark.");

    let rows = match batch {
        16 => run_profile::<16>(&exps),
        32 => run_profile::<32>(&exps),
        64 => run_profile::<64>(&exps),
        _ => {
            println!("  Unsupported batch {batch}; falling back to B_BIND=32");
            run_profile::<32>(&exps)
        }
    };

    print_rows(&rows);
    write_json(&rows);
    println!("  JSON: /tmp/railgun-bind-proof-source-scaling.json");
}
