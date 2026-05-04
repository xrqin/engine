//! Benchmark: delta-disjoint source-count scaling with fixed revoked delta.
//!
//! Run:
//!   cargo test --release --test bench_delta_disjoint_source_scaling -- --nocapture
//!
//! Full profile:
//!   RAILGUN_BENCH_DELTA_SOURCE_SCALING=1 RAILGUN_BENCH_MAX_EXP=16 \
//!     RAILGUN_BENCH_FIXED_DELTA=64 \
//!     cargo test --release --test bench_delta_disjoint_source_scaling -- --nocapture
//!
//! This benchmark keeps |RevokedDelta| fixed and varies |S_note|. It measures
//! the warm-cache online proof proxy for:
//!   S_note ∩ RevokedDelta(old,current) = ∅
//!
//! The note-local cache root is treated as already bound to source_commitment
//! by an offline reusable bind proof. Cache tree build and witness preparation
//! are reported separately from Nova prove time.

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::{
    poseidon::{PoseidonConfig, PoseidonSponge},
    CryptographicSponge,
};
use ark_ff::AdditiveGroup;
use folding_schemes::FoldingScheme;
use railgun_merge_ivc::{
    delta_disjoint_step_circuit::{
        DeltaDisjointStepCircuit, DeltaDisjointStepInputs, DST_DELTA_CACHE_LEAF,
        DST_DELTA_CACHE_NODE,
    },
    poseidon_config::nova_poseidon_config,
    NovaParams,
};
use rand::{rngs::StdRng, SeedableRng};
use std::{env, fs, time::Instant};

const B_DELTA: usize = 16;
const FIXED_DEPTH: usize = 16;

#[derive(Clone, Debug)]
struct NoteCacheTree<const DEPTH: usize> {
    root: Fr,
    values: Vec<Fr>,
    levels: Vec<Vec<Fr>>,
    defaults: Vec<Fr>,
}

#[derive(Clone, Debug)]
struct Row {
    profile: &'static str,
    note_sources: usize,
    delta_size: usize,
    tree_depth: usize,
    capacity: usize,
    steps: usize,
    cache_build_ms: f64,
    witness_build_ms: f64,
    setup_ms: f64,
    prove_ms: f64,
    verify_ms: f64,
    status: &'static str,
}

fn poseidon_hash(params: &PoseidonConfig<Fr>, inputs: &[Fr]) -> Fr {
    let mut sponge = PoseidonSponge::<Fr>::new(params);
    sponge.absorb(&inputs.to_vec());
    sponge.squeeze_field_elements(1)[0]
}

fn leaf_hash(params: &PoseidonConfig<Fr>, index: usize, value: Fr) -> Fr {
    poseidon_hash(
        params,
        &[
            Fr::from(DST_DELTA_CACHE_LEAF),
            Fr::from(index as u64),
            value,
        ],
    )
}

fn node_hash(params: &PoseidonConfig<Fr>, left: Fr, right: Fr) -> Fr {
    poseidon_hash(params, &[Fr::from(DST_DELTA_CACHE_NODE), left, right])
}

fn build_note_cache_tree<const DEPTH: usize>(
    params: &PoseidonConfig<Fr>,
    note_sources: usize,
) -> NoteCacheTree<DEPTH> {
    assert!(note_sources >= 2, "need adjacent pred/succ leaves");
    assert!(
        note_sources <= (1usize << DEPTH),
        "note_sources exceeds fixed tree capacity"
    );

    let values: Vec<Fr> = (0..note_sources)
        .map(|idx| Fr::from((idx + 1) as u64 * 100))
        .collect();

    let mut defaults = Vec::with_capacity(DEPTH + 1);
    defaults.push(Fr::ZERO);
    for level in 0..DEPTH {
        let d = defaults[level];
        defaults.push(node_hash(params, d, d));
    }

    let mut levels = Vec::with_capacity(DEPTH + 1);
    levels.push(
        values
            .iter()
            .enumerate()
            .map(|(idx, value)| leaf_hash(params, idx, *value))
            .collect::<Vec<_>>(),
    );

    for level in 0..DEPTH {
        let current = &levels[level];
        let default = defaults[level];
        let pairs = ((current.len().max(1)) + 1) / 2;
        let mut next = Vec::with_capacity(pairs);
        for pair in 0..pairs {
            let left = current.get(pair * 2).copied().unwrap_or(default);
            let right = current.get(pair * 2 + 1).copied().unwrap_or(default);
            next.push(node_hash(params, left, right));
        }
        levels.push(next);
    }

    NoteCacheTree {
        root: levels[DEPTH][0],
        values,
        levels,
        defaults,
    }
}

fn path_for<const DEPTH: usize>(tree: &NoteCacheTree<DEPTH>, index: usize) -> (Vec<Fr>, Vec<bool>) {
    let mut idx = index;
    let mut siblings = Vec::with_capacity(DEPTH);
    let mut directions = Vec::with_capacity(DEPTH);
    for level in 0..DEPTH {
        let sibling_idx = idx ^ 1;
        siblings.push(
            tree.levels[level]
                .get(sibling_idx)
                .copied()
                .unwrap_or(tree.defaults[level]),
        );
        directions.push((idx & 1) == 1);
        idx >>= 1;
    }
    (siblings, directions)
}

fn make_delta_input<const DEPTH: usize>(
    tree: &NoteCacheTree<DEPTH>,
    offset: usize,
    delta_size: usize,
) -> DeltaDisjointStepInputs<Fr, B_DELTA, DEPTH> {
    let mut input = DeltaDisjointStepInputs::<Fr, B_DELTA, DEPTH>::default();
    for j in 0..B_DELTA {
        let k = offset + j;
        if k >= delta_size {
            break;
        }

        let pred_index = (k * 13) % (tree.values.len() - 1);
        let succ_index = pred_index + 1;
        let pred = tree.values[pred_index];
        let succ = tree.values[succ_index];
        let revoked = pred + Fr::from(50u64);
        let (pred_siblings, pred_dirs) = path_for(tree, pred_index);
        let (succ_siblings, succ_dirs) = path_for(tree, succ_index);

        input.revoked[j] = revoked;
        input.actives[j] = true;
        input.pred_values[j] = pred;
        input.succ_values[j] = succ;
        input.pred_indices[j] = Fr::from(pred_index as u64);
        input.succ_indices[j] = Fr::from(succ_index as u64);
        for depth in 0..DEPTH {
            input.pred_siblings[j * DEPTH + depth] = pred_siblings[depth];
            input.succ_siblings[j * DEPTH + depth] = succ_siblings[depth];
            input.pred_directions[j * DEPTH + depth] = pred_dirs[depth];
            input.succ_directions[j * DEPTH + depth] = succ_dirs[depth];
        }
    }
    input
}

fn build_inputs<const DEPTH: usize>(
    tree: &NoteCacheTree<DEPTH>,
    delta_size: usize,
) -> Vec<DeltaDisjointStepInputs<Fr, B_DELTA, DEPTH>> {
    let n_steps = (delta_size + B_DELTA - 1) / B_DELTA;
    (0..n_steps)
        .map(|step| make_delta_input(tree, step * B_DELTA, delta_size))
        .collect()
}

fn bench_one<const DEPTH: usize>(
    profile: &'static str,
    params: &NovaParams<DeltaDisjointStepCircuit<Fr, B_DELTA, DEPTH>>,
    rng: &mut StdRng,
    poseidon_config: &PoseidonConfig<Fr>,
    setup_ms: f64,
    note_sources: usize,
    delta_size: usize,
) -> Row {
    let cache_start = Instant::now();
    let tree = build_note_cache_tree::<DEPTH>(poseidon_config, note_sources);
    let cache_build_ms = cache_start.elapsed().as_secs_f64() * 1000.0;

    let witness_start = Instant::now();
    let inputs = build_inputs(&tree, delta_size);
    let witness_build_ms = witness_start.elapsed().as_secs_f64() * 1000.0;

    let z_0 = vec![tree.root, Fr::ZERO, Fr::from(1u64)];
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
        profile,
        note_sources,
        delta_size,
        tree_depth: DEPTH,
        capacity: 1usize << DEPTH,
        steps: (delta_size + B_DELTA - 1) / B_DELTA,
        cache_build_ms,
        witness_build_ms,
        setup_ms,
        prove_ms,
        verify_ms,
        status: "measured",
    }
}

fn run_profile<const DEPTH: usize>(
    profile: &'static str,
    note_sources_list: &[usize],
    delta_size: usize,
) -> Vec<Row> {
    let mut rng = StdRng::seed_from_u64(42 + DEPTH as u64 + delta_size as u64);
    let poseidon_config = nova_poseidon_config();
    let setup_start = Instant::now();
    let params = NovaParams::<DeltaDisjointStepCircuit<Fr, B_DELTA, DEPTH>>::rand(
        poseidon_config.clone(),
        &mut rng,
    )
    .expect("Nova params");
    let setup_ms = setup_start.elapsed().as_secs_f64() * 1000.0;

    note_sources_list
        .iter()
        .copied()
        .map(|note_sources| {
            bench_one::<DEPTH>(
                profile,
                &params,
                &mut rng,
                &poseidon_config,
                setup_ms,
                note_sources,
                delta_size,
            )
        })
        .collect()
}

fn run_variable_depth(exp: usize, delta_size: usize) -> Vec<Row> {
    let note_sources = 1usize << exp;
    match exp {
        10 => run_profile::<10>("variable-depth", &[note_sources], delta_size),
        11 => run_profile::<11>("variable-depth", &[note_sources], delta_size),
        12 => run_profile::<12>("variable-depth", &[note_sources], delta_size),
        13 => run_profile::<13>("variable-depth", &[note_sources], delta_size),
        14 => run_profile::<14>("variable-depth", &[note_sources], delta_size),
        15 => run_profile::<15>("variable-depth", &[note_sources], delta_size),
        16 => run_profile::<16>("variable-depth", &[note_sources], delta_size),
        _ => panic!("unsupported variable depth exp {exp}"),
    }
}

fn format_secs(ms: f64) -> String {
    format!("{:.2}s", ms / 1000.0)
}

fn print_rows(title: &str, rows: &[Row]) {
    println!("\n  === {title} ===");
    println!("  +----------------+----------+-------+-------+-------+----------+----------+----------+----------+----------+");
    println!("  | profile        | note src | delta | depth | steps | cache    | witness  | prove    | verify   | per-dlt  |");
    println!("  +----------------+----------+-------+-------+-------+----------+----------+----------+----------+----------+");
    for row in rows {
        println!(
            "  | {:<14} | {:>8} | {:>5} | {:>5} | {:>5} | {:>8} | {:>8} | {:>8} | {:>7.1}ms | {:>8} |",
            row.profile,
            row.note_sources,
            row.delta_size,
            row.tree_depth,
            row.steps,
            format_secs(row.cache_build_ms),
            format_secs(row.witness_build_ms),
            format_secs(row.prove_ms),
            row.verify_ms,
            format!("{:.1}ms", row.prove_ms / row.delta_size as f64),
        );
    }
    println!("  +----------------+----------+-------+-------+-------+----------+----------+----------+----------+----------+");
}

fn json_escape(value: &str) -> String {
    value.replace('"', "\\\"")
}

fn write_json(rows: &[Row]) {
    let mut json = String::new();
    json.push_str("{\n");
    json.push_str(&format!("  \"batchDelta\": {},\n", B_DELTA));
    json.push_str("  \"rows\": [\n");
    for (i, row) in rows.iter().enumerate() {
        let comma = if i + 1 == rows.len() { "" } else { "," };
        json.push_str(&format!(
            "    {{ \"profile\": \"{}\", \"noteSources\": {}, \"deltaSize\": {}, \"treeDepth\": {}, \"capacity\": {}, \"steps\": {}, \"cacheBuildMs\": {:.3}, \"witnessBuildMs\": {:.3}, \"setupMs\": {:.3}, \"proveMs\": {:.3}, \"verifyMs\": {:.3}, \"proveMsPerDelta\": {:.3}, \"status\": \"{}\" }}{}\n",
            json_escape(row.profile),
            row.note_sources,
            row.delta_size,
            row.tree_depth,
            row.capacity,
            row.steps,
            row.cache_build_ms,
            row.witness_build_ms,
            row.setup_ms,
            row.prove_ms,
            row.verify_ms,
            row.prove_ms / row.delta_size as f64,
            row.status,
            comma
        ));
    }
    json.push_str("  ]\n");
    json.push_str("}\n");
    let _ = fs::write("/tmp/railgun-delta-disjoint-source-scaling.json", json);
}

fn exp_range() -> Vec<usize> {
    let full = env::var("RAILGUN_BENCH_DELTA_SOURCE_SCALING")
        .ok()
        .as_deref()
        == Some("1");
    let max_exp = if full {
        env::var("RAILGUN_BENCH_MAX_EXP")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(16)
            .min(16)
    } else {
        13
    };
    (10..=max_exp).collect()
}

fn fixed_delta() -> usize {
    let full = env::var("RAILGUN_BENCH_DELTA_SOURCE_SCALING")
        .ok()
        .as_deref()
        == Some("1");
    if full {
        env::var("RAILGUN_BENCH_FIXED_DELTA")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(64)
    } else {
        16
    }
}

#[test]
fn bench_delta_disjoint_source_scaling() {
    let exps = exp_range();
    let delta_size = fixed_delta();
    let note_sources_list: Vec<usize> = exps.iter().map(|exp| 1usize << exp).collect();

    println!("\n  === Delta-disjoint source-count scaling ===");
    println!("  exps={exps:?}, fixed_delta={delta_size}, B_DELTA={B_DELTA}");
    println!(
        "  full_profile={}",
        env::var("RAILGUN_BENCH_DELTA_SOURCE_SCALING")
            .ok()
            .as_deref()
            == Some("1")
    );
    println!("  Note: cache build and witness build are reported separately from online prove.");

    let mut rows = Vec::new();
    let fixed_rows = run_profile::<FIXED_DEPTH>("fixed-depth", &note_sources_list, delta_size);
    print_rows("fixed depth", &fixed_rows);
    rows.extend(fixed_rows);
    write_json(&rows);

    let mut variable_rows = Vec::new();
    for exp in exps {
        let mut row = run_variable_depth(exp, delta_size);
        variable_rows.append(&mut row);
    }
    print_rows("variable depth", &variable_rows);
    rows.extend(variable_rows);
    write_json(&rows);

    println!("  JSON: /tmp/railgun-delta-disjoint-source-scaling.json");
}
