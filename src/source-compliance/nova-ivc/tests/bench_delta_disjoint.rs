//! Benchmark: warm-cache delta-disjoint proof prototype.
//!
//! Run:
//!   cargo test --release --test bench_delta_disjoint -- --nocapture
//!
//! This measures the optimized online path proxy:
//!   S_note ∩ RevokedDelta(old,current) = ∅
//!
//! The note-local cache root is treated as already bound to source_commitment
//! by an offline reusable bind proof. Online work scales with revoked delta.

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
use std::{fs, time::Instant};

const NOTE_SOURCES: usize = 2048;
const NOTE_TREE_DEPTH: usize = 16;
const B_DELTA: usize = 16;
const DELTA_SIZES: &[usize] = &[8, 32, 64, 128];

type DC = DeltaDisjointStepCircuit<Fr, B_DELTA, NOTE_TREE_DEPTH>;

#[derive(Clone, Debug)]
struct NoteCacheTree {
    root: Fr,
    values: Vec<Fr>,
    levels: Vec<Vec<Fr>>,
    defaults: Vec<Fr>,
}

#[derive(Clone, Debug)]
struct Row {
    note_sources: usize,
    delta_size: usize,
    steps: usize,
    setup_ms: f64,
    prove_ms: f64,
    verify_ms: f64,
}

fn poseidon_hash(params: &PoseidonConfig<Fr>, inputs: &[Fr]) -> Fr {
    let mut sponge = PoseidonSponge::<Fr>::new(params);
    sponge.absorb(&inputs.to_vec());
    sponge.squeeze_field_elements(1)[0]
}

fn leaf_hash(params: &PoseidonConfig<Fr>, index: usize, value: Fr) -> Fr {
    poseidon_hash(params, &[Fr::from(DST_DELTA_CACHE_LEAF), Fr::from(index as u64), value])
}

fn node_hash(params: &PoseidonConfig<Fr>, left: Fr, right: Fr) -> Fr {
    poseidon_hash(params, &[Fr::from(DST_DELTA_CACHE_NODE), left, right])
}

fn build_note_cache_tree(params: &PoseidonConfig<Fr>, note_sources: usize) -> NoteCacheTree {
    let values: Vec<Fr> = (0..note_sources)
        .map(|idx| Fr::from((idx + 1) as u64 * 100))
        .collect();

    let mut defaults = Vec::with_capacity(NOTE_TREE_DEPTH + 1);
    defaults.push(Fr::ZERO);
    for level in 0..NOTE_TREE_DEPTH {
        let d = defaults[level];
        defaults.push(node_hash(params, d, d));
    }

    let mut levels = Vec::with_capacity(NOTE_TREE_DEPTH + 1);
    levels.push(
        values
            .iter()
            .enumerate()
            .map(|(idx, value)| leaf_hash(params, idx, *value))
            .collect::<Vec<_>>(),
    );

    for level in 0..NOTE_TREE_DEPTH {
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
        root: levels[NOTE_TREE_DEPTH][0],
        values,
        levels,
        defaults,
    }
}

fn path_for(tree: &NoteCacheTree, index: usize) -> (Vec<Fr>, Vec<bool>) {
    let mut idx = index;
    let mut siblings = Vec::with_capacity(NOTE_TREE_DEPTH);
    let mut directions = Vec::with_capacity(NOTE_TREE_DEPTH);
    for level in 0..NOTE_TREE_DEPTH {
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

fn make_delta_input(tree: &NoteCacheTree, offset: usize, delta_size: usize) -> DeltaDisjointStepInputs<Fr, B_DELTA, NOTE_TREE_DEPTH> {
    let mut input = DeltaDisjointStepInputs::<Fr, B_DELTA, NOTE_TREE_DEPTH>::default();
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
        for depth in 0..NOTE_TREE_DEPTH {
            input.pred_siblings[j * NOTE_TREE_DEPTH + depth] = pred_siblings[depth];
            input.succ_siblings[j * NOTE_TREE_DEPTH + depth] = succ_siblings[depth];
            input.pred_directions[j * NOTE_TREE_DEPTH + depth] = pred_dirs[depth];
            input.succ_directions[j * NOTE_TREE_DEPTH + depth] = succ_dirs[depth];
        }
    }
    input
}

fn bench_delta_size(
    params: &NovaParams<DC>,
    rng: &mut StdRng,
    tree: &NoteCacheTree,
    setup_ms: f64,
    delta_size: usize,
) -> Row {
    let n_steps = (delta_size + B_DELTA - 1) / B_DELTA;
    let z_0 = vec![tree.root, Fr::ZERO, Fr::from(1u64)];
    let start = Instant::now();
    let mut nova = params.initial_nova(z_0).expect("initial Nova");

    for step in 0..n_steps {
        let input = make_delta_input(tree, step * B_DELTA, delta_size);
        nova.prove_step(&mut *rng, input, None).expect("prove step");
    }

    let prove_ms = start.elapsed().as_secs_f64() * 1000.0;
    let ivc = nova.ivc_proof();
    let verify_start = Instant::now();
    params.verify(ivc).expect("verify Nova proof");
    let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;

    Row {
        note_sources: NOTE_SOURCES,
        delta_size,
        steps: n_steps,
        setup_ms,
        prove_ms,
        verify_ms,
    }
}

fn write_json(rows: &[Row], tree_ms: f64) {
    let mut json = String::new();
    json.push_str("{\n");
    json.push_str(&format!("  \"noteSources\": {},\n", NOTE_SOURCES));
    json.push_str(&format!("  \"noteTreeDepth\": {},\n", NOTE_TREE_DEPTH));
    json.push_str(&format!("  \"batchDelta\": {},\n", B_DELTA));
    json.push_str(&format!("  \"treeMs\": {:.3},\n", tree_ms));
    json.push_str("  \"rows\": [\n");
    for (i, row) in rows.iter().enumerate() {
        let comma = if i + 1 == rows.len() { "" } else { "," };
        json.push_str(&format!(
            "    {{ \"noteSources\": {}, \"deltaSize\": {}, \"steps\": {}, \"setupMs\": {:.3}, \"proveMs\": {:.3}, \"verifyMs\": {:.3} }}{}\n",
            row.note_sources, row.delta_size, row.steps, row.setup_ms, row.prove_ms, row.verify_ms, comma
        ));
    }
    json.push_str("  ]\n");
    json.push_str("}\n");
    let _ = fs::write("/tmp/railgun-delta-disjoint-bench.json", json);
}

#[test]
fn bench_delta_disjoint_warm_cache() {
    let mut rng = StdRng::seed_from_u64(42);
    let poseidon_config = nova_poseidon_config();

    let tree_start = Instant::now();
    let tree = build_note_cache_tree(&poseidon_config, NOTE_SOURCES);
    let tree_ms = tree_start.elapsed().as_secs_f64() * 1000.0;

    let setup_start = Instant::now();
    let params = NovaParams::<DC>::rand(poseidon_config, &mut rng).expect("Nova params");
    let setup_ms = setup_start.elapsed().as_secs_f64() * 1000.0;

    println!("\n  === Warm-cache R_ACC_DISJOINT_DELTA prototype ===");
    println!(
        "  note_sources={}, note_tree_depth={}, B_DELTA={}",
        NOTE_SOURCES, NOTE_TREE_DEPTH, B_DELTA
    );
    println!("  note cache tree build: {:.1}ms", tree_ms);
    println!("  setup: {:.1}s", setup_ms / 1000.0);
    println!();
    println!("  +----------+--------+----------+----------+----------+");
    println!("  | delta    | steps  | prove    | verify   | note src |");
    println!("  +----------+--------+----------+----------+----------+");

    let mut rows = Vec::new();
    for &delta_size in DELTA_SIZES {
        let row = bench_delta_size(&params, &mut rng, &tree, setup_ms, delta_size);
        println!(
            "  | {:>8} | {:>6} | {:>7.2}s | {:>7.1}ms | {:>8} |",
            row.delta_size,
            row.steps,
            row.prove_ms / 1000.0,
            row.verify_ms,
            row.note_sources,
        );
        rows.push(row);
        write_json(&rows, tree_ms);
    }

    println!("  +----------+--------+----------+----------+----------+");
    println!("  Note: online proof scales with revoked delta size; note cache/bind proof is assumed warm.");
}
