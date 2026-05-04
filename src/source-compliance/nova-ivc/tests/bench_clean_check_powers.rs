//! Benchmark: Nova CleanCheckStepCircuit cost at powers of two.
//!
//! Run:
//!   cargo test --release --test bench_clean_check_powers -- --nocapture
//!
//! The default run caps at 2^11 to keep routine test time bounded. Set
//! RAILGUN_BENCH_LARGE=1 RAILGUN_BENCH_MAX_EXP=16 for an explicit stress sweep.

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::{
    poseidon::{PoseidonConfig, PoseidonSponge},
    CryptographicSponge,
};
use ark_ff::AdditiveGroup;
use folding_schemes::FoldingScheme;
use railgun_merge_ivc::{
    clean_check_step_circuit::{CleanCheckStepCircuit, CleanCheckStepInputs},
    frontier_gadget::{DST_SRC_LEAF, DST_SRC_NODE},
    poseidon_config::nova_poseidon_config,
    NovaParams,
};
use rand::{rngs::StdRng, SeedableRng};
use std::{env, fs, time::Instant};

const B_CLEAN: usize = 32;
const DEPTH: usize = 20;
const FIRST_EXP: usize = 10;
const LAST_EXP: usize = 16;

type CC = CleanCheckStepCircuit<Fr, B_CLEAN>;

#[derive(Clone, Debug)]
struct Row {
    exp: usize,
    sources: usize,
    steps: usize,
    tree_ms: f64,
    prove_ms: f64,
    verify_ms: f64,
}

#[derive(Clone, Debug)]
struct CleanTreeWitness {
    root: Fr,
    sources: Vec<Fr>,
    siblings: Vec<Vec<Fr>>,
    directions: Vec<Vec<bool>>,
}

fn selected_exponents() -> Vec<usize> {
    let max_exp = env::var("RAILGUN_BENCH_MAX_EXP")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(if env::var("RAILGUN_BENCH_LARGE").ok().as_deref() == Some("1") {
            LAST_EXP
        } else {
            11
        })
        .clamp(FIRST_EXP, LAST_EXP);
    let max_exp = if env::var("RAILGUN_BENCH_LARGE").ok().as_deref() == Some("1") {
        max_exp
    } else {
        max_exp.min(11)
    };
    (FIRST_EXP..=max_exp).collect()
}

fn poseidon_hash(params: &PoseidonConfig<Fr>, inputs: &[Fr]) -> Fr {
    let mut sponge = PoseidonSponge::<Fr>::new(params);
    sponge.absorb(&inputs.to_vec());
    sponge.squeeze_field_elements(1)[0]
}

fn leaf_hash(params: &PoseidonConfig<Fr>, source: Fr) -> Fr {
    poseidon_hash(params, &[Fr::from(DST_SRC_LEAF), source])
}

fn node_hash(params: &PoseidonConfig<Fr>, left: Fr, right: Fr) -> Fr {
    poseidon_hash(params, &[Fr::from(DST_SRC_NODE), left, right])
}

fn build_clean_tree_witness(
    params: &PoseidonConfig<Fr>,
    n_sources: usize,
) -> CleanTreeWitness {
    let sources: Vec<Fr> = (0..n_sources)
        .map(|idx| Fr::from((idx + 1) as u64 * 100))
        .collect();

    let mut default_hashes = Vec::with_capacity(DEPTH + 1);
    default_hashes.push(Fr::ZERO);
    for level in 0..DEPTH {
        let d = default_hashes[level];
        default_hashes.push(node_hash(params, d, d));
    }

    let mut levels: Vec<Vec<Fr>> = Vec::with_capacity(DEPTH + 1);
    levels.push(
        sources
            .iter()
            .map(|source| leaf_hash(params, *source))
            .collect(),
    );

    for level in 0..DEPTH {
        let current = &levels[level];
        let default = default_hashes[level];
        let pairs = ((current.len().max(1)) + 1) / 2;
        let mut next = Vec::with_capacity(pairs);
        for pair in 0..pairs {
            let left = current.get(pair * 2).copied().unwrap_or(default);
            let right = current.get(pair * 2 + 1).copied().unwrap_or(default);
            next.push(node_hash(params, left, right));
        }
        levels.push(next);
    }

    let mut siblings = vec![vec![Fr::ZERO; DEPTH]; n_sources];
    let mut directions = vec![vec![false; DEPTH]; n_sources];
    for source_idx in 0..n_sources {
        let mut idx = source_idx;
        for level in 0..DEPTH {
            let sibling_idx = idx ^ 1;
            siblings[source_idx][level] = levels[level]
                .get(sibling_idx)
                .copied()
                .unwrap_or(default_hashes[level]);
            directions[source_idx][level] = (idx & 1) == 1;
            idx >>= 1;
        }
    }

    CleanTreeWitness {
        root: levels[DEPTH][0],
        sources,
        siblings,
        directions,
    }
}

fn run_clean_check(
    poseidon_config: &PoseidonConfig<Fr>,
    params: &NovaParams<CC>,
    rng: &mut StdRng,
    n_sources: usize,
) -> Row {
    let tree_start = Instant::now();
    let tree = build_clean_tree_witness(poseidon_config, n_sources);
    let tree_ms = tree_start.elapsed().as_secs_f64() * 1000.0;

    let z_0 = vec![tree.root, Fr::ZERO, Fr::from(1u64)];
    let n_steps = (n_sources + B_CLEAN - 1) / B_CLEAN;
    let start = Instant::now();
    let mut nova = params.initial_nova(z_0).expect("initial Nova");

    for step in 0..n_steps {
        let base = step * B_CLEAN;
        let mut sources = [Fr::ZERO; B_CLEAN];
        let mut actives = [false; B_CLEAN];
        let mut siblings = vec![Fr::ZERO; B_CLEAN * DEPTH];
        let mut directions = vec![false; B_CLEAN * DEPTH];

        for j in 0..B_CLEAN {
            let idx = base + j;
            if idx < n_sources {
                sources[j] = tree.sources[idx];
                actives[j] = true;
                for depth in 0..DEPTH {
                    siblings[j * DEPTH + depth] = tree.siblings[idx][depth];
                    directions[j * DEPTH + depth] = tree.directions[idx][depth];
                }
            }
        }

        nova.prove_step(
            &mut *rng,
            CleanCheckStepInputs {
                sources,
                actives,
                siblings,
                directions,
            },
            None,
        )
        .expect("prove step");
    }

    let prove_ms = start.elapsed().as_secs_f64() * 1000.0;
    let ivc = nova.ivc_proof();
    let verify_start = Instant::now();
    params.verify(ivc).expect("verify Nova proof");
    let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;

    Row {
        exp: n_sources.trailing_zeros() as usize,
        sources: n_sources,
        steps: n_steps,
        tree_ms,
        prove_ms,
        verify_ms,
    }
}

fn write_json(setup_ms: f64, rows: &[Row]) {
    let mut json = String::new();
    json.push_str("{\n");
    json.push_str(&format!("  \"setupMs\": {:.3},\n", setup_ms));
    json.push_str(&format!("  \"batchSize\": {},\n", B_CLEAN));
    json.push_str(&format!("  \"merkleDepth\": {},\n", DEPTH));
    json.push_str("  \"rows\": [\n");
    for (i, row) in rows.iter().enumerate() {
        let comma = if i + 1 == rows.len() { "" } else { "," };
        json.push_str(&format!(
            "    {{ \"exp\": {}, \"sources\": {}, \"steps\": {}, \"treeMs\": {:.3}, \"proveMs\": {:.3}, \"verifyMs\": {:.3} }}{}\n",
            row.exp, row.sources, row.steps, row.tree_ms, row.prove_ms, row.verify_ms, comma
        ));
    }
    json.push_str("  ]\n");
    json.push_str("}\n");
    let _ = fs::write("/tmp/railgun-clean-powers-nova.json", json);
}

#[test]
fn bench_clean_check_powers() {
    let mut rng = StdRng::seed_from_u64(42);
    let poseidon_config = nova_poseidon_config();

    println!("\n  === Nova CLEAN_CHECK powers benchmark ===");
    println!("  B_CLEAN={}, DEPTH={}", B_CLEAN, DEPTH);

    let setup_start = Instant::now();
    let params = NovaParams::<CC>::rand(poseidon_config.clone(), &mut rng).expect("Nova params");
    let setup_ms = setup_start.elapsed().as_secs_f64() * 1000.0;
    println!("  Setup: {:.1}s", setup_ms / 1000.0);
    println!();
    println!("  +-----+---------+--------+----------+----------+----------+");
    println!("  | exp | sources | steps  | tree     | prove    | verify   |");
    println!("  +-----+---------+--------+----------+----------+----------+");

    let mut rows = Vec::new();
    for exp in selected_exponents() {
        let row = run_clean_check(&poseidon_config, &params, &mut rng, 1usize << exp);
        println!(
            "  | {:>3} | {:>7} | {:>6} | {:>7.1}s | {:>7.1}s | {:>7.1}ms |",
            row.exp,
            row.sources,
            row.steps,
            row.tree_ms / 1000.0,
            row.prove_ms / 1000.0,
            row.verify_ms,
        );
        rows.push(row);
        write_json(setup_ms, &rows);
    }

    println!("  +-----+---------+--------+----------+----------+----------+");
    println!("  Note: active=true with valid depth-20 Merkle paths for every source.");
    write_json(setup_ms, &rows);
}
