//! Benchmark: incremental ordered-set insert proof proxy.
//!
//! Run:
//!   cargo test --release --test bench_bind_incremental_insert -- --nocapture
//!
//! Full profile:
//!   RAILGUN_BENCH_INSERT_SCALING=1 \
//!     cargo test --release --test bench_bind_incremental_insert -- --nocapture
//!
//! This benchmark measures an incremental update proxy:
//!   Given an authenticated ordered-set root, insert k new source keys.
//!
//! The proxy uses a sparse Merkle tree keyed by source value. It does not
//! re-materialize a flat BuildSourceDescriptor root.

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::{
    poseidon::{PoseidonConfig, PoseidonSponge},
    CryptographicSponge,
};
use ark_ff::AdditiveGroup;
use folding_schemes::FoldingScheme;
use railgun_merge_ivc::{
    ordered_set_insert_step_circuit::{
        OrderedSetInsertStepCircuit, OrderedSetInsertStepInputs, DST_ORDERED_SET_LEAF,
        DST_ORDERED_SET_NODE,
    },
    poseidon_config::nova_poseidon_config,
    NovaParams,
};
use rand::{rngs::StdRng, SeedableRng};
use std::{collections::HashMap, env, fs, time::Instant};

const B_INSERT: usize = 16;
const TREE_DEPTH: usize = 20;

type IC = OrderedSetInsertStepCircuit<Fr, B_INSERT, TREE_DEPTH>;

#[derive(Clone, Debug)]
struct SparseOrderedSetTree<const DEPTH: usize> {
    root: Fr,
    levels: Vec<HashMap<usize, Fr>>,
    defaults: Vec<Fr>,
}

#[derive(Clone, Debug)]
struct InsertWitness {
    key: usize,
    siblings: Vec<Fr>,
}

#[derive(Clone, Debug)]
struct Row {
    base_sources: usize,
    insert_count: usize,
    tree_depth: usize,
    steps: usize,
    setup_ms: f64,
    build_old_root_ms: f64,
    witness_build_ms: f64,
    prove_ms: f64,
    verify_ms: f64,
    status: &'static str,
}

fn poseidon_hash(params: &PoseidonConfig<Fr>, inputs: &[Fr]) -> Fr {
    let mut sponge = PoseidonSponge::<Fr>::new(params);
    sponge.absorb(&inputs.to_vec());
    sponge.squeeze_field_elements(1)[0]
}

fn leaf_hash(params: &PoseidonConfig<Fr>, key: usize) -> Fr {
    poseidon_hash(
        params,
        &[Fr::from(DST_ORDERED_SET_LEAF), Fr::from(key as u64)],
    )
}

fn node_hash(params: &PoseidonConfig<Fr>, left: Fr, right: Fr) -> Fr {
    poseidon_hash(params, &[Fr::from(DST_ORDERED_SET_NODE), left, right])
}

impl<const DEPTH: usize> SparseOrderedSetTree<DEPTH> {
    fn new(params: &PoseidonConfig<Fr>) -> Self {
        let mut defaults = Vec::with_capacity(DEPTH + 1);
        defaults.push(Fr::ZERO);
        for level in 0..DEPTH {
            let d = defaults[level];
            defaults.push(node_hash(params, d, d));
        }
        let levels = (0..=DEPTH).map(|_| HashMap::new()).collect();
        Self {
            root: defaults[DEPTH],
            levels,
            defaults,
        }
    }

    fn from_base(params: &PoseidonConfig<Fr>, base_sources: usize) -> Self {
        let mut tree = Self::new(params);
        for key in 1..=base_sources {
            tree.insert_without_witness(params, key);
        }
        tree
    }

    fn path_for(&self, key: usize) -> Vec<Fr> {
        let mut idx = key;
        let mut siblings = Vec::with_capacity(DEPTH);
        for level in 0..DEPTH {
            let sibling_idx = idx ^ 1;
            siblings.push(
                self.levels[level]
                    .get(&sibling_idx)
                    .copied()
                    .unwrap_or(self.defaults[level]),
            );
            idx >>= 1;
        }
        siblings
    }

    fn set_node(&mut self, level: usize, idx: usize, value: Fr) {
        if value == self.defaults[level] {
            self.levels[level].remove(&idx);
        } else {
            self.levels[level].insert(idx, value);
        }
    }

    fn insert_without_witness(&mut self, params: &PoseidonConfig<Fr>, key: usize) {
        self.update_insert(params, key);
    }

    fn insert_with_witness(&mut self, params: &PoseidonConfig<Fr>, key: usize) -> InsertWitness {
        let siblings = self.path_for(key);
        self.update_insert(params, key);
        InsertWitness { key, siblings }
    }

    fn update_insert(&mut self, params: &PoseidonConfig<Fr>, key: usize) {
        let mut idx = key;
        let mut current = leaf_hash(params, key);
        self.set_node(0, idx, current);

        for level in 0..DEPTH {
            let sibling_idx = idx ^ 1;
            let sibling = self.levels[level]
                .get(&sibling_idx)
                .copied()
                .unwrap_or(self.defaults[level]);
            let parent = if (idx & 1) == 0 {
                node_hash(params, current, sibling)
            } else {
                node_hash(params, sibling, current)
            };
            idx >>= 1;
            current = parent;
            self.set_node(level + 1, idx, current);
        }
        self.root = current;
    }
}

fn selected_base_sources() -> Vec<usize> {
    if env::var("RAILGUN_BENCH_INSERT_SCALING").ok().as_deref() == Some("1") {
        vec![1 << 10, 1 << 12, 1 << 14, 1 << 16]
    } else {
        vec![1 << 10, 1 << 12]
    }
}

fn selected_insert_counts() -> Vec<usize> {
    if env::var("RAILGUN_BENCH_INSERT_SCALING").ok().as_deref() == Some("1") {
        vec![1, 8, 64]
    } else {
        vec![1, 8]
    }
}

fn build_inputs(
    witnesses: &[InsertWitness],
) -> Vec<OrderedSetInsertStepInputs<Fr, B_INSERT, TREE_DEPTH>> {
    let n_steps = (witnesses.len() + B_INSERT - 1) / B_INSERT;
    let mut inputs = Vec::with_capacity(n_steps);
    for step in 0..n_steps {
        let base = step * B_INSERT;
        let mut input = OrderedSetInsertStepInputs::<Fr, B_INSERT, TREE_DEPTH>::default();
        for j in 0..B_INSERT {
            let idx = base + j;
            if idx < witnesses.len() {
                input.keys[j] = Fr::from(witnesses[idx].key as u64);
                input.actives[j] = true;
                for depth in 0..TREE_DEPTH {
                    input.siblings[j * TREE_DEPTH + depth] = witnesses[idx].siblings[depth];
                }
            }
        }
        inputs.push(input);
    }
    inputs
}

fn bench_one(
    params: &NovaParams<IC>,
    rng: &mut StdRng,
    poseidon_config: &PoseidonConfig<Fr>,
    setup_ms: f64,
    base_tree: &SparseOrderedSetTree<TREE_DEPTH>,
    build_old_root_ms: f64,
    base_sources: usize,
    insert_count: usize,
) -> Row {
    let mut tree = base_tree.clone();
    let old_root = tree.root;

    let witness_start = Instant::now();
    let witnesses: Vec<InsertWitness> = (0..insert_count)
        .map(|i| tree.insert_with_witness(poseidon_config, base_sources + 1 + i))
        .collect();
    let inputs = build_inputs(&witnesses);
    let witness_build_ms = witness_start.elapsed().as_secs_f64() * 1000.0;

    let z_0 = vec![old_root, Fr::ZERO, Fr::from(1u64)];
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
        base_sources,
        insert_count,
        tree_depth: TREE_DEPTH,
        steps: (insert_count + B_INSERT - 1) / B_INSERT,
        setup_ms,
        build_old_root_ms,
        witness_build_ms,
        prove_ms,
        verify_ms,
        status: "measured",
    }
}

fn write_json(rows: &[Row]) {
    let mut json = String::new();
    json.push_str("{\n");
    json.push_str("  \"relation\": \"R_ORDERED_SET_INSERT_PROXY\",\n");
    json.push_str(&format!("  \"batchInsert\": {},\n", B_INSERT));
    json.push_str(&format!("  \"treeDepth\": {},\n", TREE_DEPTH));
    json.push_str("  \"rows\": [\n");
    for (i, row) in rows.iter().enumerate() {
        let comma = if i + 1 == rows.len() { "" } else { "," };
        json.push_str(&format!(
            "    {{ \"baseSources\": {}, \"insertCount\": {}, \"treeDepth\": {}, \"steps\": {}, \"setupMs\": {:.3}, \"buildOldRootMs\": {:.3}, \"witnessBuildMs\": {:.3}, \"proveMs\": {:.3}, \"verifyMs\": {:.3}, \"proveMsPerInsert\": {:.3}, \"status\": \"{}\" }}{}\n",
            row.base_sources,
            row.insert_count,
            row.tree_depth,
            row.steps,
            row.setup_ms,
            row.build_old_root_ms,
            row.witness_build_ms,
            row.prove_ms,
            row.verify_ms,
            row.prove_ms / row.insert_count as f64,
            row.status,
            comma
        ));
    }
    json.push_str("  ]\n");
    json.push_str("}\n");
    let _ = fs::write("/tmp/railgun-bind-incremental-insert.json", json);
}

fn print_rows(rows: &[Row]) {
    println!("  +---------+---------+-------+-------+----------+----------+----------+----------+----------+");
    println!("  | base    | inserts | depth | steps | old-root | witness  | prove    | verify   | per-ins  |");
    println!("  +---------+---------+-------+-------+----------+----------+----------+----------+----------+");
    for row in rows {
        println!(
            "  | {:>7} | {:>7} | {:>5} | {:>5} | {:>7.2}s | {:>7.2}s | {:>7.2}s | {:>7.1}ms | {:>7.2}ms |",
            row.base_sources,
            row.insert_count,
            row.tree_depth,
            row.steps,
            row.build_old_root_ms / 1000.0,
            row.witness_build_ms / 1000.0,
            row.prove_ms / 1000.0,
            row.verify_ms,
            row.prove_ms / row.insert_count as f64,
        );
    }
    println!("  +---------+---------+-------+-------+----------+----------+----------+----------+----------+");
}

#[test]
fn bench_bind_incremental_insert() {
    let mut rng = StdRng::seed_from_u64(43);
    let poseidon_config = nova_poseidon_config();
    let setup_start = Instant::now();
    let params = NovaParams::<IC>::rand(poseidon_config.clone(), &mut rng).expect("Nova params");
    let setup_ms = setup_start.elapsed().as_secs_f64() * 1000.0;

    let bases = selected_base_sources();
    let inserts = selected_insert_counts();

    println!("\n  === Incremental ordered-set insert proxy ===");
    println!("  bases={bases:?}, inserts={inserts:?}, B_INSERT={B_INSERT}, DEPTH={TREE_DEPTH}");
    println!("  setup: {:.2}s", setup_ms / 1000.0);
    println!("  Note: flat descriptor re-materialization is not included.");

    let mut rows = Vec::new();
    for base in bases {
        let build_start = Instant::now();
        let base_tree = SparseOrderedSetTree::<TREE_DEPTH>::from_base(&poseidon_config, base);
        let build_old_root_ms = build_start.elapsed().as_secs_f64() * 1000.0;
        for insert_count in &inserts {
            let row = bench_one(
                &params,
                &mut rng,
                &poseidon_config,
                setup_ms,
                &base_tree,
                build_old_root_ms,
                base,
                *insert_count,
            );
            rows.push(row);
            write_json(&rows);
        }
    }
    print_rows(&rows);
    write_json(&rows);
    println!("  JSON: /tmp/railgun-bind-incremental-insert.json");
}
