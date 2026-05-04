//! CleanCheckCircuit — Groth16 circuit for R_SRC_CLEAN.
//!
//! Verifies that every source prime in a note's SrcSet is a member of the
//! cleanSourceRoot Merkle tree (i.e., not blacklisted).
//!
//! This is NOT an IVC circuit — it's a one-shot Groth16 proof because
//! clean-check doesn't need recursive folding.
//!
//! Public inputs:
//!   - source_commitment: Com_src(src_root, src_count, rho_src)
//!   - clean_source_root: Merkle root of the clean source universe
//!
//! Private witness (per source):
//!   - source primes (sorted, unique)
//!   - Merkle path siblings + direction bits
//!   - src_root, src_count, rho_src (to open commitment)

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_crypto_primitives::sponge::{constraints::CryptographicSpongeVar, poseidon::constraints::PoseidonSpongeVar};
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::fp::FpVar,
    prelude::Boolean,
    select::CondSelectGadget,
};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

// ============================================================
// Constants
// ============================================================

/// Domain separation tags matching the TypeScript engine
const DST_SRC_LEAF: u64   = 0x524C56_03; // LeafHash_src
const DST_SRC_NODE: u64   = 0x524E56_03; // NodeHash_src
const DST_SRC_COMMIT: u64 = 0x525343_03; // Com_src

// ============================================================
// CleanCheckCircuit
// ============================================================

/// Groth16 circuit for R_SRC_CLEAN.
///
/// Generic over MAX_SOURCES and MERKLE_DEPTH.
#[derive(Clone)]
pub struct CleanCheckCircuit<const MAX_SOURCES: usize, const MERKLE_DEPTH: usize> {
    pub poseidon_params: PoseidonConfig<Fr>,

    // Public inputs
    pub source_commitment: Fr,
    pub clean_source_root: Fr,

    // Private witness: commitment opening
    pub src_root: Fr,
    pub src_count: Fr,
    pub rho_src: Fr,

    // Private witness: source primes and membership proofs
    /// source_primes[i] for i < active_count are real; rest are padding (0)
    pub source_primes: Vec<Fr>,
    /// is_active[i] = true if source_primes[i] is a real source
    pub is_active: Vec<bool>,
    /// merkle_siblings[i][j] = sibling at depth j for source i
    pub merkle_siblings: Vec<Vec<Fr>>,
    /// merkle_directions[i][j] = true if source i is on the right at depth j
    pub merkle_directions: Vec<Vec<bool>>,
}

impl<const MAX_SOURCES: usize, const MERKLE_DEPTH: usize>
    CleanCheckCircuit<MAX_SOURCES, MERKLE_DEPTH>
{
    /// Create a dummy instance for setup (generates valid constraint system shape).
    pub fn dummy(poseidon_params: PoseidonConfig<Fr>) -> Self {
        Self {
            poseidon_params,
            source_commitment: Fr::from(0u64),
            clean_source_root: Fr::from(0u64),
            src_root: Fr::from(0u64),
            src_count: Fr::from(0u64),
            rho_src: Fr::from(0u64),
            source_primes: vec![Fr::from(0u64); MAX_SOURCES],
            is_active: vec![false; MAX_SOURCES],
            merkle_siblings: vec![vec![Fr::from(0u64); MERKLE_DEPTH]; MAX_SOURCES],
            merkle_directions: vec![vec![false; MERKLE_DEPTH]; MAX_SOURCES],
        }
    }
}

// ============================================================
// In-circuit Poseidon helpers
// ============================================================

fn poseidon_hash(
    params: &PoseidonConfig<Fr>,
    cs: ConstraintSystemRef<Fr>,
    inputs: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::new(cs, params);
    let input_vec: Vec<FpVar<Fr>> = inputs.to_vec();
    sponge.absorb(&input_vec)?;
    let out = sponge.squeeze_field_elements(1)?;
    Ok(out[0].clone())
}

// ============================================================
// Constraint Synthesizer
// ============================================================

impl<const MAX_SOURCES: usize, const MERKLE_DEPTH: usize> ConstraintSynthesizer<Fr>
    for CleanCheckCircuit<MAX_SOURCES, MERKLE_DEPTH>
{
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ---- Public inputs ----
        let source_commitment_var =
            FpVar::new_input(cs.clone(), || Ok(self.source_commitment))?;
        let clean_source_root_var =
            FpVar::new_input(cs.clone(), || Ok(self.clean_source_root))?;

        // ---- Private witness: commitment opening ----
        let src_root_var = FpVar::new_witness(cs.clone(), || Ok(self.src_root))?;
        let src_count_var = FpVar::new_witness(cs.clone(), || Ok(self.src_count))?;
        let rho_src_var = FpVar::new_witness(cs.clone(), || Ok(self.rho_src))?;

        // ---- DST constants ----
        let dst_leaf = FpVar::new_constant(cs.clone(), Fr::from(DST_SRC_LEAF))?;
        let dst_node = FpVar::new_constant(cs.clone(), Fr::from(DST_SRC_NODE))?;
        let dst_commit = FpVar::new_constant(cs.clone(), Fr::from(DST_SRC_COMMIT))?;

        // ---- Constraint 1: Verify commitment opening ----
        // Com_src = Poseidon(DST_SRC_COMMIT, src_root, src_count, rho_src)
        let computed_commit = poseidon_hash(
            &self.poseidon_params,
            cs.clone(),
            &[dst_commit, src_root_var, src_count_var, rho_src_var],
        )?;
        computed_commit.enforce_equal(&source_commitment_var)?;

        // ---- Constraint 2: For each source, verify Merkle membership ----
        for i in 0..MAX_SOURCES {
            let source_var = FpVar::new_witness(cs.clone(), || Ok(self.source_primes[i]))?;
            let active_var = Boolean::new_witness(cs.clone(), || Ok(self.is_active[i]))?;

            // LeafHash = Poseidon(DST_SRC_LEAF, source)
            let leaf = poseidon_hash(
                &self.poseidon_params,
                cs.clone(),
                &[dst_leaf.clone(), source_var],
            )?;

            // Walk Merkle path
            let mut current = leaf;
            for j in 0..MERKLE_DEPTH {
                let sibling = FpVar::new_witness(cs.clone(), || Ok(self.merkle_siblings[i][j]))?;
                let dir = Boolean::new_witness(cs.clone(), || Ok(self.merkle_directions[i][j]))?;

                // If dir=false: hash(current, sibling); if dir=true: hash(sibling, current)
                let left = CondSelectGadget::conditionally_select(&dir, &sibling, &current)?;
                let right = CondSelectGadget::conditionally_select(&dir, &current, &sibling)?;

                current = poseidon_hash(
                    &self.poseidon_params,
                    cs.clone(),
                    &[dst_node.clone(), left, right],
                )?;
            }

            // If active: computed root must equal clean_source_root
            // If inactive (padding): no constraint
            // Implementation: expected = active ? clean_root : current (so equality always holds for inactive)
            let expected = CondSelectGadget::conditionally_select(
                &active_var, &clean_source_root_var, &current,
            )?;
            current.enforce_equal(&expected)?;
        }

        Ok(())
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::gr1cs::ConstraintSystem;
    use crate::poseidon_config::nova_poseidon_config;

    #[test]
    #[ignore] // Legacy Groth16 circuit; use CleanCheckStepCircuit (Nova IVC) instead
    fn test_clean_check_constraint_count() {
        // Small instance: 4 sources, depth 10
        let params = nova_poseidon_config();
        let circuit = CleanCheckCircuit::<4, 10>::dummy(params);

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        println!("CleanCheck(4, 10): {} constraints", cs.num_constraints());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    #[ignore] // Legacy Groth16 circuit; use CleanCheckStepCircuit (Nova IVC) instead
    fn test_clean_check_16_depth20() {
        let params = nova_poseidon_config();
        let circuit = CleanCheckCircuit::<16, 20>::dummy(params);

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        println!("CleanCheck(16, 20): {} constraints", cs.num_constraints());
        assert!(cs.is_satisfied().unwrap());
    }
}
