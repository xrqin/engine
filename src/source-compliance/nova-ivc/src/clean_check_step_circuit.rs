//! CleanCheckStepCircuit — Nova FCircuit for R_SRC_CLEAN.
//!
//! Each step verifies B sources' Merkle membership in the clean source tree.
//! This is the Nova IVC version of CleanCheckCircuit, enabling:
//! - Parallel proving with SCAN_A, SCAN_B, MERGE2 (4-way parallel)
//! - Single proof output (vs K separate Groth16 proofs)
//!
//! State vector z_i (3 elements):
//!   [clean_root, num_checked, membership_ok]
//!
//! External inputs per step:
//!   - sources[B]: source prime values
//!   - actives[B]: validity flags
//!   - siblings[B * DEPTH]: flattened Merkle path siblings
//!   - directions[B * DEPTH]: flattened Merkle path direction bits
//!
//! Per source: LeafHash → walk 20-level Merkle path → check root == clean_root

use ark_crypto_primitives::sponge::{Absorb, poseidon::PoseidonConfig};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    convert::ToBitsGadget,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    prelude::Boolean,
    select::CondSelectGadget,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::vec::Vec;
use core::borrow::Borrow;
use folding_schemes::{Error, frontend::FCircuit};

use crate::frontier_gadget::{self, DST_SRC_LEAF, DST_SRC_NODE, poseidon_gadget};

const MERKLE_DEPTH: usize = 20;

// ============================================================
// External Inputs
// ============================================================

#[derive(Clone, Debug)]
pub struct CleanCheckStepInputs<F: PrimeField, const B: usize> {
    pub sources: [F; B],
    pub actives: [bool; B],
    /// Flattened siblings: siblings[i * DEPTH + j] for source i, depth j
    pub siblings: Vec<F>,
    /// Flattened directions: directions[i * DEPTH + j]
    pub directions: Vec<bool>,
}

impl<F: PrimeField, const B: usize> Default for CleanCheckStepInputs<F, B> {
    fn default() -> Self {
        Self {
            sources: [F::ZERO; B],
            actives: [false; B],
            siblings: vec![F::ZERO; B * MERKLE_DEPTH],
            directions: vec![false; B * MERKLE_DEPTH],
        }
    }
}

#[derive(Clone, Debug)]
pub struct CleanCheckStepInputsVar<F: PrimeField, const B: usize> {
    pub sources: [FpVar<F>; B],
    pub actives: [Boolean<F>; B],
    pub siblings: Vec<FpVar<F>>,
    pub directions: Vec<Boolean<F>>,
}

impl<F: PrimeField, const B: usize> AllocVar<CleanCheckStepInputs<F, B>, F>
    for CleanCheckStepInputsVar<F, B>
{
    fn new_variable<T: Borrow<CleanCheckStepInputs<F, B>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        f().and_then(|value| {
            let value = value.borrow();
            let sources: [FpVar<F>; B] = core::array::from_fn(|i| {
                FpVar::new_variable(cs.clone(), || Ok(value.sources[i]), mode).unwrap()
            });
            let actives: [Boolean<F>; B] = core::array::from_fn(|i| {
                Boolean::new_variable(cs.clone(), || Ok(value.actives[i]), mode).unwrap()
            });
            let siblings: Vec<FpVar<F>> = value
                .siblings
                .iter()
                .map(|s| FpVar::new_variable(cs.clone(), || Ok(*s), mode).unwrap())
                .collect();
            let directions: Vec<Boolean<F>> = value
                .directions
                .iter()
                .map(|d| Boolean::new_variable(cs.clone(), || Ok(*d), mode).unwrap())
                .collect();
            Ok(Self {
                sources,
                actives,
                siblings,
                directions,
            })
        })
    }
}

// ============================================================
// CleanCheckStepCircuit
// ============================================================

#[derive(Clone, Debug)]
pub struct CleanCheckStepCircuit<F: PrimeField + Absorb, const B: usize> {
    pub poseidon_params: PoseidonConfig<F>,
}

impl<F: PrimeField + Absorb, const B: usize> FCircuit<F> for CleanCheckStepCircuit<F, B> {
    type Params = PoseidonConfig<F>;
    type ExternalInputs = CleanCheckStepInputs<F, B>;
    type ExternalInputsVar = CleanCheckStepInputsVar<F, B>;

    fn new(params: Self::Params) -> Result<Self, Error> {
        Ok(Self {
            poseidon_params: params,
        })
    }

    fn state_len(&self) -> usize {
        // [clean_root, num_checked, all_ok]
        3
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let clean_root = &z_i[0];
        let num_checked = &z_i[1];
        // z_i[2] = all_ok (unused in logic, just passed through)

        let dst_leaf = FpVar::new_constant(cs.clone(), F::from(DST_SRC_LEAF as u64))?;
        let dst_node = FpVar::new_constant(cs.clone(), F::from(DST_SRC_NODE as u64))?;

        let mut checked_count = num_checked.clone();
        let one = FpVar::<F>::one();

        for i in 0..B {
            let source = &external_inputs.sources[i];
            let active = &external_inputs.actives[i];

            // LeafHash(source)
            let leaf = poseidon_gadget(
                &self.poseidon_params,
                cs.clone(),
                &[dst_leaf.clone(), source.clone()],
            )?;

            // Walk Merkle path (DEPTH levels)
            let mut current = leaf;
            for j in 0..MERKLE_DEPTH {
                let idx = i * MERKLE_DEPTH + j;
                let sibling = &external_inputs.siblings[idx];
                let dir = &external_inputs.directions[idx];

                let left =
                    CondSelectGadget::conditionally_select(dir, sibling, &current)?;
                let right =
                    CondSelectGadget::conditionally_select(dir, &current, sibling)?;

                current = poseidon_gadget(
                    &self.poseidon_params,
                    cs.clone(),
                    &[dst_node.clone(), left, right],
                )?;
            }

            // If active: computed root must equal clean_root
            // expected = active ? clean_root : current (so equality always holds for inactive)
            let expected =
                CondSelectGadget::conditionally_select(active, clean_root, &current)?;
            current.enforce_equal(&expected)?;

            // Increment checked count
            let inc = CondSelectGadget::conditionally_select(active, &one, &FpVar::zero())?;
            checked_count = &checked_count + &inc;
        }

        Ok(vec![clean_root.clone(), checked_count, z_i[2].clone()])
    }
}
