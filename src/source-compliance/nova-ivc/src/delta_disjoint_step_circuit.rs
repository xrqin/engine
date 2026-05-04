//! DeltaDisjointStepCircuit — warm-cache prototype for accumulator-style refresh.
//!
//! This is an online-path proxy for:
//!   R_ACC_DISJOINT_DELTA: S_note ∩ RevokedDelta(old,current) = ∅
//!
//! Assumptions outside this step circuit:
//! - A note-local cache root is already built from the exact SrcSet.
//! - A reusable bind proof already ties that cache root to source_commitment.
//! - Revoked delta values are public policy inputs for the current refresh.
//!
//! Per revoked source, the witness provides adjacent predecessor/successor
//! leaves in the cached sorted note tree. The circuit proves:
//! - pred and succ are members of note_root;
//! - succ_index = pred_index + 1;
//! - pred_value < revoked < succ_value.
//!
//! Therefore the revoked source is not in the exact sorted note set, while
//! online work scales with delta size rather than note source count.

use ark_crypto_primitives::sponge::{poseidon::PoseidonConfig, Absorb};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    prelude::Boolean,
    select::CondSelectGadget,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::vec::Vec;
use core::borrow::Borrow;
use folding_schemes::{frontend::FCircuit, Error};

use crate::frontier_gadget::{assert_lt_when, enforce_eq_when, poseidon_gadget};

pub const DST_DELTA_CACHE_LEAF: u64 = 0x5244_4C01;
pub const DST_DELTA_CACHE_NODE: u64 = 0x5244_4E01;

#[derive(Clone, Debug)]
pub struct DeltaDisjointStepInputs<F: PrimeField, const B: usize, const DEPTH: usize> {
    pub revoked: [F; B],
    pub actives: [bool; B],
    pub pred_values: [F; B],
    pub succ_values: [F; B],
    pub pred_indices: [F; B],
    pub succ_indices: [F; B],
    pub pred_siblings: Vec<F>,
    pub succ_siblings: Vec<F>,
    pub pred_directions: Vec<bool>,
    pub succ_directions: Vec<bool>,
}

impl<F: PrimeField, const B: usize, const DEPTH: usize> Default
    for DeltaDisjointStepInputs<F, B, DEPTH>
{
    fn default() -> Self {
        Self {
            revoked: [F::ZERO; B],
            actives: [false; B],
            pred_values: [F::ZERO; B],
            succ_values: [F::ZERO; B],
            pred_indices: [F::ZERO; B],
            succ_indices: [F::ZERO; B],
            pred_siblings: vec![F::ZERO; B * DEPTH],
            succ_siblings: vec![F::ZERO; B * DEPTH],
            pred_directions: vec![false; B * DEPTH],
            succ_directions: vec![false; B * DEPTH],
        }
    }
}

#[derive(Clone, Debug)]
pub struct DeltaDisjointStepInputsVar<F: PrimeField, const B: usize, const DEPTH: usize> {
    pub revoked: [FpVar<F>; B],
    pub actives: [Boolean<F>; B],
    pub pred_values: [FpVar<F>; B],
    pub succ_values: [FpVar<F>; B],
    pub pred_indices: [FpVar<F>; B],
    pub succ_indices: [FpVar<F>; B],
    pub pred_siblings: Vec<FpVar<F>>,
    pub succ_siblings: Vec<FpVar<F>>,
    pub pred_directions: Vec<Boolean<F>>,
    pub succ_directions: Vec<Boolean<F>>,
}

impl<F: PrimeField, const B: usize, const DEPTH: usize>
    AllocVar<DeltaDisjointStepInputs<F, B, DEPTH>, F>
    for DeltaDisjointStepInputsVar<F, B, DEPTH>
{
    fn new_variable<T: Borrow<DeltaDisjointStepInputs<F, B, DEPTH>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        f().and_then(|value| {
            let value = value.borrow();
            let revoked = core::array::from_fn(|i| {
                FpVar::new_variable(cs.clone(), || Ok(value.revoked[i]), mode).unwrap()
            });
            let actives = core::array::from_fn(|i| {
                Boolean::new_variable(cs.clone(), || Ok(value.actives[i]), mode).unwrap()
            });
            let pred_values = core::array::from_fn(|i| {
                FpVar::new_variable(cs.clone(), || Ok(value.pred_values[i]), mode).unwrap()
            });
            let succ_values = core::array::from_fn(|i| {
                FpVar::new_variable(cs.clone(), || Ok(value.succ_values[i]), mode).unwrap()
            });
            let pred_indices = core::array::from_fn(|i| {
                FpVar::new_variable(cs.clone(), || Ok(value.pred_indices[i]), mode).unwrap()
            });
            let succ_indices = core::array::from_fn(|i| {
                FpVar::new_variable(cs.clone(), || Ok(value.succ_indices[i]), mode).unwrap()
            });
            let pred_siblings = value
                .pred_siblings
                .iter()
                .map(|s| FpVar::new_variable(cs.clone(), || Ok(*s), mode).unwrap())
                .collect();
            let succ_siblings = value
                .succ_siblings
                .iter()
                .map(|s| FpVar::new_variable(cs.clone(), || Ok(*s), mode).unwrap())
                .collect();
            let pred_directions = value
                .pred_directions
                .iter()
                .map(|d| Boolean::new_variable(cs.clone(), || Ok(*d), mode).unwrap())
                .collect();
            let succ_directions = value
                .succ_directions
                .iter()
                .map(|d| Boolean::new_variable(cs.clone(), || Ok(*d), mode).unwrap())
                .collect();
            Ok(Self {
                revoked,
                actives,
                pred_values,
                succ_values,
                pred_indices,
                succ_indices,
                pred_siblings,
                succ_siblings,
                pred_directions,
                succ_directions,
            })
        })
    }
}

#[derive(Clone, Debug)]
pub struct DeltaDisjointStepCircuit<F: PrimeField + Absorb, const B: usize, const DEPTH: usize> {
    pub poseidon_params: PoseidonConfig<F>,
}

impl<F: PrimeField + Absorb, const B: usize, const DEPTH: usize> DeltaDisjointStepCircuit<F, B, DEPTH> {
    fn merkle_root_var(
        &self,
        cs: ConstraintSystemRef<F>,
        index: &FpVar<F>,
        value: &FpVar<F>,
        siblings: &[FpVar<F>],
        directions: &[Boolean<F>],
        dst_leaf: &FpVar<F>,
        dst_node: &FpVar<F>,
    ) -> Result<FpVar<F>, SynthesisError> {
        let mut current = poseidon_gadget(
            &self.poseidon_params,
            cs.clone(),
            &[dst_leaf.clone(), index.clone(), value.clone()],
        )?;

        for depth in 0..DEPTH {
            let sibling = &siblings[depth];
            let dir = &directions[depth];
            let left = CondSelectGadget::conditionally_select(dir, sibling, &current)?;
            let right = CondSelectGadget::conditionally_select(dir, &current, sibling)?;
            current = poseidon_gadget(
                &self.poseidon_params,
                cs.clone(),
                &[dst_node.clone(), left, right],
            )?;
        }

        Ok(current)
    }
}

impl<F: PrimeField + Absorb, const B: usize, const DEPTH: usize> FCircuit<F>
    for DeltaDisjointStepCircuit<F, B, DEPTH>
{
    type Params = PoseidonConfig<F>;
    type ExternalInputs = DeltaDisjointStepInputs<F, B, DEPTH>;
    type ExternalInputsVar = DeltaDisjointStepInputsVar<F, B, DEPTH>;

    fn new(params: Self::Params) -> Result<Self, Error> {
        Ok(Self {
            poseidon_params: params,
        })
    }

    fn state_len(&self) -> usize {
        // [note_cache_root, num_delta_checked, all_ok]
        3
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let note_root = &z_i[0];
        let mut checked_count = z_i[1].clone();
        let one = FpVar::<F>::one();

        let dst_leaf = FpVar::new_constant(cs.clone(), F::from(DST_DELTA_CACHE_LEAF))?;
        let dst_node = FpVar::new_constant(cs.clone(), F::from(DST_DELTA_CACHE_NODE))?;

        for i in 0..B {
            let active = &external_inputs.actives[i];
            let pred_root = self.merkle_root_var(
                cs.clone(),
                &external_inputs.pred_indices[i],
                &external_inputs.pred_values[i],
                &external_inputs.pred_siblings[i * DEPTH..(i + 1) * DEPTH],
                &external_inputs.pred_directions[i * DEPTH..(i + 1) * DEPTH],
                &dst_leaf,
                &dst_node,
            )?;
            let succ_root = self.merkle_root_var(
                cs.clone(),
                &external_inputs.succ_indices[i],
                &external_inputs.succ_values[i],
                &external_inputs.succ_siblings[i * DEPTH..(i + 1) * DEPTH],
                &external_inputs.succ_directions[i * DEPTH..(i + 1) * DEPTH],
                &dst_leaf,
                &dst_node,
            )?;

            let expected_pred =
                CondSelectGadget::conditionally_select(active, note_root, &pred_root)?;
            let expected_succ =
                CondSelectGadget::conditionally_select(active, note_root, &succ_root)?;
            pred_root.enforce_equal(&expected_pred)?;
            succ_root.enforce_equal(&expected_succ)?;

            let pred_plus_one = &external_inputs.pred_indices[i] + &one;
            enforce_eq_when(active, &pred_plus_one, &external_inputs.succ_indices[i])?;
            assert_lt_when(active, &external_inputs.pred_values[i], &external_inputs.revoked[i], 64)?;
            assert_lt_when(active, &external_inputs.revoked[i], &external_inputs.succ_values[i], 64)?;

            let inc = CondSelectGadget::conditionally_select(active, &one, &FpVar::zero())?;
            checked_count = &checked_count + &inc;
        }

        Ok(vec![note_root.clone(), checked_count, z_i[2].clone()])
    }
}
