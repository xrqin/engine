//! Merge2StepCircuit — Nova FCircuit for C_SRC_STEP(mode=MERGE2).
//!
//! Each step performs B micro-merge operations: compares heads of two
//! sorted source streams, emits the smaller (deduplicates equals),
//! and appends to the output frontier.
//!
//! State vector z_i (D + 5 elements):
//!   [frontier[0..D-1], count, last_out, has_last_out, target_root, target_count]
//!
//! External inputs per step:
//!   For each micro-step t: (has_a, val_a, has_b, val_b)
//!   + is_final

use ark_crypto_primitives::sponge::{Absorb, poseidon::PoseidonConfig};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::{fp::FpVar, FieldVar},
    prelude::Boolean,
    select::CondSelectGadget,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::vec::Vec;
use core::borrow::Borrow;
use folding_schemes::{Error, frontend::FCircuit};

use crate::frontier_gadget::{
    DST_SRC_BAG, DST_SRC_LEAF, DST_SRC_NODE, DST_SRC_ROOT,
    append_leaf, assert_lt_when, bits_to_fp, enforce_eq_when, fold_frontier, fp_to_bits,
};

// ============================================================
// External Inputs
// ============================================================

#[derive(Clone, Debug)]
pub struct Merge2ExternalInputs<F: PrimeField, const B: usize> {
    pub has_a: [bool; B],
    pub val_a: [F; B],
    pub has_b: [bool; B],
    pub val_b: [F; B],
    pub is_final: bool,
}

impl<F: PrimeField, const B: usize> Default for Merge2ExternalInputs<F, B> {
    fn default() -> Self {
        Self {
            has_a: [false; B],
            val_a: [F::ZERO; B],
            has_b: [false; B],
            val_b: [F::ZERO; B],
            is_final: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Merge2ExternalInputsVar<F: PrimeField, const B: usize> {
    pub has_a: [Boolean<F>; B],
    pub val_a: [FpVar<F>; B],
    pub has_b: [Boolean<F>; B],
    pub val_b: [FpVar<F>; B],
    pub is_final: Boolean<F>,
}

impl<F: PrimeField, const B: usize> AllocVar<Merge2ExternalInputs<F, B>, F>
    for Merge2ExternalInputsVar<F, B>
{
    fn new_variable<T: Borrow<Merge2ExternalInputs<F, B>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        f().and_then(|value| {
            let value = value.borrow();
            let has_a: [Boolean<F>; B] = core::array::from_fn(|i| {
                Boolean::new_variable(cs.clone(), || Ok(value.has_a[i]), mode).unwrap()
            });
            let val_a: [FpVar<F>; B] = core::array::from_fn(|i| {
                FpVar::new_variable(cs.clone(), || Ok(value.val_a[i]), mode).unwrap()
            });
            let has_b: [Boolean<F>; B] = core::array::from_fn(|i| {
                Boolean::new_variable(cs.clone(), || Ok(value.has_b[i]), mode).unwrap()
            });
            let val_b: [FpVar<F>; B] = core::array::from_fn(|i| {
                FpVar::new_variable(cs.clone(), || Ok(value.val_b[i]), mode).unwrap()
            });
            let is_final = Boolean::new_variable(cs.clone(), || Ok(value.is_final), mode)?;
            Ok(Self {
                has_a,
                val_a,
                has_b,
                val_b,
                is_final,
            })
        })
    }
}

// ============================================================
// Merge2StepCircuit
// ============================================================

/// Nova FCircuit for MERGE2 mode of C_SRC_STEP.
///
/// - D: frontier depth
/// - B: micro-merge steps per Nova step (B_MERGE)
#[derive(Clone, Debug)]
pub struct Merge2StepCircuit<F: PrimeField + Absorb, const D: usize, const B: usize> {
    pub poseidon_params: PoseidonConfig<F>,
}

impl<F: PrimeField + Absorb, const D: usize, const B: usize> FCircuit<F>
    for Merge2StepCircuit<F, D, B>
{
    type Params = PoseidonConfig<F>;
    type ExternalInputs = Merge2ExternalInputs<F, B>;
    type ExternalInputsVar = Merge2ExternalInputsVar<F, B>;

    fn new(params: Self::Params) -> Result<Self, Error> {
        Ok(Self {
            poseidon_params: params,
        })
    }

    fn state_len(&self) -> usize {
        D + 5
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let frontier: Vec<FpVar<F>> = z_i[0..D].to_vec();
        let count = &z_i[D];
        let last_out = &z_i[D + 1];
        let has_last_out_fp = &z_i[D + 2];
        let target_root = &z_i[D + 3];
        let target_count = &z_i[D + 4];

        let dst_leaf = FpVar::new_constant(cs.clone(), F::from(DST_SRC_LEAF as u64))?;
        let dst_node = FpVar::new_constant(cs.clone(), F::from(DST_SRC_NODE as u64))?;
        let dst_bag = FpVar::new_constant(cs.clone(), F::from(DST_SRC_BAG as u64))?;
        let dst_root = FpVar::new_constant(cs.clone(), F::from(DST_SRC_ROOT as u64))?;

        let has_last_bits = fp_to_bits(has_last_out_fp, 1)?;
        let mut has_last = has_last_bits[0].clone();
        let mut count_bits = fp_to_bits(count, D)?;
        let mut cur_frontier = frontier;
        let mut cur_last = last_out.clone();

        // B micro-merge steps
        for t in 0..B {
            let ha = &external_inputs.has_a[t];
            let va = &external_inputs.val_a[t];
            let hb = &external_inputs.has_b[t];
            let vb = &external_inputs.val_b[t];

            // do_emit = has_a OR has_b
            let do_emit: Boolean<F> = ha | hb;

            // emit_val: prover provides pre-ordered values
            // if has_a: emit val_a; else: emit val_b
            let emit_val = CondSelectGadget::conditionally_select(ha, va, vb)?;

            // Strict ordering: if do_emit AND has_last, emit_val > last
            let check_order: Boolean<F> = &do_emit & &has_last;
            assert_lt_when(&check_order, &cur_last, &emit_val, 252)?;

            // AppendLeaf
            let (new_frontier, new_count_bits) = append_leaf(
                &self.poseidon_params,
                cs.clone(),
                &cur_frontier,
                &count_bits,
                &emit_val,
                &do_emit,
                &dst_leaf,
                &dst_node,
            )?;
            cur_frontier = new_frontier;
            count_bits = new_count_bits;

            // Update last/has_last
            cur_last = CondSelectGadget::conditionally_select(&do_emit, &emit_val, &cur_last)?;
            has_last = &has_last | &do_emit;
        }

        let new_count = bits_to_fp(&count_bits)?;

        let folded_root = fold_frontier(
            &self.poseidon_params,
            cs.clone(),
            &cur_frontier,
            &count_bits,
            &new_count,
            &dst_bag,
            &dst_root,
        )?;

        enforce_eq_when(&external_inputs.is_final, &folded_root, target_root)?;
        enforce_eq_when(&external_inputs.is_final, &new_count, target_count)?;

        let has_last_fp = FpVar::from(has_last);
        let mut z_out = cur_frontier;
        z_out.push(new_count);
        z_out.push(cur_last);
        z_out.push(has_last_fp);
        z_out.push(target_root.clone());
        z_out.push(target_count.clone());

        Ok(z_out)
    }
}
