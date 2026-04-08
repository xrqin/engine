//! ScanStepCircuit — Nova FCircuit for C_SRC_STEP(mode=SCAN).
//!
//! Each step processes B source primes: verifies strict ordering,
//! appends each to the binary frontier, and on the final step verifies
//! the frontier folds to the target descriptor.
//!
//! State vector z_i (D + 5 elements):
//!   [frontier[0..D-1], count, last, has_last, target_root, target_count]
//!
//! External inputs per step:
//!   - sources[B]: source prime values
//!   - valids[B]: validity bits (prefix-1/suffix-0)
//!   - is_final: bool (1 on last step)

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
pub struct ScanExternalInputs<F: PrimeField, const B: usize> {
    pub sources: [F; B],
    pub valids: [bool; B],
    pub is_final: bool,
}

impl<F: PrimeField, const B: usize> Default for ScanExternalInputs<F, B> {
    fn default() -> Self {
        Self {
            sources: [F::ZERO; B],
            valids: [false; B],
            is_final: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ScanExternalInputsVar<F: PrimeField, const B: usize> {
    pub sources: [FpVar<F>; B],
    pub valids: [Boolean<F>; B],
    pub is_final: Boolean<F>,
}

impl<F: PrimeField, const B: usize> AllocVar<ScanExternalInputs<F, B>, F>
    for ScanExternalInputsVar<F, B>
{
    fn new_variable<T: Borrow<ScanExternalInputs<F, B>>>(
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
            let valids: [Boolean<F>; B] = core::array::from_fn(|i| {
                Boolean::new_variable(cs.clone(), || Ok(value.valids[i]), mode).unwrap()
            });
            let is_final = Boolean::new_variable(cs.clone(), || Ok(value.is_final), mode)?;
            Ok(Self {
                sources,
                valids,
                is_final,
            })
        })
    }
}

// ============================================================
// ScanStepCircuit
// ============================================================

/// Nova FCircuit for SCAN mode of C_SRC_STEP.
///
/// - D: frontier depth (max sources = 2^D)
/// - B: sources per step (B_SCAN)
#[derive(Clone, Debug)]
pub struct ScanStepCircuit<F: PrimeField + Absorb, const D: usize, const B: usize> {
    pub poseidon_params: PoseidonConfig<F>,
}

impl<F: PrimeField + Absorb, const D: usize, const B: usize> FCircuit<F>
    for ScanStepCircuit<F, D, B>
{
    type Params = PoseidonConfig<F>;
    type ExternalInputs = ScanExternalInputs<F, B>;
    type ExternalInputsVar = ScanExternalInputsVar<F, B>;

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
        // Unpack state
        let frontier: Vec<FpVar<F>> = z_i[0..D].to_vec();
        let count = &z_i[D];
        let last_in = &z_i[D + 1];
        let has_last_in = &z_i[D + 2];
        let target_root = &z_i[D + 3];
        let target_count = &z_i[D + 4];

        // DST constants
        let dst_leaf = FpVar::new_constant(cs.clone(), F::from(DST_SRC_LEAF as u64))?;
        let dst_node = FpVar::new_constant(cs.clone(), F::from(DST_SRC_NODE as u64))?;
        let dst_bag = FpVar::new_constant(cs.clone(), F::from(DST_SRC_BAG as u64))?;
        let dst_root = FpVar::new_constant(cs.clone(), F::from(DST_SRC_ROOT as u64))?;

        // Decompose state
        let has_last_bits = fp_to_bits(has_last_in, 1)?;
        let mut has_last = has_last_bits[0].clone();
        let mut count_bits = fp_to_bits(count, D)?;
        let mut cur_frontier = frontier;
        let mut cur_last = last_in.clone();

        // Process B sources per step
        for i in 0..B {
            let source = &external_inputs.sources[i];
            let valid = &external_inputs.valids[i];

            // Ordering check: if valid AND has_last, enforce last < source
            let check_order: Boolean<F> = valid & &has_last;
            assert_lt_when(&check_order, &cur_last, source, 252)?;

            // AppendLeaf (conditional on valid)
            let (new_frontier, new_count_bits) = append_leaf(
                &self.poseidon_params,
                cs.clone(),
                &cur_frontier,
                &count_bits,
                source,
                valid,
                &dst_leaf,
                &dst_node,
            )?;
            cur_frontier = new_frontier;
            count_bits = new_count_bits;

            // Update last/has_last
            cur_last = CondSelectGadget::conditionally_select(valid, source, &cur_last)?;
            has_last = &has_last | valid;
        }

        // Recompose count
        let new_count = bits_to_fp(&count_bits)?;

        // FoldFrontier (every step for circuit uniformity)
        let folded_root = fold_frontier(
            &self.poseidon_params,
            cs.clone(),
            &cur_frontier,
            &count_bits,
            &new_count,
            &dst_bag,
            &dst_root,
        )?;

        // Final step: enforce folded_root == target
        enforce_eq_when(&external_inputs.is_final, &folded_root, target_root)?;
        enforce_eq_when(&external_inputs.is_final, &new_count, target_count)?;

        // Pack output state
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
