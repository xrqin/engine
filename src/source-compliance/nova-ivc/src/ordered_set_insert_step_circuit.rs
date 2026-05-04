//! OrderedSetInsertStepCircuit — incremental ordered-set update proxy.
//!
//! This prototype measures whether an already authenticated source set can be
//! updated by proving only local insertions instead of rebuilding a full bind
//! proof. It uses a sparse Merkle tree keyed by the source value.
//!
//! Per inserted source key, the circuit proves:
//! - the old sparse leaf at key is empty;
//! - the old empty-leaf path reconstructs the current root;
//! - replacing that leaf with LeafHash(key) yields the next root.
//!
//! This is not a production R_ACC_BIND_NOTE relation. It does not materialize
//! the flat BuildSourceDescriptor root, and it does not include an outer
//! wrapper. It is an incremental update cost proxy.

use ark_crypto_primitives::sponge::{poseidon::PoseidonConfig, Absorb};
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
use folding_schemes::{frontend::FCircuit, Error};

use crate::frontier_gadget::poseidon_gadget;

pub const DST_ORDERED_SET_LEAF: u64 = 0x524F_4C01;
pub const DST_ORDERED_SET_NODE: u64 = 0x524F_4E01;

#[derive(Clone, Debug)]
pub struct OrderedSetInsertStepInputs<F: PrimeField, const B: usize, const DEPTH: usize> {
    pub keys: [F; B],
    pub actives: [bool; B],
    pub siblings: Vec<F>,
}

impl<F: PrimeField, const B: usize, const DEPTH: usize> Default
    for OrderedSetInsertStepInputs<F, B, DEPTH>
{
    fn default() -> Self {
        Self {
            keys: [F::ZERO; B],
            actives: [false; B],
            siblings: vec![F::ZERO; B * DEPTH],
        }
    }
}

#[derive(Clone, Debug)]
pub struct OrderedSetInsertStepInputsVar<F: PrimeField, const B: usize, const DEPTH: usize> {
    pub keys: [FpVar<F>; B],
    pub actives: [Boolean<F>; B],
    pub siblings: Vec<FpVar<F>>,
}

impl<F: PrimeField, const B: usize, const DEPTH: usize>
    AllocVar<OrderedSetInsertStepInputs<F, B, DEPTH>, F>
    for OrderedSetInsertStepInputsVar<F, B, DEPTH>
{
    fn new_variable<T: Borrow<OrderedSetInsertStepInputs<F, B, DEPTH>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        f().and_then(|value| {
            let value = value.borrow();
            let keys = core::array::from_fn(|i| {
                FpVar::new_variable(cs.clone(), || Ok(value.keys[i]), mode).unwrap()
            });
            let actives = core::array::from_fn(|i| {
                Boolean::new_variable(cs.clone(), || Ok(value.actives[i]), mode).unwrap()
            });
            let siblings = value
                .siblings
                .iter()
                .map(|s| FpVar::new_variable(cs.clone(), || Ok(*s), mode).unwrap())
                .collect();
            Ok(Self {
                keys,
                actives,
                siblings,
            })
        })
    }
}

#[derive(Clone, Debug)]
pub struct OrderedSetInsertStepCircuit<F: PrimeField + Absorb, const B: usize, const DEPTH: usize> {
    pub poseidon_params: PoseidonConfig<F>,
}

impl<F: PrimeField + Absorb, const B: usize, const DEPTH: usize>
    OrderedSetInsertStepCircuit<F, B, DEPTH>
{
    fn leaf_var(
        &self,
        cs: ConstraintSystemRef<F>,
        key: &FpVar<F>,
        dst_leaf: &FpVar<F>,
    ) -> Result<FpVar<F>, SynthesisError> {
        poseidon_gadget(&self.poseidon_params, cs, &[dst_leaf.clone(), key.clone()])
    }

    fn root_from_leaf_var(
        &self,
        cs: ConstraintSystemRef<F>,
        key: &FpVar<F>,
        leaf: &FpVar<F>,
        siblings: &[FpVar<F>],
        dst_node: &FpVar<F>,
    ) -> Result<FpVar<F>, SynthesisError> {
        let bits = key.to_bits_le()?;
        for bit in bits.iter().skip(DEPTH) {
            bit.enforce_equal(&Boolean::constant(false))?;
        }

        let mut current = leaf.clone();
        for depth in 0..DEPTH {
            let dir = &bits[depth];
            let sibling = &siblings[depth];
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
    for OrderedSetInsertStepCircuit<F, B, DEPTH>
{
    type Params = PoseidonConfig<F>;
    type ExternalInputs = OrderedSetInsertStepInputs<F, B, DEPTH>;
    type ExternalInputsVar = OrderedSetInsertStepInputsVar<F, B, DEPTH>;

    fn new(params: Self::Params) -> Result<Self, Error> {
        Ok(Self {
            poseidon_params: params,
        })
    }

    fn state_len(&self) -> usize {
        // [current_root, num_inserted, all_ok]
        3
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let mut current_root = z_i[0].clone();
        let mut inserted_count = z_i[1].clone();
        let all_ok = z_i[2].clone();

        let zero_leaf = FpVar::<F>::zero();
        let one = FpVar::<F>::one();
        let dst_leaf = FpVar::new_constant(cs.clone(), F::from(DST_ORDERED_SET_LEAF))?;
        let dst_node = FpVar::new_constant(cs.clone(), F::from(DST_ORDERED_SET_NODE))?;

        for i in 0..B {
            let key = &external_inputs.keys[i];
            let active = &external_inputs.actives[i];
            let siblings = &external_inputs.siblings[i * DEPTH..(i + 1) * DEPTH];

            let old_root =
                self.root_from_leaf_var(cs.clone(), key, &zero_leaf, siblings, &dst_node)?;
            let expected_old =
                CondSelectGadget::conditionally_select(active, &current_root, &old_root)?;
            old_root.enforce_equal(&expected_old)?;

            let inserted_leaf = self.leaf_var(cs.clone(), key, &dst_leaf)?;
            let next_root =
                self.root_from_leaf_var(cs.clone(), key, &inserted_leaf, siblings, &dst_node)?;
            current_root =
                CondSelectGadget::conditionally_select(active, &next_root, &current_root)?;

            let inc = CondSelectGadget::conditionally_select(active, &one, &FpVar::zero())?;
            inserted_count = &inserted_count + &inc;
        }

        Ok(vec![current_root, inserted_count, all_ok])
    }
}
