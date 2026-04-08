//! MergeStepCircuit — Nova FCircuit for R_MERGE2 folding.
//!
//! Modeled directly on zERC20's WithdrawCircuit (withdraw_nova.rs).
//!
//! State vector z_i = [acc_root, acc_count, hash_chain]  (3 elements)
//!
//! External inputs per step:
//!   - is_dummy: bool (for padding to power-of-2)
//!   - right_root: the canonical set tree root of the set to merge
//!   - right_count: the element count of the right set
//!
//! Step semantics (in-circuit):
//!   1. If is_dummy: z_{i+1} = z_i (no-op)
//!   2. Otherwise:
//!      - new_root = Poseidon(DST_MERGE, acc_root, acc_count, right_root, right_count)
//!      - new_count = acc_count + right_count  (upper bound; exact dedup is external)
//!      - new_hash_chain = Poseidon(DST_CHAIN, hash_chain, acc_root, new_root, step_marker)
//!      - z_{i+1} = [new_root, new_count, new_hash_chain]
//!
//! NOTE: The exact union (sorted dedup) is computed off-circuit by the prover.
//! The circuit only verifies the hash-chain commitment over the merge sequence.
//! The actual set membership proof is done via R_SUBSET_FROM_TREE against A_policy.

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::{Absorb, poseidon::PoseidonConfig};
use ark_ff::{AdditiveGroup, PrimeField, Zero};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::fp::FpVar,
    prelude::Boolean,
    select::CondSelectGadget,
    GR1CSVar,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::vec::Vec;
use core::borrow::Borrow;
use folding_schemes::{Error, frontend::FCircuit};

/// State vector length: [acc_root, acc_count, hash_chain]
pub const MERGE_STATE_LEN: usize = 3;

/// Domain separation constants (as field elements).
/// These match the DSTs in the TypeScript engine.
const DST_MERGE_STEP: u64 = 0x524d53_01; // "RMS\x01" - RAILGUN Merge Step
const DST_HASH_CHAIN: u64 = 0x524843_01; // "RHC\x01" - RAILGUN Hash Chain

// ============================================================
// External Inputs (analogous to zERC20's WithdrawExternalInputs)
// ============================================================

#[derive(Clone, Debug)]
pub struct MergeExternalInputs<F: PrimeField> {
    /// If true, this is a dummy/padding step (no-op).
    pub is_dummy: bool,
    /// Canonical set tree root of the right set to merge.
    pub right_root: F,
    /// Element count of the right set.
    pub right_count: F,
}

impl<F: PrimeField> Default for MergeExternalInputs<F> {
    fn default() -> Self {
        Self {
            is_dummy: true,
            right_root: F::ZERO,
            right_count: F::ZERO,
        }
    }
}

// R1CS variable version
#[derive(Clone, Debug)]
pub struct MergeExternalInputsVar<F: PrimeField> {
    pub is_dummy: Boolean<F>,
    pub right_root: FpVar<F>,
    pub right_count: FpVar<F>,
}

impl<F: PrimeField> AllocVar<MergeExternalInputs<F>, F> for MergeExternalInputsVar<F> {
    fn new_variable<T: Borrow<MergeExternalInputs<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        f().and_then(|value| {
            let value = value.borrow();
            let is_dummy = Boolean::new_variable(cs.clone(), || Ok(value.is_dummy), mode)?;
            let right_root = FpVar::<F>::new_variable(cs.clone(), || Ok(value.right_root), mode)?;
            let right_count = FpVar::<F>::new_variable(cs, || Ok(value.right_count), mode)?;
            Ok(Self {
                is_dummy,
                right_root,
                right_count,
            })
        })
    }
}

// ============================================================
// MergeStepCircuit (analogous to zERC20's WithdrawCircuit)
// ============================================================

#[derive(Clone, Debug)]
pub struct MergeStepCircuit<F: PrimeField + Absorb> {
    pub poseidon_params: PoseidonConfig<F>,
}

impl<F: PrimeField + Absorb> FCircuit<F> for MergeStepCircuit<F> {
    type Params = PoseidonConfig<F>;
    type ExternalInputs = MergeExternalInputs<F>;
    type ExternalInputsVar = MergeExternalInputsVar<F>;

    fn new(params: Self::Params) -> Result<Self, Error> {
        Ok(Self {
            poseidon_params: params,
        })
    }

    fn state_len(&self) -> usize {
        MERGE_STATE_LEN
    }

    /// Generate step constraints.
    ///
    /// z_i = [acc_root, acc_count, hash_chain]
    /// external_inputs = { is_dummy, right_root, right_count }
    ///
    /// If is_dummy: z_{i+1} = z_i
    /// Else:
    ///   merged_root  = Poseidon(DST_MERGE, acc_root, acc_count, right_root, right_count)
    ///   merged_count = acc_count + right_count
    ///   new_chain    = Poseidon(DST_CHAIN, hash_chain, acc_root, merged_root)
    ///   z_{i+1}      = [merged_root, merged_count, new_chain]
    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // Unpack state
        let acc_root = &z_i[0];
        let acc_count = &z_i[1];
        let hash_chain = &z_i[2];

        // Unpack external inputs
        let MergeExternalInputsVar {
            is_dummy,
            right_root,
            right_count,
        } = external_inputs;

        // DST constants
        let dst_merge = FpVar::new_constant(cs.clone(), F::from(DST_MERGE_STEP))?;
        let dst_chain = FpVar::new_constant(cs, F::from(DST_HASH_CHAIN))?;

        // Compute merged_root = Poseidon(dst_merge, acc_root, acc_count, right_root, right_count)
        let merged_root = poseidon_gadget(
            &self.poseidon_params,
            &[
                dst_merge.clone(),
                acc_root.clone(),
                acc_count.clone(),
                right_root,
                right_count.clone(),
            ],
        )?;

        // merged_count = acc_count + right_count
        let merged_count = acc_count + &right_count;

        // new_chain = Poseidon(dst_chain, hash_chain, acc_root, merged_root)
        let new_chain = poseidon_gadget(
            &self.poseidon_params,
            &[
                dst_chain,
                hash_chain.clone(),
                acc_root.clone(),
                merged_root.clone(),
            ],
        )?;

        // Conditional select: if is_dummy, keep z_i; else use new values
        let out_root = CondSelectGadget::conditionally_select(&is_dummy, acc_root, &merged_root)?;
        let out_count =
            CondSelectGadget::conditionally_select(&is_dummy, acc_count, &merged_count)?;
        let out_chain = CondSelectGadget::conditionally_select(&is_dummy, hash_chain, &new_chain)?;

        Ok(vec![out_root, out_count, out_chain])
    }
}

// ============================================================
// Poseidon gadget (in-circuit Poseidon hash)
// ============================================================

fn poseidon_gadget<F: PrimeField + Absorb>(
    params: &PoseidonConfig<F>,
    inputs: &[FpVar<F>],
) -> Result<FpVar<F>, SynthesisError> {
    use ark_crypto_primitives::sponge::{
        constraints::CryptographicSpongeVar,
        poseidon::constraints::PoseidonSpongeVar,
    };
    use ark_r1cs_std::GR1CSVar;

    let cs = inputs[0].cs();
    let mut sponge = PoseidonSpongeVar::new(cs, params);
    sponge.absorb(&inputs)?;
    let output = sponge.squeeze_field_elements(1)?;
    Ok(output[0].clone())
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::NovaParams;
    use ark_bn254::Fr;
    use ark_ff::AdditiveGroup;
    use folding_schemes::FoldingScheme;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn test_merge_step_circuit_basic() {
        let mut rng = StdRng::seed_from_u64(42);
        let poseidon_config = crate::poseidon_config::nova_poseidon_config();

        // Setup Nova params
        let nova_params =
            NovaParams::<MergeStepCircuit<Fr>>::rand(poseidon_config.clone(), &mut rng)
                .expect("Nova setup should succeed");

        // Initial state: z_0 = [initial_root, count=1, initial_chain]
        let initial_root = Fr::from(12345u64);
        let initial_count = Fr::from(1u64);
        let initial_chain = Fr::from(0u64);
        let z_0 = vec![initial_root, initial_count, initial_chain];

        // Create Nova instance
        let mut nova = nova_params.initial_nova(z_0.clone()).expect("Nova init");

        // Step 1: merge with a real set
        let ext_input_1 = MergeExternalInputs {
            is_dummy: false,
            right_root: Fr::from(67890u64),
            right_count: Fr::from(3u64),
        };
        nova.prove_step(&mut rng, ext_input_1, None)
            .expect("prove_step 1");

        // Step 2: merge with another set
        let ext_input_2 = MergeExternalInputs {
            is_dummy: false,
            right_root: Fr::from(11111u64),
            right_count: Fr::from(2u64),
        };
        nova.prove_step(&mut rng, ext_input_2, None)
            .expect("prove_step 2");

        // Step 3: dummy step (padding)
        let ext_input_3 = MergeExternalInputs::default();
        nova.prove_step(&mut rng, ext_input_3, None)
            .expect("prove_step 3 (dummy)");

        // Verify the IVC proof
        let ivc_proof = nova.ivc_proof();
        nova_params.verify(ivc_proof).expect("IVC verification should pass");

        // Check final state
        let final_state = nova.state();
        assert_eq!(final_state.len(), MERGE_STATE_LEN);
        // acc_count should be 1 + 3 + 2 = 6 (dummy doesn't change count)
        assert_eq!(final_state[1], Fr::from(6u64));
    }

    #[test]
    fn test_merge_step_circuit_many_steps() {
        let mut rng = StdRng::seed_from_u64(99);
        let poseidon_config = crate::poseidon_config::nova_poseidon_config();

        let nova_params =
            NovaParams::<MergeStepCircuit<Fr>>::rand(poseidon_config.clone(), &mut rng)
                .expect("Nova setup should succeed");

        let z_0 = vec![Fr::from(1u64), Fr::from(1u64), Fr::ZERO];
        let mut nova = nova_params.initial_nova(z_0).expect("Nova init");

        // Fold 8 merge steps
        for i in 0..8 {
            let ext = MergeExternalInputs {
                is_dummy: false,
                right_root: Fr::from(1000u64 + i as u64),
                right_count: Fr::from(4u64),
            };
            nova.prove_step(&mut rng, ext, None)
                .expect(&format!("prove_step {}", i));
        }

        let ivc_proof = nova.ivc_proof();
        nova_params.verify(ivc_proof).expect("IVC verification after 8 steps");

        let final_state = nova.state();
        // 1 + 8*4 = 33
        assert_eq!(final_state[1], Fr::from(33u64));
    }
}
