//! BindSortedScanStepCircuit — cold bind proof proxy.
//!
//! This is a prototype step circuit for measuring the cold/offline cost of
//! reusable bind proof construction. It is not the full production
//! R_ACC_BIND_NOTE relation.
//!
//! The step proves, for a batch of canonical sources:
//! - active sources are strictly increasing relative to the previous active
//!   source carried in state;
//! - descriptor_digest absorbs every active source in order;
//! - cache_digest absorbs every active source in order.
//!
//! It intentionally uses rolling Poseidon digests as a proxy for the
//! production descriptor/cache roots so the benchmark isolates sorted-scan
//! proof cost.

use ark_crypto_primitives::sponge::{poseidon::PoseidonConfig, Absorb};
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
use folding_schemes::{frontend::FCircuit, Error};

use crate::frontier_gadget::{assert_lt_when, poseidon_gadget};

pub const DST_BIND_DESC_ROLL: u64 = 0x5242_4401;
pub const DST_BIND_CACHE_ROLL: u64 = 0x5242_4301;

#[derive(Clone, Debug)]
pub struct BindSortedScanStepInputs<F: PrimeField, const B: usize> {
    pub sources: [F; B],
    pub actives: [bool; B],
}

impl<F: PrimeField, const B: usize> Default for BindSortedScanStepInputs<F, B> {
    fn default() -> Self {
        Self {
            sources: [F::ZERO; B],
            actives: [false; B],
        }
    }
}

#[derive(Clone, Debug)]
pub struct BindSortedScanStepInputsVar<F: PrimeField, const B: usize> {
    pub sources: [FpVar<F>; B],
    pub actives: [Boolean<F>; B],
}

impl<F: PrimeField, const B: usize> AllocVar<BindSortedScanStepInputs<F, B>, F>
    for BindSortedScanStepInputsVar<F, B>
{
    fn new_variable<T: Borrow<BindSortedScanStepInputs<F, B>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        f().and_then(|value| {
            let value = value.borrow();
            let sources = core::array::from_fn(|i| {
                FpVar::new_variable(cs.clone(), || Ok(value.sources[i]), mode).unwrap()
            });
            let actives = core::array::from_fn(|i| {
                Boolean::new_variable(cs.clone(), || Ok(value.actives[i]), mode).unwrap()
            });
            Ok(Self { sources, actives })
        })
    }
}

#[derive(Clone, Debug)]
pub struct BindSortedScanStepCircuit<F: PrimeField + Absorb, const B: usize> {
    pub poseidon_params: PoseidonConfig<F>,
}

impl<F: PrimeField + Absorb, const B: usize> FCircuit<F> for BindSortedScanStepCircuit<F, B> {
    type Params = PoseidonConfig<F>;
    type ExternalInputs = BindSortedScanStepInputs<F, B>;
    type ExternalInputsVar = BindSortedScanStepInputsVar<F, B>;

    fn new(params: Self::Params) -> Result<Self, Error> {
        Ok(Self {
            poseidon_params: params,
        })
    }

    fn state_len(&self) -> usize {
        // [prev_source, count, descriptor_digest, cache_digest, all_ok]
        5
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let mut prev_source = z_i[0].clone();
        let mut count = z_i[1].clone();
        let mut descriptor_digest = z_i[2].clone();
        let mut cache_digest = z_i[3].clone();
        let all_ok = z_i[4].clone();

        let one = FpVar::<F>::one();
        let desc_dst = FpVar::new_constant(cs.clone(), F::from(DST_BIND_DESC_ROLL))?;
        let cache_dst = FpVar::new_constant(cs.clone(), F::from(DST_BIND_CACHE_ROLL))?;

        for i in 0..B {
            let source = &external_inputs.sources[i];
            let active = &external_inputs.actives[i];

            // The benchmark source domain uses positive 64-bit values and
            // initializes prev_source to 0 as the lower sentinel.
            assert_lt_when(active, &prev_source, source, 64)?;

            let next_descriptor_digest = poseidon_gadget(
                &self.poseidon_params,
                cs.clone(),
                &[
                    desc_dst.clone(),
                    descriptor_digest.clone(),
                    count.clone(),
                    source.clone(),
                ],
            )?;
            let next_cache_digest = poseidon_gadget(
                &self.poseidon_params,
                cs.clone(),
                &[cache_dst.clone(), cache_digest.clone(), source.clone()],
            )?;

            descriptor_digest = CondSelectGadget::conditionally_select(
                active,
                &next_descriptor_digest,
                &descriptor_digest,
            )?;
            cache_digest =
                CondSelectGadget::conditionally_select(active, &next_cache_digest, &cache_digest)?;
            prev_source = CondSelectGadget::conditionally_select(active, source, &prev_source)?;

            let inc = CondSelectGadget::conditionally_select(active, &one, &FpVar::zero())?;
            count = &count + &inc;
        }

        Ok(vec![
            prev_source,
            count,
            descriptor_digest,
            cache_digest,
            all_ok,
        ])
    }
}
