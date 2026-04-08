//! Frontier gadgets for source descriptor construction in R1CS.
//!
//! Implements AppendLeafFrontier and FoldFrontier as arkworks R1CS gadgets,
//! matching the circom source-descriptor.circom implementation.

use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{constraints::PoseidonSpongeVar, PoseidonConfig},
    Absorb,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    convert::ToBitsGadget,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    prelude::Boolean,
    select::CondSelectGadget,
};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use core::ops::{BitAnd, Not};

// Domain separation tags matching the TypeScript engine and circom
pub const DST_SRC_LEAF: u64 = 0x524C56_03;
pub const DST_SRC_NODE: u64 = 0x524E56_03;
pub const DST_SRC_BAG: u64 = 0x525342_01;
pub const DST_SRC_ROOT: u64 = 0x525352_01;

/// In-circuit Poseidon hash (sponge mode, arbitrary inputs).
pub fn poseidon_gadget<F: PrimeField + Absorb>(
    params: &PoseidonConfig<F>,
    cs: ConstraintSystemRef<F>,
    inputs: &[FpVar<F>],
) -> Result<FpVar<F>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::new(cs, params);
    sponge.absorb(&inputs.to_vec())?;
    let out = sponge.squeeze_field_elements(1)?;
    Ok(out[0].clone())
}

/// Increment a D-bit binary number by 1, conditional on `do_increment`.
pub fn increment_bits<F: PrimeField>(
    bits: &[Boolean<F>],
    do_increment: &Boolean<F>,
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    let d = bits.len();
    let mut carry = do_increment.clone();
    let mut new_bits = Vec::with_capacity(d);

    for h in 0..d {
        // new_bit = bit XOR carry
        let new_bit = &bits[h] ^ &carry;
        // new_carry = bit AND carry
        let new_carry = &bits[h] & &carry;
        new_bits.push(new_bit);
        carry = new_carry;
    }

    Ok(new_bits)
}

/// Reconstruct a field element from bits (little-endian).
pub fn bits_to_fp<F: PrimeField>(bits: &[Boolean<F>]) -> Result<FpVar<F>, SynthesisError> {
    let mut acc = FpVar::<F>::zero();
    let mut power = F::one();
    for bit in bits {
        let bit_fp = FpVar::from(bit.clone());
        acc = acc + FpVar::constant(power) * &bit_fp;
        power.double_in_place();
    }
    Ok(acc)
}

/// Decompose a field element into D bits (little-endian).
/// Enforces that the value fits in D bits.
pub fn fp_to_bits<F: PrimeField>(
    val: &FpVar<F>,
    d: usize,
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    let all_bits = val.to_bits_le()?;
    let mut bits = Vec::with_capacity(d);
    for i in 0..d {
        bits.push(all_bits[i].clone());
    }
    // Enforce higher bits are 0
    for i in d..all_bits.len() {
        all_bits[i].enforce_equal(&Boolean::constant(false))?;
    }
    Ok(bits)
}

/// AppendLeaf to the binary append frontier.
///
/// Implements the carry-chain based append operation matching circom's
/// AppendLeafFrontier(D).
///
/// Returns: (new_frontier, new_count_bits)
pub fn append_leaf<F: PrimeField + Absorb>(
    params: &PoseidonConfig<F>,
    cs: ConstraintSystemRef<F>,
    frontier: &[FpVar<F>],
    count_bits: &[Boolean<F>],
    leaf_value: &FpVar<F>,
    do_append: &Boolean<F>,
    dst_leaf: &FpVar<F>,
    dst_node: &FpVar<F>,
) -> Result<(Vec<FpVar<F>>, Vec<Boolean<F>>), SynthesisError> {
    let d = frontier.len();
    assert_eq!(count_bits.len(), d);
    let zero = FpVar::<F>::zero();

    // LeafHash(leaf_value) = Poseidon(DST_LEAF, leaf_value)
    let leaf_hash = poseidon_gadget(params, cs.clone(), &[dst_leaf.clone(), leaf_value.clone()])?;

    // Carry chain
    let mut cur = leaf_hash;
    let mut carry = do_append.clone();
    let mut new_frontier = frontier.to_vec();

    for h in 0..d {
        // merge = carry AND bit (merge frontier[h] into cur)
        let merge_h = &carry & &count_bits[h];
        // store = carry AND NOT bit (store cur into frontier[h])
        let not_bit = !&count_bits[h];
        let store_h = &carry & &not_bit;

        // NodeHash(frontier[h], cur) — always computed
        let node_hash = poseidon_gadget(
            params,
            cs.clone(),
            &[dst_node.clone(), frontier[h].clone(), cur.clone()],
        )?;

        // new_cur: if merge → node_hash; else → cur
        cur = CondSelectGadget::conditionally_select(&merge_h, &node_hash, &cur)?;

        // new_frontier[h]:
        //   store → cur; merge → 0; else → frontier[h]
        let temp = CondSelectGadget::conditionally_select(&store_h, &cur, &frontier[h])?;
        new_frontier[h] = CondSelectGadget::conditionally_select(&merge_h, &zero, &temp)?;

        carry = merge_h;
    }

    let new_count_bits = increment_bits(count_bits, do_append)?;
    Ok((new_frontier, new_count_bits))
}

/// FoldFrontier: finalize frontier into src_root.
///
/// Bag-folds active slots and computes RootHash(count, bag).
pub fn fold_frontier<F: PrimeField + Absorb>(
    params: &PoseidonConfig<F>,
    cs: ConstraintSystemRef<F>,
    frontier: &[FpVar<F>],
    count_bits: &[Boolean<F>],
    count: &FpVar<F>,
    dst_bag: &FpVar<F>,
    dst_root: &FpVar<F>,
) -> Result<FpVar<F>, SynthesisError> {
    let d = frontier.len();

    let mut bag = FpVar::<F>::zero();
    let mut has_bag = Boolean::<F>::constant(false);

    for h in 0..d {
        let active = &count_bits[h];
        let need_fold: Boolean<F> = active & &has_bag;
        let not_has_bag = !&has_bag;
        let first_active: Boolean<F> = active & &not_has_bag;

        // BagHash(frontier[h], bag) — always computed
        let bag_hash = poseidon_gadget(
            params,
            cs.clone(),
            &[dst_bag.clone(), frontier[h].clone(), bag.clone()],
        )?;

        let after_fold = CondSelectGadget::conditionally_select(&need_fold, &bag_hash, &bag)?;
        bag = CondSelectGadget::conditionally_select(&first_active, &frontier[h], &after_fold)?;
        has_bag = &has_bag | active;
    }

    // src_root = RootHash(count, bag)
    let src_root = poseidon_gadget(params, cs, &[dst_root.clone(), count.clone(), bag])?;
    Ok(src_root)
}

/// Conditional enforce_equal: if cond, enforce lhs == rhs.
pub fn enforce_eq_when<F: PrimeField>(
    cond: &Boolean<F>,
    lhs: &FpVar<F>,
    rhs: &FpVar<F>,
) -> Result<(), SynthesisError> {
    let diff = lhs - rhs;
    let cond_fp = FpVar::from(cond.clone());
    let product = &cond_fp * &diff;
    product.enforce_equal(&FpVar::zero())?;
    Ok(())
}

/// Conditional assert lhs < rhs (when cond=1).
pub fn assert_lt_when<F: PrimeField>(
    cond: &Boolean<F>,
    lhs: &FpVar<F>,
    rhs: &FpVar<F>,
    n_bits: usize,
) -> Result<(), SynthesisError> {
    let diff = rhs - lhs;
    let one = FpVar::<F>::one();
    let effective_diff = CondSelectGadget::conditionally_select(cond, &diff, &one)?;
    // Check effective_diff - 1 fits in n_bits (strict positivity)
    let diff_minus_one = &effective_diff - &one;
    let bits = diff_minus_one.to_bits_le()?;
    for i in n_bits..bits.len() {
        bits[i].enforce_equal(&Boolean::constant(false))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_relations::gr1cs::ConstraintSystem;

    fn test_poseidon_config() -> PoseidonConfig<Fr> {
        crate::poseidon_config::nova_poseidon_config()
    }

    #[test]
    fn test_append_leaf_constraint_count() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let params = test_poseidon_config();

        const D: usize = 10;
        let dst_leaf = FpVar::new_constant(cs.clone(), Fr::from(DST_SRC_LEAF)).unwrap();
        let dst_node = FpVar::new_constant(cs.clone(), Fr::from(DST_SRC_NODE)).unwrap();

        let frontier: Vec<FpVar<Fr>> = (0..D)
            .map(|_| FpVar::new_witness(cs.clone(), || Ok(Fr::from(0u64))).unwrap())
            .collect();
        let count_bits: Vec<Boolean<Fr>> = (0..D)
            .map(|_| Boolean::new_witness(cs.clone(), || Ok(false)).unwrap())
            .collect();
        let leaf = FpVar::new_witness(cs.clone(), || Ok(Fr::from(42u64))).unwrap();
        let do_append = Boolean::new_witness(cs.clone(), || Ok(true)).unwrap();

        let before = cs.num_constraints();
        let (_new_f, _new_cb) = append_leaf(
            &params, cs.clone(), &frontier, &count_bits, &leaf, &do_append,
            &dst_leaf, &dst_node,
        ).unwrap();
        let after = cs.num_constraints();

        println!("AppendLeaf (D={}) constraints: {}", D, after - before);
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_fold_frontier_constraint_count() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let params = test_poseidon_config();

        const D: usize = 10;
        let dst_bag = FpVar::new_constant(cs.clone(), Fr::from(DST_SRC_BAG)).unwrap();
        let dst_root = FpVar::new_constant(cs.clone(), Fr::from(DST_SRC_ROOT)).unwrap();

        let frontier: Vec<FpVar<Fr>> = (0..D)
            .map(|_| FpVar::new_witness(cs.clone(), || Ok(Fr::from(0u64))).unwrap())
            .collect();
        let count_bits: Vec<Boolean<Fr>> = (0..D)
            .map(|_| Boolean::new_witness(cs.clone(), || Ok(false)).unwrap())
            .collect();
        let count = FpVar::new_witness(cs.clone(), || Ok(Fr::from(0u64))).unwrap();

        let before = cs.num_constraints();
        let _root = fold_frontier(
            &params, cs.clone(), &frontier, &count_bits, &count, &dst_bag, &dst_root,
        ).unwrap();
        let after = cs.num_constraints();

        println!("FoldFrontier (D={}) constraints: {}", D, after - before);
        assert!(cs.is_satisfied().unwrap());
    }
}
