//! Poseidon hash configuration for BN254, matching RAILGUN engine's Poseidon.

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use folding_schemes::transcript::poseidon::poseidon_canonical_config;

/// Canonical Poseidon config for Nova transcript (BN254 scalar field).
pub fn nova_poseidon_config() -> PoseidonConfig<Fr> {
    poseidon_canonical_config::<Fr>()
}
