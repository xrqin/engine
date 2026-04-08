//! WASM bindings for RAILGUN Merge IVC (Nova).
//!
//! Exposes MergeNovaWasm to TypeScript, following zERC20's WithdrawNovaWasm pattern:
//!
//!   const merger = new MergeNovaWasm(ppBytes, vpBytes);
//!   const result = merger.prove(z0, steps);
//!   // result = { finalState: [accRoot, accCount, hashChain], ivcProof: "0x...", steps: N }

use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use folding_schemes::FoldingScheme;
use railgun_merge_ivc::{
    MergeExternalInputs, MergeStepCircuit, MERGE_STATE_LEN, NovaParams,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use web_time::Instant;

// ============================================================
// JS types (serde bridge)
// ============================================================

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsMergeStepInput {
    pub is_dummy: bool,
    pub right_root: String,  // hex field element
    pub right_count: String, // hex field element
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct JsProveResult {
    final_state: Vec<String>,
    ivc_proof: String,
    steps: usize,
}

// ============================================================
// Helpers
// ============================================================

fn hex_to_fr(hex_str: &str) -> Result<Fr, JsValue> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str)
        .map_err(|e| JsValue::from_str(&format!("hex decode error: {}", e)))?;
    // Pad to 32 bytes (little-endian for arkworks)
    let mut padded = vec![0u8; 32];
    let start = 32usize.saturating_sub(bytes.len());
    padded[start..].copy_from_slice(&bytes);
    padded.reverse(); // big-endian hex -> little-endian arkworks
    Fr::from_random_bytes(&padded)
        .ok_or_else(|| JsValue::from_str("invalid field element"))
}

fn fr_to_hex(f: &Fr) -> String {
    let repr = f.into_bigint();
    format!("0x{:064x}", repr)
}

fn log_timing(msg: &str) {
    web_sys::console::log_1(&JsValue::from_str(msg));
}

// ============================================================
// MergeNovaWasm (analogous to zERC20's WithdrawNovaWasm)
// ============================================================

#[wasm_bindgen]
pub struct MergeNovaWasm {
    params: NovaParams<MergeStepCircuit<Fr>>,
}

#[wasm_bindgen]
impl MergeNovaWasm {
    /// Constructor: load Nova prover/verifier params from serialized bytes.
    ///
    /// Usage from TypeScript:
    ///   const merger = new MergeNovaWasm(ppBytes, vpBytes);
    #[wasm_bindgen(constructor)]
    pub fn new(pp_bytes: Vec<u8>, vp_bytes: Vec<u8>) -> Result<MergeNovaWasm, JsValue> {
        console_error_panic_hook::set_once();
        let poseidon_config = railgun_merge_ivc::poseidon_config::nova_poseidon_config();
        let params = NovaParams::from_bytes(poseidon_config, pp_bytes, vp_bytes)
            .map_err(|err| JsValue::from_str(&err.to_string()))?;
        Ok(MergeNovaWasm { params })
    }

    /// Run the IVC fold over merge steps.
    ///
    /// z0: initial state [accRoot, accCount, hashChain] as hex strings
    /// steps: array of { isDummy, rightRoot, rightCount }
    ///
    /// Returns: { finalState, ivcProof, steps }
    #[wasm_bindgen]
    pub fn prove(&self, z0: JsValue, steps: JsValue) -> Result<JsValue, JsValue> {
        console_error_panic_hook::set_once();

        let z0_hex: Vec<String> = serde_wasm_bindgen::from_value(z0)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let step_inputs: Vec<JsMergeStepInput> = serde_wasm_bindgen::from_value(steps)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        if z0_hex.len() != MERGE_STATE_LEN {
            return Err(JsValue::from_str(&format!(
                "z0 must have {} elements, got {}",
                MERGE_STATE_LEN,
                z0_hex.len()
            )));
        }

        let z0_fields = z0_hex
            .iter()
            .map(|s| hex_to_fr(s))
            .collect::<Result<Vec<_>, _>>()?;

        let prove_start = Instant::now();
        let mut nova = self
            .params
            .initial_nova(z0_fields)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let mut rng = rand::thread_rng();

        for (idx, step) in step_inputs.iter().enumerate() {
            let step_start = Instant::now();
            let ext = MergeExternalInputs {
                is_dummy: step.is_dummy,
                right_root: hex_to_fr(&step.right_root)?,
                right_count: hex_to_fr(&step.right_count)?,
            };

            nova.prove_step(&mut rng, ext, None)
                .map_err(|e| JsValue::from_str(&format!("prove_step[{}]: {}", idx, e)))?;

            log_timing(&format!(
                "MergeNovaWasm::prove_step[{}] {:.2} ms",
                idx,
                step_start.elapsed().as_secs_f64() * 1000.0
            ));
        }

        log_timing(&format!(
            "MergeNovaWasm::prove total {:.2} ms for {} steps",
            prove_start.elapsed().as_secs_f64() * 1000.0,
            step_inputs.len()
        ));

        // Extract and verify IVC proof
        let state = nova.state();
        let final_state: Vec<String> = state.iter().map(fr_to_hex).collect();
        let ivc_proof = nova.ivc_proof();
        self.params
            .verify(ivc_proof.clone())
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        // Serialize proof
        let mut proof_bytes = Vec::new();
        ivc_proof
            .serialize_uncompressed(&mut proof_bytes)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let result = JsProveResult {
            final_state,
            ivc_proof: format!("0x{}", hex::encode(proof_bytes)),
            steps: step_inputs.len(),
        };

        serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
    }
}
