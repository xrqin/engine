//! RAILGUN Source Compliance — Nova IVC circuits
//!
//! Circuits:
//! - `merge_circuit`: Simplified hash-chain commitment (legacy benchmark)
//! - `scan_step_circuit`: C_SRC_STEP(mode=SCAN) — per-source verification via frontier append
//! - `merge2_step_circuit`: C_SRC_STEP(mode=MERGE2) — sorted merge with dedup
//! - `clean_check_circuit`: R_SRC_CLEAN — Groth16 Merkle membership check
//! - `frontier_gadget`: Shared R1CS gadgets for binary append frontier

pub mod clean_check_circuit;
pub mod clean_check_step_circuit;
pub mod frontier_gadget;
pub mod merge2_step_circuit;
pub mod merge_circuit;
pub mod params;
pub mod poseidon_config;
pub mod scan_step_circuit;

pub use clean_check_circuit::CleanCheckCircuit;
pub use clean_check_step_circuit::CleanCheckStepCircuit;
pub use merge2_step_circuit::Merge2StepCircuit;
pub use merge_circuit::{MergeExternalInputs, MergeStepCircuit, MERGE_STATE_LEN};
pub use params::{DeciderParams, NovaParams};
pub use scan_step_circuit::ScanStepCircuit;
