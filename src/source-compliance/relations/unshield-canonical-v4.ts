/**
 * R_UNSHIELD_V4_SET — RAILGUN Source Compliance v7
 *
 * Canonical unshield relation: spend + public output, per-public-bucket
 * exact aggregation + subset proof.
 *
 * R_UNSHIELD_V4_SET(merkleRootUsed, inputBinding, publicOutputBinding,
 *                    lineageBinding, policyBinding; W_can, W_merge, W_subset) = 1 iff
 *   1. canonical unshield relation is satisfied
 *   2. RealIn(tx) are exactly the notes bound by inputBinding
 *   3. RealPubOut(tx) are exactly the public outputs bound by publicOutputBinding
 *   4. for every public output bucket τ:
 *        R_MERGE_N^src(lineageBinding; W_merge, τ) = 1
 *      ∧ R_MERGE_N^mod(lineageBinding; W_merge, τ) = 1
 *      ∧ R_SUBSET_FROM_TREE^src(lineageBinding, policyBinding; W_subset, τ) = 1
 *      ∧ R_SUBSET_FROM_TREE^mod(lineageBinding, policyBinding; W_subset, τ) = 1
 */

import { NoteV4 } from '../commitments';
import {
  computeInputBinding,
  computePublicOutputBinding,
  PublicOutput,
} from './transfer-canonical-v4';

// ============================================================
// Types
// ============================================================

export interface UnshieldInputNote {
  note: NoteV4;
  nullifier: bigint;
}

export interface PublicBucketSpec {
  /** Public outputs in this bucket */
  outputs: PublicOutput[];
  /** Token hash for this bucket */
  tokenHash: bigint;
}

export interface UnshieldCanonicalWitness {
  inputNotes: UnshieldInputNote[];
  publicBuckets: PublicBucketSpec[];
  /** Per-bucket meta commits that hash into lineageBinding */
  bucketMetaCommits: bigint[];
}

// ============================================================
// Verify Unshield Canonical
// ============================================================

/**
 * Verify R_UNSHIELD_V4_SET canonical part (excluding merge/subset proofs).
 *
 * Checks:
 * 1. Input notes are bound by inputBinding
 * 2. Public outputs are bound by publicOutputBinding
 * 3. Value conservation: sum(input values per token) >= sum(public output values per token)
 */
export function verifyUnshieldCanonicalV4(
  merkleRootUsed: bigint,
  inputBinding: bigint,
  publicOutputBinding: bigint,
  witness: UnshieldCanonicalWitness,
  chainid: bigint,
  verifierAddr: bigint,
): boolean {
  // 1. Verify inputBinding
  const computedInputBinding = computeInputBinding(
    chainid,
    verifierAddr,
    merkleRootUsed,
    witness.inputNotes.map(inp => ({
      nullifier: inp.nullifier,
      note: inp.note,
    })),
  );
  if (computedInputBinding !== inputBinding) return false;

  // 2. Verify publicOutputBinding
  const allPublicOutputs: PublicOutput[] = [];
  for (const bucket of witness.publicBuckets) {
    allPublicOutputs.push(...bucket.outputs);
  }
  const computedPubBinding = computePublicOutputBinding(chainid, verifierAddr, allPublicOutputs);
  if (computedPubBinding !== publicOutputBinding) return false;

  // 3. Value conservation per token
  const inputValuesByToken = new Map<string, bigint>();
  for (const inp of witness.inputNotes) {
    const key = inp.note.tokenHash.toString();
    inputValuesByToken.set(key, (inputValuesByToken.get(key) ?? 0n) + inp.note.value);
  }

  for (const bucket of witness.publicBuckets) {
    const key = bucket.tokenHash.toString();
    let bucketTotal = 0n;
    for (const output of bucket.outputs) {
      if (output.tokenHash !== bucket.tokenHash) return false;
      bucketTotal += output.value;
    }
    const available = inputValuesByToken.get(key) ?? 0n;
    if (bucketTotal > available) return false;
  }

  return true;
}
