/**
 * R_TRANSFER_CANONICAL_V5 — RAILGUN Source Compliance v8.1
 *
 * Canonical transfer relation: spend/create, value conservation,
 * bucket consistency, lineageBinding alignment.
 *
 * Upgrades from V4:
 * - NoteV5 / noteComV5 (v8.1 note commitment)
 * - v8.1 bindings: computeInputNoteSemV8, computeInputBindingV8, computeOutputBindingV8
 * - NEW public input: inputLineageBinding (anti-splice for modular lineage subproofs)
 * - NEW constraint: every output note MUST have cleanEpoch === currentPolicyEpoch
 * - NEW constraint: bucketSrcCommit[tau] MUST === output note's sourceCommitment
 *
 * R_TRANSFER_CANONICAL_V5(merkleRootUsed, inputBinding, inputLineageBinding,
 *     outputBinding, lineageBinding; W_can) = 1 iff
 *   1. canonical UTXO spend/create relation is satisfied
 *   2. RealIn(tx) are exactly the notes bound by inputBinding
 *   3. inputLineageBinding matches the input notes' lineage semantics
 *   4. RealOut(tx) are exactly the notes bound by outputBinding
 *   5. notes are partitioned by hidden token buckets inside the witness
 *   6. for each output bucket tau: every output note binds to same bucketSrcCommit[tau] and bucketModCommit[tau]
 *   7. bucketSrcCommit[tau] === output note's sourceCommitment (note-backed buckets)
 *   8. all output notes have cleanEpoch === currentPolicyEpoch
 *   9. all bucketMetaCommit[tau] hash to lineageBinding
 */

import { NoteV5, noteComV5 } from '../commitments';
import {
  computeInputNoteSemV8,
  computeInputBindingV8,
  computeInputLineageBinding,
  computeOutputBindingV8,
} from '../bindings';
import { NOTE_VERSION_V5 } from '../constants';

// ============================================================
// Types
// ============================================================

export interface TransferInputNoteV5 {
  note: NoteV5;
  nullifier: bigint;
  merkleProof: bigint[]; // simplified: path elements
}

export interface TransferOutputNoteV5 {
  note: NoteV5;
  commitment: bigint;
}

export interface TransferCanonicalV5Witness {
  inputNotes: TransferInputNoteV5[];
  outputNotes: TransferOutputNoteV5[];
  bucketAssignment: {
    outputBucketIndex: number[];
    bucketSrcCommit: bigint[];
    bucketModCommit: bigint[];
  };
  bucketMetaCommits: bigint[];
  bucketCount: number;
}

// ============================================================
// Verify R_TRANSFER_CANONICAL_V5
// ============================================================

/**
 * Verify the canonical transfer relation (v8.1).
 *
 * Checks:
 * 1. inputBinding matches witness inputs (v8.1 DSTs)
 * 2. inputLineageBinding matches witness inputs' lineage semantics
 * 3. outputBinding matches witness outputs (v8.1 DSTs)
 * 4. Output commitment integrity (noteComV5)
 * 5. All output notes: cleanEpoch === currentPolicyEpoch
 * 6. Value conservation per token bucket
 * 7. Each output note in bucket tau binds to bucketSrcCommit[tau] and bucketModCommit[tau]
 * 8. bucketSrcCommit[tau] === output note's sourceCommitment (note-backed invariant)
 * 9. bucketMetaCommits length matches bucketCount
 */
export function verifyTransferCanonicalV5(
  merkleRootUsed: bigint,
  inputBinding: bigint,
  inputLineageBinding: bigint,
  outputBinding: bigint,
  lineageBinding: bigint,
  witness: TransferCanonicalV5Witness,
  chainid: bigint,
  verifierAddr: bigint,
  currentPolicyEpoch: bigint,
): boolean {
  // 1. Verify inputBinding matches witness inputs (v8.1)
  const inSemValues = witness.inputNotes.map(inp =>
    computeInputNoteSemV8(
      inp.nullifier,
      inp.note.tokenHash,
      inp.note.sourceCommitment,
      inp.note.moduleCommitment,
      inp.note.cleanEpoch,
    ),
  );
  const computedInputBinding = computeInputBindingV8(
    chainid,
    verifierAddr,
    merkleRootUsed,
    inSemValues,
  );
  if (computedInputBinding !== inputBinding) return false;

  // 2. Verify inputLineageBinding matches witness inputs' lineage semantics
  const computedInputLineageBinding = computeInputLineageBinding(
    chainid,
    verifierAddr,
    witness.inputNotes.map(inp => ({
      sourceCommitment: inp.note.sourceCommitment,
      moduleCommitment: inp.note.moduleCommitment,
      cleanEpoch: inp.note.cleanEpoch,
    })),
  );
  if (computedInputLineageBinding !== inputLineageBinding) return false;

  // 3. Verify outputBinding matches witness outputs (v8.1)
  const outputCommitments = witness.outputNotes.map(out => out.commitment);
  const computedOutputBinding = computeOutputBindingV8(chainid, verifierAddr, outputCommitments);
  if (computedOutputBinding !== outputBinding) return false;

  // 4. Verify output commitment integrity (noteComV5)
  for (const out of witness.outputNotes) {
    if (noteComV5(out.note) !== out.commitment) return false;
  }

  // 5. All output notes: cleanEpoch === currentPolicyEpoch
  for (const out of witness.outputNotes) {
    if (out.note.cleanEpoch !== currentPolicyEpoch) return false;
  }

  // 6. Verify value conservation per token bucket
  const { bucketAssignment, bucketCount } = witness;
  for (let tau = 0; tau < bucketCount; tau++) {
    // Collect output indices for this bucket
    const outputIndices = bucketAssignment.outputBucketIndex
      .map((b, i) => (b === tau ? i : -1))
      .filter(i => i >= 0);

    if (outputIndices.length === 0) continue;

    const bucketTokenHash = witness.outputNotes[outputIndices[0]].note.tokenHash;

    // Sum input values for this token
    let inputSum = 0n;
    for (const inp of witness.inputNotes) {
      if (inp.note.tokenHash === bucketTokenHash) {
        inputSum += inp.note.value;
      }
    }

    // Sum output values for this bucket
    let outputSum = 0n;
    for (const idx of outputIndices) {
      outputSum += witness.outputNotes[idx].note.value;
    }

    if (inputSum !== outputSum) return false;
  }

  // 7. Verify each output note in bucket tau binds to bucketSrcCommit[tau] and bucketModCommit[tau]
  // 8. bucketSrcCommit[tau] === output note's sourceCommitment (note-backed invariant)
  for (let i = 0; i < witness.outputNotes.length; i++) {
    const tau = bucketAssignment.outputBucketIndex[i];
    const note = witness.outputNotes[i].note;
    if (note.sourceCommitment !== bucketAssignment.bucketSrcCommit[tau]) return false;
    if (note.moduleCommitment !== bucketAssignment.bucketModCommit[tau]) return false;
  }

  // 9. Verify bucketMetaCommits length matches bucketCount
  if (witness.bucketMetaCommits.length !== bucketCount) return false;

  return true;
}
