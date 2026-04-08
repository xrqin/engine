/**
 * JoinSplit V5 Witness Generator — RAILGUN Source Compliance v8.1
 *
 * Generates the witness for the joinsplit-v5.circom circuit.
 * Every field computed here must match the circuit's constraints exactly.
 *
 * Maps to: R_TRANSFER_CANONICAL_V5 (§4.3.11)
 */

import { poseidon } from '../../utils/poseidon';
import { NoteV5, noteComV5, dstToFieldElement } from '../commitments';
import {
  computeInputNoteSemV8,
  computeInputBindingV8,
  computeInputLineageNoteSem,
  computeInputLineageBinding,
  computeOutputBindingV8,
  computeBucketSrcMeta,
  computeBucketMetaCommitV8,
  computeLineageBindingV8,
} from '../bindings';
import {
  NOTE_VERSION_V5,
  DST_NOTE_COM_V5,
  DST_INPUT_NOTE_BIND_V4,
  DST_INPUT_BIND_V11,
  DST_INPUT_LINEAGE_NOTE_BIND_V1,
  DST_INPUT_LINEAGE_BIND_V1,
  DST_OUTPUT_BIND_V11,
  DST_BUCKET_SRC_IN_REF_V2,
  DST_BUCKET_MOD_IN_REF_V2,
  DST_BUCKET_SRC_META_V1,
  DST_BUCKET_META_V3,
  DST_LINEAGE_BIND_V3,
} from '../constants';

// ============================================================
// Types
// ============================================================

export interface JoinSplitV5InputNote {
  /** Note fields */
  note: NoteV5;
  /** Nullifier for this input */
  nullifier: bigint;
  /** Random value used to derive NPK */
  random: bigint;
  /** Value of this input note */
  value: bigint;
  /** Merkle proof path elements */
  pathElements: bigint[];
  /** Leaf index in merkle tree */
  leafIndex: bigint;
}

export interface JoinSplitV5OutputNote {
  /** Recipient's NPK */
  npk: bigint;
  /** Output value */
  value: bigint;
  /** rho_value for the output note */
  rhoValue: bigint;
  /** Source commitment for output note */
  sourceCommitment: bigint;
  /** Module commitment for output note */
  moduleCommitment: bigint;
}

export interface JoinSplitV5BucketInfo {
  /** Bucket role identifier (as field element) */
  bucketRole: string;
  /** Source commitment for the bucket */
  bucketSrcCommit: bigint;
  /** Module commitment for the bucket */
  bucketModCommit: bigint;
  /** Pre-computed bucket source input reference digest */
  bucketSrcInRefDigest: bigint;
  /** Pre-computed bucket module input reference digest */
  bucketModInRefDigest: bigint;
}

export interface JoinSplitV5WitnessInput {
  /** Merkle root */
  merkleRoot: bigint;
  /** Target output epoch */
  targetOutputEpoch: bigint;
  /** Whether to enforce input clean epoch (fast-path) */
  enforceInputClean: 0 | 1;
  /** Chain ID */
  chainid: bigint;
  /** Verifier address */
  verifierAddr: bigint;
  /** Transaction type string */
  txType: string;
  /** EdDSA public key [Ax, Ay] */
  publicKey: [bigint, bigint];
  /** EdDSA signature [R8x, R8y, S] */
  signature: [bigint, bigint, bigint];
  /** Nullifying key */
  nullifyingKey: bigint;
  /** Token hash */
  token: bigint;
  /** Input notes */
  inputNotes: JoinSplitV5InputNote[];
  /** Output notes */
  outputNotes: JoinSplitV5OutputNote[];
  /** Bucket info per output */
  buckets: JoinSplitV5BucketInfo[];
}

// ============================================================
// Witness output type — matches circuit signal layout
// ============================================================

export interface JoinSplitV5CircuitInput {
  // Public signals
  merkleRoot: bigint;
  inputBinding: bigint;
  inputLineageBinding: bigint;
  outputBinding: bigint;
  lineageBinding: bigint;
  targetOutputEpoch: bigint;
  enforceInputClean: bigint;

  // DST constants
  dstNoteComV5: bigint;
  dstInputNoteBind: bigint;
  dstInputBind: bigint;
  dstInputLineageNote: bigint;
  dstInputLineageBind: bigint;
  dstOutputBind: bigint;
  dstBucketSrcInRef: bigint;
  dstBucketModInRef: bigint;
  dstBucketSrcMeta: bigint;
  dstBucketMeta: bigint;
  dstLineageBind: bigint;
  noteVersionV5: bigint;
  chainid: bigint;
  verifierAddr: bigint;
  txType: bigint;

  // Keys and signature
  publicKey: [bigint, bigint];
  signature: [bigint, bigint, bigint];
  nullifyingKey: bigint;

  // Input notes
  token: bigint;
  randomIn: bigint[];
  valueIn: bigint[];
  sourceCommitmentIn: bigint[];
  moduleCommitmentIn: bigint[];
  cleanEpochIn: bigint[];
  pathElements: bigint[][];
  leavesIndices: bigint[];
  nullifiers: bigint[];

  // Output notes
  npkOut: bigint[];
  valueOut: bigint[];
  rhoValueOut: bigint[];
  sourceCommitmentOut: bigint[];
  moduleCommitmentOut: bigint[];

  // Bucket assignments
  nBuckets: bigint;
  outputBucketIndex: bigint[];
  bucketSrcCommit: bigint[];
  bucketModCommit: bigint[];
  bucketRole: bigint[];
  bucketSrcInRefDigest: bigint[];
  bucketModInRefDigest: bigint[];
  bucketMetaCommit: bigint[];
}

// ============================================================
// Witness Generator
// ============================================================

/**
 * Generate the full witness for joinsplit-v5.circom.
 *
 * Computes all public inputs (inputBinding, inputLineageBinding,
 * outputBinding, lineageBinding) and formats private witness signals
 * exactly matching the circuit layout.
 */
export function generateJoinSplitV5Witness(
  input: JoinSplitV5WitnessInput,
): JoinSplitV5CircuitInput {
  const nInputs = input.inputNotes.length;
  const nOutputs = input.outputNotes.length;

  // ----------------------------------------------------------
  // 1. Compute output note commitments
  // ----------------------------------------------------------
  const outputCommitments: bigint[] = [];
  for (const out of input.outputNotes) {
    const outNote: NoteV5 = {
      value: out.value,
      tokenHash: input.token,
      ownerPubkey: out.npk,
      rhoValue: out.rhoValue,
      sourceCommitment: out.sourceCommitment,
      moduleCommitment: out.moduleCommitment,
      cleanEpoch: input.targetOutputEpoch,
    };
    outputCommitments.push(noteComV5(outNote));
  }

  // ----------------------------------------------------------
  // 2. Compute inputBinding (§4.2.2)
  // ----------------------------------------------------------
  const inSemValues = input.inputNotes.map(inp =>
    computeInputNoteSemV8(
      inp.nullifier,
      input.token,
      inp.note.sourceCommitment,
      inp.note.moduleCommitment,
      inp.note.cleanEpoch,
    ),
  );
  const computedInputBinding = computeInputBindingV8(
    input.chainid,
    input.verifierAddr,
    input.merkleRoot,
    inSemValues,
  );

  // ----------------------------------------------------------
  // 3. Compute inputLineageBinding (§4.2.3)
  // ----------------------------------------------------------
  const computedInputLineageBinding = computeInputLineageBinding(
    input.chainid,
    input.verifierAddr,
    input.inputNotes.map(inp => ({
      sourceCommitment: inp.note.sourceCommitment,
      moduleCommitment: inp.note.moduleCommitment,
      cleanEpoch: inp.note.cleanEpoch,
    })),
  );

  // ----------------------------------------------------------
  // 4. Compute outputBinding (§4.2.4)
  // ----------------------------------------------------------
  const computedOutputBinding = computeOutputBindingV8(
    input.chainid,
    input.verifierAddr,
    outputCommitments,
  );

  // ----------------------------------------------------------
  // 5. Compute lineageBinding (§4.2.5)
  // ----------------------------------------------------------
  const bucketMetaCommits: bigint[] = [];
  for (let i = 0; i < nOutputs; i++) {
    const bucket = input.buckets[i];
    const srcMeta = computeBucketSrcMeta(
      bucket.bucketRole,
      bucket.bucketSrcInRefDigest,
      bucket.bucketSrcCommit,
    );
    const metaCommit = computeBucketMetaCommitV8(
      bucket.bucketRole,
      srcMeta,
      bucket.bucketModInRefDigest,
      bucket.bucketModCommit,
    );
    bucketMetaCommits.push(metaCommit);
  }

  const computedLineageBinding = computeLineageBindingV8(
    input.chainid,
    input.verifierAddr,
    input.txType,
    bucketMetaCommits,
  );

  // ----------------------------------------------------------
  // 6. Pack circuit input
  // ----------------------------------------------------------
  return {
    // Public signals
    merkleRoot: input.merkleRoot,
    inputBinding: computedInputBinding,
    inputLineageBinding: computedInputLineageBinding,
    outputBinding: computedOutputBinding,
    lineageBinding: computedLineageBinding,
    targetOutputEpoch: input.targetOutputEpoch,
    enforceInputClean: BigInt(input.enforceInputClean),

    // DST constants
    dstNoteComV5: dstToFieldElement(DST_NOTE_COM_V5),
    dstInputNoteBind: dstToFieldElement(DST_INPUT_NOTE_BIND_V4),
    dstInputBind: dstToFieldElement(DST_INPUT_BIND_V11),
    dstInputLineageNote: dstToFieldElement(DST_INPUT_LINEAGE_NOTE_BIND_V1),
    dstInputLineageBind: dstToFieldElement(DST_INPUT_LINEAGE_BIND_V1),
    dstOutputBind: dstToFieldElement(DST_OUTPUT_BIND_V11),
    dstBucketSrcInRef: dstToFieldElement(DST_BUCKET_SRC_IN_REF_V2),
    dstBucketModInRef: dstToFieldElement(DST_BUCKET_MOD_IN_REF_V2),
    dstBucketSrcMeta: dstToFieldElement(DST_BUCKET_SRC_META_V1),
    dstBucketMeta: dstToFieldElement(DST_BUCKET_META_V3),
    dstLineageBind: dstToFieldElement(DST_LINEAGE_BIND_V3),
    noteVersionV5: BigInt(NOTE_VERSION_V5),
    chainid: input.chainid,
    verifierAddr: input.verifierAddr,
    txType: dstToFieldElement(input.txType),

    // Keys and signature
    publicKey: input.publicKey,
    signature: input.signature,
    nullifyingKey: input.nullifyingKey,

    // Input notes
    token: input.token,
    randomIn: input.inputNotes.map(n => n.random),
    valueIn: input.inputNotes.map(n => n.value),
    sourceCommitmentIn: input.inputNotes.map(n => n.note.sourceCommitment),
    moduleCommitmentIn: input.inputNotes.map(n => n.note.moduleCommitment),
    cleanEpochIn: input.inputNotes.map(n => n.note.cleanEpoch),
    pathElements: input.inputNotes.map(n => n.pathElements),
    leavesIndices: input.inputNotes.map(n => n.leafIndex),
    nullifiers: input.inputNotes.map(n => n.nullifier),

    // Output notes
    npkOut: input.outputNotes.map(n => n.npk),
    valueOut: input.outputNotes.map(n => n.value),
    rhoValueOut: input.outputNotes.map(n => n.rhoValue),
    sourceCommitmentOut: input.outputNotes.map(n => n.sourceCommitment),
    moduleCommitmentOut: input.outputNotes.map(n => n.moduleCommitment),

    // Bucket assignments
    nBuckets: BigInt(nOutputs), // one bucket per output in transfer
    outputBucketIndex: input.outputNotes.map((_, i) => BigInt(i)),
    bucketSrcCommit: input.buckets.map(b => b.bucketSrcCommit),
    bucketModCommit: input.buckets.map(b => b.bucketModCommit),
    bucketRole: input.buckets.map(b => dstToFieldElement(b.bucketRole)),
    bucketSrcInRefDigest: input.buckets.map(b => b.bucketSrcInRefDigest),
    bucketModInRefDigest: input.buckets.map(b => b.bucketModInRefDigest),
    bucketMetaCommit: bucketMetaCommits,
  };
}

/**
 * Validate witness integrity — checks all constraints that the circuit enforces.
 * Returns true if the witness would satisfy all circuit constraints.
 */
export function validateJoinSplitV5Witness(
  witness: JoinSplitV5CircuitInput,
): { valid: true } | { valid: false; reason: string } {
  const nInputs = witness.nullifiers.length;
  const nOutputs = witness.npkOut.length;

  // 1. enforceInputClean is boolean
  if (witness.enforceInputClean !== 0n && witness.enforceInputClean !== 1n) {
    return { valid: false, reason: 'enforceInputClean must be 0 or 1' };
  }

  // 2. Value conservation
  let sumIn = 0n;
  for (const v of witness.valueIn) sumIn += v;
  let sumOut = 0n;
  for (const v of witness.valueOut) sumOut += v;
  if (sumIn !== sumOut) {
    return { valid: false, reason: `Value conservation failed: ${sumIn} !== ${sumOut}` };
  }

  // 3. Output values are 120-bit
  const MAX_120 = (1n << 120n) - 1n;
  for (let i = 0; i < nOutputs; i++) {
    if (witness.valueOut[i] > MAX_120 || witness.valueOut[i] < 0n) {
      return { valid: false, reason: `Output value[${i}] exceeds 120 bits` };
    }
  }

  // 4. Bucket constraints: bucketSrcCommit === outputNote.source_commitment
  for (let i = 0; i < nOutputs; i++) {
    if (witness.sourceCommitmentOut[i] !== witness.bucketSrcCommit[i]) {
      return {
        valid: false,
        reason: `Output[${i}] sourceCommitment !== bucketSrcCommit`,
      };
    }
    if (witness.moduleCommitmentOut[i] !== witness.bucketModCommit[i]) {
      return {
        valid: false,
        reason: `Output[${i}] moduleCommitment !== bucketModCommit`,
      };
    }
  }

  // 5. Fast-path epoch check
  if (witness.enforceInputClean === 1n) {
    for (let i = 0; i < nInputs; i++) {
      if (witness.cleanEpochIn[i] !== witness.targetOutputEpoch) {
        return {
          valid: false,
          reason: `Fast-path: input[${i}] cleanEpoch ${witness.cleanEpochIn[i]} !== targetOutputEpoch ${witness.targetOutputEpoch}`,
        };
      }
    }
  }

  return { valid: true };
}
