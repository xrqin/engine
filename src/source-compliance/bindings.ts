/**
 * v8.1 Binding Layer
 *
 * Extracted from v7-proof.ts and updated per v8.1 spec §4.2.2-4.2.6.
 *
 * Key additions over v7:
 * - inputLineageBinding (§4.2.3) — anti-splice binding for modular lineage subproofs
 * - Updated DSTs: V4/V11/V7/V3 versions
 * - bucketSrcMeta intermediate hash (§4.2.5)
 * - policyBinding with cleanSourceRoot + A_mod_policy + dual mode flags (§4.2.6)
 *
 * NORMATIVE INVARIANT (v8.1 §4.2.5):
 * For note-backed private output buckets, bucketSrcCommit[τ] MUST equal the
 * output note's source_commitment — i.e. Com_src(src_root, src_count; rho_src_note)
 * computed via comSrcV8(). There is NO separate bucket commitment DST in v8.1.
 * The v7 DST_BUCKET_SRC_COM_V1 is NOT used for note-backed buckets in v8.1.
 * For public buckets (e.g. unshield), the same Com_src primitive is used but
 * there is no output note commitment to match against.
 */

import { poseidon } from '../utils/poseidon';
import { dstToFieldElement, comSrcV8 } from './commitments';
import {
  NOTE_VERSION_V5,
  DST_INPUT_NOTE_BIND_V4,
  DST_INPUT_BIND_V11,
  DST_INPUT_LINEAGE_NOTE_BIND_V1,
  DST_INPUT_LINEAGE_BIND_V1,
  DST_OUTPUT_BIND_V11,
  DST_PUBLIC_OUTPUT_BIND_V7,
  DST_BUCKET_SRC_IN_REF_V2,
  DST_BUCKET_MOD_IN_REF_V2,
  DST_BUCKET_SRC_META_V1,
  DST_BUCKET_META_V3,
  DST_LINEAGE_BIND_V3,
  DST_POLICY_BIND_V3,
} from './constants';

// ============================================================
// Input Note Semantic (v8.1: DST_INPUT_NOTE_BIND_V4)
// ============================================================

/**
 * inSem[i] = H(DST_INPUT_NOTE_BIND_V4, nf_i, tokenHash, source_commitment,
 *              module_commitment, clean_epoch, NOTE_VERSION_V5)
 */
export function computeInputNoteSemV8(
  nullifier: bigint,
  tokenHash: bigint,
  sourceCommitment: bigint,
  moduleCommitment: bigint,
  cleanEpoch: bigint,
): bigint {
  return poseidon([
    dstToFieldElement(DST_INPUT_NOTE_BIND_V4),
    nullifier,
    tokenHash,
    sourceCommitment,
    moduleCommitment,
    cleanEpoch,
    BigInt(NOTE_VERSION_V5),
  ]);
}

// ============================================================
// Input Binding (v8.1: DST_INPUT_BIND_V11)
// ============================================================

/**
 * inputBinding = H(DST_INPUT_BIND_V11, chainid, verifier_addr, merkleRootUsed,
 *                  n, inSem[0], ..., inSem[n-1])
 */
export function computeInputBindingV8(
  chainid: bigint,
  verifierAddr: bigint,
  merkleRootUsed: bigint,
  inSemValues: bigint[],
): bigint {
  const n = inSemValues.length;
  const dst = dstToFieldElement(DST_INPUT_BIND_V11);
  let state = poseidon([dst, chainid, verifierAddr, merkleRootUsed, BigInt(n)]);
  for (const sem of inSemValues) {
    state = poseidon([state, sem]);
  }
  return state;
}

// ============================================================
// Input Lineage Binding (v8.1: NEW — anti-splice core)
// ============================================================

/**
 * inLineageSem[i] = H(DST_INPUT_LINEAGE_NOTE_BIND_V1, i, source_commitment,
 *                     module_commitment, clean_epoch, NOTE_VERSION_V5)
 */
export function computeInputLineageNoteSem(
  index: number,
  sourceCommitment: bigint,
  moduleCommitment: bigint,
  cleanEpoch: bigint,
): bigint {
  return poseidon([
    dstToFieldElement(DST_INPUT_LINEAGE_NOTE_BIND_V1),
    BigInt(index),
    sourceCommitment,
    moduleCommitment,
    cleanEpoch,
    BigInt(NOTE_VERSION_V5),
  ]);
}

/**
 * inputLineageBinding = H(DST_INPUT_LINEAGE_BIND_V1, chainid, verifier_addr,
 *                         n, inLineageSem[0], ..., inLineageSem[n-1])
 *
 * All modular lineage subproofs MUST take this as a public input.
 */
export function computeInputLineageBinding(
  chainid: bigint,
  verifierAddr: bigint,
  inputNotes: Array<{
    sourceCommitment: bigint;
    moduleCommitment: bigint;
    cleanEpoch: bigint;
  }>,
): bigint {
  const n = inputNotes.length;
  const inLineageSems = inputNotes.map((note, i) =>
    computeInputLineageNoteSem(i, note.sourceCommitment, note.moduleCommitment, note.cleanEpoch),
  );

  const dst = dstToFieldElement(DST_INPUT_LINEAGE_BIND_V1);
  let state = poseidon([dst, chainid, verifierAddr, BigInt(n)]);
  for (const sem of inLineageSems) {
    state = poseidon([state, sem]);
  }
  return state;
}

// ============================================================
// Output Binding (v8.1: DST_OUTPUT_BIND_V11)
// ============================================================

/**
 * outputBinding = H(DST_OUTPUT_BIND_V11, chainid, verifier_addr, k, cm_out[0..k-1])
 */
export function computeOutputBindingV8(
  chainid: bigint,
  verifierAddr: bigint,
  outputCommitments: bigint[],
): bigint {
  const k = outputCommitments.length;
  const dst = dstToFieldElement(DST_OUTPUT_BIND_V11);
  let state = poseidon([dst, chainid, verifierAddr, BigInt(k)]);
  for (const cm of outputCommitments) {
    state = poseidon([state, cm]);
  }
  return state;
}

// ============================================================
// Public Output Binding (v8.1: DST_PUBLIC_OUTPUT_BIND_V7)
// ============================================================

/**
 * publicOutputBinding = H(DST_PUBLIC_OUTPUT_BIND_V7, chainid, verifier_addr,
 *                         p, pub_out[0..p-1])
 */
export function computePublicOutputBindingV8(
  chainid: bigint,
  verifierAddr: bigint,
  publicOutputs: bigint[],
): bigint {
  const p = publicOutputs.length;
  const dst = dstToFieldElement(DST_PUBLIC_OUTPUT_BIND_V7);
  let state = poseidon([dst, chainid, verifierAddr, BigInt(p)]);
  for (const pub of publicOutputs) {
    state = poseidon([state, pub]);
  }
  return state;
}

// ============================================================
// Bucket Lineage (v8.1: updated structure per §4.2.5)
// ============================================================

/**
 * bucketSrcInRefDigest[τ] = H(DST_BUCKET_SRC_IN_REF_V2, bucketRole,
 *                             carriedInputRefList_src[τ])
 */
export function computeBucketSrcInRefDigest(
  bucketRole: string,
  carriedInputRefs: bigint[],
): bigint {
  const dst = dstToFieldElement(DST_BUCKET_SRC_IN_REF_V2);
  let state = poseidon([dst, dstToFieldElement(bucketRole)]);
  for (const ref of carriedInputRefs) {
    state = poseidon([state, ref]);
  }
  return state;
}

/**
 * bucketModInRefDigest[τ] = H(DST_BUCKET_MOD_IN_REF_V2, bucketRole,
 *                             carriedInputRefList_mod[τ])
 */
export function computeBucketModInRefDigest(
  bucketRole: string,
  carriedInputRefs: bigint[],
): bigint {
  const dst = dstToFieldElement(DST_BUCKET_MOD_IN_REF_V2);
  let state = poseidon([dst, dstToFieldElement(bucketRole)]);
  for (const ref of carriedInputRefs) {
    state = poseidon([state, ref]);
  }
  return state;
}

/**
 * bucketSrcMeta[τ] = H(DST_BUCKET_SRC_META_V1, bucketRole,
 *                      bucketSrcInRefDigest[τ], bucketSrcCommit[τ])
 *
 * CRITICAL (v8.1 §4.2.5): For note-backed private output buckets,
 * bucketSrcCommit[τ] MUST be the note's source_commitment — that is,
 * the value returned by comSrcV8(srcRoot, srcCount, rhoSrcNote).
 * Do NOT use a separate bucket-specific DST (the v7 DST_BUCKET_SRC_COM_V1
 * is NOT valid here). For public buckets the same Com_src primitive applies
 * but there is no output note to equate against.
 */
export function computeBucketSrcMeta(
  bucketRole: string,
  bucketSrcInRefDigest: bigint,
  bucketSrcCommit: bigint,
): bigint {
  return poseidon([
    dstToFieldElement(DST_BUCKET_SRC_META_V1),
    dstToFieldElement(bucketRole),
    bucketSrcInRefDigest,
    bucketSrcCommit,
  ]);
}

/**
 * Convenience: compute bucketSrcMeta for a note-backed private output bucket,
 * enforcing the v8.1 §4.2.5 invariant that bucketSrcCommit = note.source_commitment.
 *
 * @param noteSourceCommitment - the output note's source_commitment field
 *   (must have been produced by comSrcV8(srcRoot, srcCount, rhoSrcNote))
 * @param srcRoot - the source descriptor root used in the note
 * @param srcCount - the source descriptor count used in the note
 * @param rhoSrcNote - the blinding factor used in the note (from deriveRhoSrc)
 *
 * Throws if noteSourceCommitment !== comSrcV8(srcRoot, srcCount, rhoSrcNote).
 */
export function computeBucketSrcMetaNoteBacked(
  bucketRole: string,
  bucketSrcInRefDigest: bigint,
  noteSourceCommitment: bigint,
  srcRoot: bigint,
  srcCount: number,
  rhoSrcNote: bigint,
): bigint {
  const recomputed = comSrcV8(srcRoot, srcCount, rhoSrcNote);
  if (recomputed !== noteSourceCommitment) {
    throw new Error(
      'v8.1 §4.2.5 violation: bucketSrcCommit must equal note.source_commitment. ' +
      `Com_src(${srcRoot}, ${srcCount}, rho) = ${recomputed} but note has ${noteSourceCommitment}`,
    );
  }
  return computeBucketSrcMeta(bucketRole, bucketSrcInRefDigest, noteSourceCommitment);
}

/**
 * bucketMetaCommit[τ] = H(DST_BUCKET_META_V3, bucketRole,
 *                         bucketSrcMeta[τ], bucketModInRefDigest[τ], bucketModCommit[τ])
 */
export function computeBucketMetaCommitV8(
  bucketRole: string,
  bucketSrcMeta: bigint,
  bucketModInRefDigest: bigint,
  bucketModCommit: bigint,
): bigint {
  return poseidon([
    dstToFieldElement(DST_BUCKET_META_V3),
    dstToFieldElement(bucketRole),
    bucketSrcMeta,
    bucketModInRefDigest,
    bucketModCommit,
  ]);
}

// ============================================================
// Lineage Binding (v8.1: DST_LINEAGE_BIND_V3)
// ============================================================

/**
 * lineageBinding = H(DST_LINEAGE_BIND_V3, chainid, verifier_addr, txType,
 *                    bucketCount, bucketMetaCommit[0..bucketCount-1])
 */
export function computeLineageBindingV8(
  chainid: bigint,
  verifierAddr: bigint,
  txType: string,
  bucketMetaCommits: bigint[],
): bigint {
  const bucketCount = bucketMetaCommits.length;
  const dst = dstToFieldElement(DST_LINEAGE_BIND_V3);
  let state = poseidon([dst, chainid, verifierAddr]);
  state = poseidon([state, dstToFieldElement(txType), BigInt(bucketCount)]);
  for (const mc of bucketMetaCommits) {
    state = poseidon([state, mc]);
  }
  return state;
}

// ============================================================
// Policy Binding (v8.1: DST_POLICY_BIND_V3)
// ============================================================

/**
 * policyBinding = H(DST_POLICY_BIND_V3, chainid, verifier_addr,
 *                   policy_epoch, reg_seq_used, cleanSourceRoot,
 *                   H_group(A_mod_policy), q_epoch,
 *                   sourcePolicyModeFlag, modulePolicyModeFlag)
 *
 * This is NOT a prover free parameter — contract/verifier must recompute it.
 */
export function computePolicyBindingV8(
  chainid: bigint,
  verifierAddr: bigint,
  policyEpoch: number,
  regSeqUsed: number,
  cleanSourceRoot: bigint,
  aModPolicyHash: bigint,
  qEpoch: bigint,
  sourcePolicyModeFlag: number,
  modulePolicyModeFlag: number,
): bigint {
  return poseidon([
    dstToFieldElement(DST_POLICY_BIND_V3),
    chainid,
    verifierAddr,
    BigInt(policyEpoch),
    BigInt(regSeqUsed),
    cleanSourceRoot,
    aModPolicyHash,
    qEpoch,
    BigInt(sourcePolicyModeFlag),
    BigInt(modulePolicyModeFlag),
  ]);
}
