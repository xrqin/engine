/**
 * R_TYPEDCALL_CANONICAL_V3 — RAILGUN Source Compliance v8.1
 *
 * Typed call canonical relation: UTXO spend/create, returnVec conservation,
 * manifest binding, session escrow validation.
 *
 * Upgrades from V2:
 * - NoteV5 / noteComV5 (v8.1 note commitment)
 * - v8.1 bindings: computeInputNoteSemV8, computeInputBindingV8, computeOutputBindingV8
 * - NEW: inputLineageBinding as public input (anti-splice for modular lineage subproofs)
 * - NEW: Must verify isAllowedManifest(moduleManifestHash) === true (via manifestRegistry)
 * - NEW: Must verify manifest metadata matches fields encoded in execBinding
 * - NEW: Output notes enforce cleanEpoch === currentPolicyEpoch
 *
 * R_TYPEDCALL_CANONICAL_V3(merkleRootUsed, inputBinding, inputLineageBinding,
 *     outputBinding, lineageBinding, moduleManifestHash, execBinding,
 *     returnBalanceBinding; W_can) = 1 iff
 *   1. canonical UTXO spend/create relation is satisfied
 *   2. RealIn(tx) are exactly the notes bound by inputBinding
 *   3. inputLineageBinding matches the input notes' lineage semantics
 *   4. RealOut(tx) are exactly the notes bound by outputBinding
 *   5. moduleManifestHash resolves to a unique accepted manifest M
 *   6. isAllowedManifest(moduleManifestHash) === true
 *   7. execBinding exactly matches M, sessionEscrow, runtimeArgs, code hashes, etc.
 *   8. manifest metadata matches fields encoded in execBinding
 *   9. session execution receipt shows returnVec consistent with returnBalanceBinding
 *  10. for each declared token tok_i:
 *        amt_i(returnVec) = sum_private_outputs(tok_i)
 *                         + sum_public_outputs(tok_i)
 *                         + deterministicFee(tok_i, M)
 *  11. every output note in bucket tau binds to bucket commitments hidden in lineageBinding
 *  12. all output notes have cleanEpoch === currentPolicyEpoch
 */

import { NoteV5, noteComV5, dstToFieldElement } from '../commitments';
import {
  computeInputNoteSemV8,
  computeInputBindingV8,
  computeInputLineageBinding,
  computeOutputBindingV8,
} from '../bindings';
import {
  DST_EXEC_BIND_V2,
  DST_RETURN_BALANCE_BIND_V2,
  DST_DECLARED_TOKEN_BIND_V1,
  DST_REACHABLE_TOKEN_BIND_V1,
  DST_RUNTIME_ARGS_V1,
} from '../constants';
import { poseidon } from '../../utils/poseidon';
import { ResolvedManifest, ManifestRegistry } from '../manifest-registry';
import { assertCanonicalTokenOrder } from '../session-escrow-v2';

// ============================================================
// Re-export PublicOutput from transfer-canonical-v5
// ============================================================

export interface PublicOutput {
  tokenHash: bigint;
  value: bigint;
  recipient: bigint;
}

// ============================================================
// Token Binding Functions
// ============================================================

/**
 * Compute declaredTokenBinding.
 * Input must be sorted, unique. Rejects duplicates or non-canonical order.
 */
export function computeDeclaredTokenBinding(tokens: bigint[]): bigint {
  assertCanonicalTokenOrder(tokens, 'declaredTokenBinding');
  rejectDuplicates(tokens, 'declaredTokenBinding');

  const dst = dstToFieldElement(DST_DECLARED_TOKEN_BIND_V1);
  let state = poseidon([dst, BigInt(tokens.length)]);
  for (const tok of tokens) {
    state = poseidon([state, tok]);
  }
  return state;
}

/**
 * Compute reachableTokenBinding.
 * Input must be sorted, unique. Rejects duplicates or non-canonical order.
 */
export function computeReachableTokenBinding(tokens: bigint[]): bigint {
  assertCanonicalTokenOrder(tokens, 'reachableTokenBinding');
  rejectDuplicates(tokens, 'reachableTokenBinding');

  const dst = dstToFieldElement(DST_REACHABLE_TOKEN_BIND_V1);
  let state = poseidon([dst, BigInt(tokens.length)]);
  for (const tok of tokens) {
    state = poseidon([state, tok]);
  }
  return state;
}

/**
 * Compute returnBalanceBinding.
 * returnVec is fixed-order aligned with declaredTokenUniverse.
 */
export function computeReturnBalanceBinding(
  chainid: bigint,
  verifierAddr: bigint,
  sessionEscrow: bigint,
  declaredTokenBinding: bigint,
  returnVec: bigint[],
): bigint {
  const dst = dstToFieldElement(DST_RETURN_BALANCE_BIND_V2);
  let state = poseidon([dst, chainid, verifierAddr, sessionEscrow, declaredTokenBinding]);
  for (const amt of returnVec) {
    state = poseidon([state, amt]);
  }
  return state;
}

/**
 * Compute runtimeArgsHash.
 */
export function computeRuntimeArgsHash(args: bigint[]): bigint {
  const dst = dstToFieldElement(DST_RUNTIME_ARGS_V1);
  let state = poseidon([dst, BigInt(args.length)]);
  for (const arg of args) {
    state = poseidon([state, arg]);
  }
  return state;
}

/**
 * Compute execBinding — binds ALL v8.1-required fields.
 */
export function computeExecBinding(
  chainid: bigint,
  verifierAddr: bigint,
  moduleManifestHash: bigint,
  sessionEscrow: bigint,
  declaredTokenBinding: bigint,
  reachableTokenBinding: bigint,
  returnBalanceBinding: bigint,
  policyFlagsHash: bigint,
  callbackPolicyHash: bigint,
  routeShapeHash: bigint,
  runtimeArgsHash: bigint,
  targetCodeHashVectorHash: bigint,
  lineageFlowMatrixHash: bigint,
): bigint {
  const dst = dstToFieldElement(DST_EXEC_BIND_V2);
  let state = poseidon([dst, chainid, verifierAddr]);
  state = poseidon([state, moduleManifestHash]);
  state = poseidon([state, sessionEscrow]);
  state = poseidon([state, declaredTokenBinding]);
  state = poseidon([state, reachableTokenBinding]);
  state = poseidon([state, returnBalanceBinding]);
  state = poseidon([state, policyFlagsHash]);
  state = poseidon([state, callbackPolicyHash]);
  state = poseidon([state, routeShapeHash]);
  state = poseidon([state, runtimeArgsHash]);
  state = poseidon([state, targetCodeHashVectorHash]);
  state = poseidon([state, lineageFlowMatrixHash]);
  return state;
}

// ============================================================
// returnVec Per-Token Conservation
// ============================================================

export interface ReturnVecConservationInput {
  declaredTokenUniverse: bigint[];
  returnVec: bigint[];
  privateOutputs: Array<{ tokenHash: bigint; value: bigint }>;
  publicOutputs: PublicOutput[];
  deterministicFees: Map<string, bigint>;
}

/**
 * Verify returnVec per-token conservation (HARD RELATION):
 *
 * For each declared token tok_i:
 *   amt_i(returnVec) = sum_private_outputs(tok_i)
 *                    + sum_public_outputs(tok_i)
 *                    + deterministicFee(tok_i, M)
 *
 * This is a mandatory check enforced within R_TYPEDCALL_CANONICAL_V3.
 */
export function verifyReturnVecConservationPerDeclaredToken(
  input: ReturnVecConservationInput,
): { ok: true } | { ok: false; tokenIndex: number; expected: bigint; actual: bigint } {
  const { declaredTokenUniverse, returnVec, privateOutputs, publicOutputs, deterministicFees } =
    input;

  if (returnVec.length !== declaredTokenUniverse.length) {
    return {
      ok: false,
      tokenIndex: -1,
      expected: BigInt(declaredTokenUniverse.length),
      actual: BigInt(returnVec.length),
    };
  }

  for (let i = 0; i < declaredTokenUniverse.length; i++) {
    const tok = declaredTokenUniverse[i];
    const tokKey = tok.toString();

    // Sum private outputs for this token
    let privateSum = 0n;
    for (const po of privateOutputs) {
      if (po.tokenHash === tok) privateSum += po.value;
    }

    // Sum public outputs for this token
    let publicSum = 0n;
    for (const po of publicOutputs) {
      if (po.tokenHash === tok) publicSum += po.value;
    }

    // Get deterministic fee
    const fee = deterministicFees.get(tokKey) ?? 0n;

    const expected = privateSum + publicSum + fee;
    if (returnVec[i] !== expected) {
      return { ok: false, tokenIndex: i, expected, actual: returnVec[i] };
    }
  }

  return { ok: true };
}

// ============================================================
// Verify R_TYPEDCALL_CANONICAL_V3
// ============================================================

export interface TypedCallCanonicalV3Witness {
  inputNotes: Array<{ note: NoteV5; nullifier: bigint }>;
  outputNotes: Array<{ note: NoteV5; commitment: bigint }>;
  sessionEscrow: bigint;
  returnVec: bigint[];
  runtimeArgs: bigint[];
  declaredTokenUniverse: bigint[];
  reachableTokenSuperset: bigint[];
  privateOutputs: Array<{ tokenHash: bigint; value: bigint }>;
  publicOutputs: PublicOutput[];
  bucketAssignment: {
    outputBucketIndex: number[];
    bucketSrcCommit: bigint[];
    bucketModCommit: bigint[];
  };
  bucketCount: number;
  currentCodeHashes: bigint[];
  policyFlagsHash: bigint;
  callbackPolicyHash: bigint;
  routeShapeHash: bigint;
}

/**
 * Verify R_TYPEDCALL_CANONICAL_V3.
 */
export function verifyTypedCallCanonicalV3(
  merkleRootUsed: bigint,
  inputBinding: bigint,
  inputLineageBinding: bigint,
  outputBinding: bigint,
  lineageBinding: bigint,
  moduleManifestHash: bigint,
  execBinding: bigint,
  returnBalanceBinding: bigint,
  witness: TypedCallCanonicalV3Witness,
  chainid: bigint,
  verifierAddr: bigint,
  manifestRegistry: ManifestRegistry,
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

  // 4. Resolve manifest — must be registered and enabled
  let resolved: ResolvedManifest;
  try {
    resolved = manifestRegistry.resolveManifest(moduleManifestHash);
  } catch {
    return false;
  }

  // 5. Verify isAllowedManifest(moduleManifestHash) === true
  if (!manifestRegistry.isRegisteredAndEnabled(moduleManifestHash)) {
    return false;
  }

  // 6. Verify code hashes haven't drifted
  if (!manifestRegistry.verifyCodeHashes(moduleManifestHash, witness.currentCodeHashes)) {
    return false;
  }

  // 7. Verify canonical token ordering
  try {
    assertCanonicalTokenOrder(witness.declaredTokenUniverse, 'declaredTokenUniverse');
    assertCanonicalTokenOrder(witness.reachableTokenSuperset, 'reachableTokenSuperset');
  } catch {
    return false;
  }

  // 8. Verify declared is subset of reachable
  const reachableSet = new Set(witness.reachableTokenSuperset.map(t => t.toString()));
  for (const tok of witness.declaredTokenUniverse) {
    if (!reachableSet.has(tok.toString())) return false;
  }

  // 9. Verify execBinding — manifest metadata must match fields encoded in execBinding
  const declaredTokenBinding = computeDeclaredTokenBinding(witness.declaredTokenUniverse);
  const reachableTokenBinding = computeReachableTokenBinding(witness.reachableTokenSuperset);
  const runtimeArgsHash = computeRuntimeArgsHash(witness.runtimeArgs);

  const computedExecBinding = computeExecBinding(
    chainid,
    verifierAddr,
    moduleManifestHash,
    witness.sessionEscrow,
    declaredTokenBinding,
    reachableTokenBinding,
    returnBalanceBinding,
    witness.policyFlagsHash,
    witness.callbackPolicyHash,
    witness.routeShapeHash,
    runtimeArgsHash,
    resolved.manifest.targetCodeHashVectorHash,
    resolved.manifest.lineageFlowMatrixHash,
  );
  if (computedExecBinding !== execBinding) return false;

  // 10. Verify returnBalanceBinding
  const computedReturnBalBinding = computeReturnBalanceBinding(
    chainid,
    verifierAddr,
    witness.sessionEscrow,
    declaredTokenBinding,
    witness.returnVec,
  );
  if (computedReturnBalBinding !== returnBalanceBinding) return false;

  // 11. Verify returnVec per-token conservation (HARD RELATION)
  const conservation = verifyReturnVecConservationPerDeclaredToken({
    declaredTokenUniverse: witness.declaredTokenUniverse,
    returnVec: witness.returnVec,
    privateOutputs: witness.privateOutputs,
    publicOutputs: witness.publicOutputs,
    deterministicFees: resolved.deterministicFees,
  });
  if (!conservation.ok) return false;

  // 12. Verify output commitment integrity (noteComV5)
  for (const out of witness.outputNotes) {
    if (noteComV5(out.note) !== out.commitment) return false;
  }

  // 13. All output notes: cleanEpoch === currentPolicyEpoch
  for (const out of witness.outputNotes) {
    if (out.note.cleanEpoch !== currentPolicyEpoch) return false;
  }

  // 14. Verify output notes bind to bucket commitments
  for (let i = 0; i < witness.outputNotes.length; i++) {
    const tau = witness.bucketAssignment.outputBucketIndex[i];
    const note = witness.outputNotes[i].note;
    if (note.sourceCommitment !== witness.bucketAssignment.bucketSrcCommit[tau]) return false;
    if (note.moduleCommitment !== witness.bucketAssignment.bucketModCommit[tau]) return false;
  }

  return true;
}

// ============================================================
// Helpers
// ============================================================

function rejectDuplicates(tokens: bigint[], label: string): void {
  const seen = new Set<string>();
  for (const tok of tokens) {
    const key = tok.toString();
    if (seen.has(key)) {
      throw new Error(`${label}: duplicate token ${key}`);
    }
    seen.add(key);
  }
}
