/**
 * Alias Accumulator (proof-complete v1)
 *
 * A_alias = A_clean[e, reg_seq_used]^{q_alias} mod N
 * C_mid   = C_mid_base^{q_alias} mod N
 *
 * cert_alias = Sig(DST_ALIAS_CERT_V7, chainid, verifier_addr, action,
 *                  bl_epoch, reg_seq_used, session_id, H(A_alias))
 *
 * v7 note: Alias is an OPTIONAL internal implementation detail of R_SUBSET_FROM_TREE.
 * Whether alias is enabled or not does NOT change R_SUBSET_FROM_TREE's semantics.
 * Security proofs target R_SUBSET_FROM_TREE as the normative object, not this alias API.
 */

import { createHash } from 'crypto';
import { modpow } from './di-hash';
import { DST_ALIAS_CERT_V7, DST_REFRESH_ID_V7 } from './constants';

/**
 * Create alias accumulator: A_alias = A_clean^{q_alias} mod N
 */
export function createAlias(aClean: bigint, qAlias: bigint, N: bigint): bigint {
  return modpow(aClean, qAlias, N);
}

/**
 * Lift base witness to alias witness: C_mid = C_mid_base^{q_alias} mod N
 */
export function liftWitness(cMidBase: bigint, qAlias: bigint, N: bigint): bigint {
  return modpow(cMidBase, qAlias, N);
}

/**
 * Verify alias subset: C_mid^{x(S) * q_epoch} === A_alias
 */
export function verifyAliasSubset(
  subset: bigint[],
  cMid: bigint,
  aAlias: bigint,
  qEpoch: bigint,
  N: bigint,
): boolean {
  if (cMid === 1n || cMid === N - 1n) return false;
  if (aAlias === 1n || aAlias === N - 1n) return false;

  let subsetProduct = 1n;
  for (const p of subset) {
    subsetProduct *= p;
  }

  const exponent = subsetProduct * qEpoch;
  const check = modpow(cMid, exponent, N);
  return check === aAlias;
}

/**
 * Compute the alias cert message hash.
 * msg = Hash(DST_ALIAS_CERT_V7, chainid, verifier_addr, action,
 *            bl_epoch, reg_seq_used, session_id, H(A_alias))
 */
export function aliasCertMessage(
  chainId: number,
  verifierAddr: string,
  action: string,
  blEpoch: number,
  regSeqUsed: number,
  sessionId: Uint8Array,
  aAlias: bigint,
): Buffer {
  const h = createHash('sha256');
  h.update(DST_ALIAS_CERT_V7);
  h.update(Buffer.from(chainId.toString()));
  h.update(Buffer.from(verifierAddr));
  h.update(Buffer.from(action));
  h.update(Buffer.from(blEpoch.toString()));
  h.update(Buffer.from(regSeqUsed.toString()));
  h.update(sessionId);
  // H(A_alias) = SHA256(A_alias big-endian bytes)
  let hex = aAlias.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const aliasHash = createHash('sha256').update(Buffer.from(hex, 'hex')).digest();
  h.update(aliasHash);
  return h.digest();
}

/**
 * Generate alias certificate (simplified: HMAC-based for testing).
 * In production this would be ECDSA / EdDSA signature.
 */
export function generateAliasCert(
  chainId: number,
  verifierAddr: string,
  action: string,
  blEpoch: number,
  regSeqUsed: number,
  sessionId: Uint8Array,
  aAlias: bigint,
  signerKey: Uint8Array,
): Buffer {
  const msg = aliasCertMessage(chainId, verifierAddr, action, blEpoch, regSeqUsed, sessionId, aAlias);
  // Simplified: HMAC-SHA256(signerKey, msg) as "signature"
  const hmac = createHash('sha256').update(signerKey).update(msg).digest();
  return hmac;
}

/**
 * Verify alias certificate.
 */
export function verifyAliasCert(
  chainId: number,
  verifierAddr: string,
  action: string,
  blEpoch: number,
  regSeqUsed: number,
  sessionId: Uint8Array,
  aAlias: bigint,
  certAlias: Buffer,
  signerKey: Uint8Array,
): boolean {
  const expected = generateAliasCert(
    chainId, verifierAddr, action, blEpoch, regSeqUsed, sessionId, aAlias, signerKey,
  );
  return certAlias.equals(expected);
}

/**
 * Compute transaction-bound refresh_id for Transfer-refresh.
 *
 * refresh_id = H_refresh(chainid, verifier_addr, bl_epoch, reg_seq_used,
 *                        nullifiers_in[0..n-1], cm_out[0..k-1], c_p_out)
 */
export function computeRefreshId(
  chainId: number,
  verifierAddr: string,
  blEpoch: number,
  regSeqUsed: number,
  nullifiersIn: bigint[],
  cmOut: bigint[],
  cPOut: bigint,
): bigint {
  const h = createHash('sha256');
  h.update(DST_REFRESH_ID_V7);
  h.update(Buffer.from(chainId.toString()));
  h.update(Buffer.from(verifierAddr));
  h.update(Buffer.from(blEpoch.toString()));
  h.update(Buffer.from(regSeqUsed.toString()));
  for (const nf of nullifiersIn) {
    let hex = nf.toString(16);
    if (hex.length % 2) hex = '0' + hex;
    h.update(Buffer.from(hex, 'hex'));
  }
  for (const cm of cmOut) {
    let hex = cm.toString(16);
    if (hex.length % 2) hex = '0' + hex;
    h.update(Buffer.from(hex, 'hex'));
  }
  {
    let hex = cPOut.toString(16);
    if (hex.length % 2) hex = '0' + hex;
    h.update(Buffer.from(hex, 'hex'));
  }
  const digest = h.digest();
  return BigInt('0x' + digest.toString('hex'));
}
