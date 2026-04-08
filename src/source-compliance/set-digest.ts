/**
 * SetDigest v6: separate digests for SrcSet and ModSet
 *
 * SetDigestSrc(S) = Poseidon_sponge(DST_SET_DIGEST_SRC_V1, Enc_set(S))
 * SetDigestMod(M) = Poseidon_sponge(DST_SET_DIGEST_MOD_V1, Enc_set(M))
 */

import { poseidon } from '../utils/poseidon';
import { CanonicalSourceSet } from './canonical-source-set';
import { DST_SET_DIGEST_SRC_V1, DST_SET_DIGEST_MOD_V1 } from './constants';

const BN254_PRIME = BigInt(
  '21888242871839275222246405745257275088548364400416034343698204186575808495617',
);

function dstToFieldElement(dst: string): bigint {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(dst);
  let val = 0n;
  for (const b of bytes) val = (val << 8n) | BigInt(b);
  return val % BN254_PRIME;
}

function bytesToFieldElements(data: Uint8Array): bigint[] {
  const CHUNK_SIZE = 31;
  const elements: bigint[] = [];
  for (let i = 0; i < data.length; i += CHUNK_SIZE) {
    const end = Math.min(i + CHUNK_SIZE, data.length);
    let val = 0n;
    for (let j = i; j < end; j++) val = (val << 8n) | BigInt(data[j]);
    elements.push(val % BN254_PRIME);
  }
  return elements;
}

function spongeDigest(dst: string, set: CanonicalSourceSet): bigint {
  const encoded = set.encode();
  const fieldElements = bytesToFieldElements(encoded);
  const dstElement = dstToFieldElement(dst);
  if (fieldElements.length === 0) return poseidon([dstElement, 0n]);
  let state = poseidon([dstElement, fieldElements[0]]);
  for (let i = 1; i < fieldElements.length; i++) {
    state = poseidon([state, fieldElements[i]]);
  }
  return state;
}

/** SetDigestSrc for source sets */
export function setDigestSrc(set: CanonicalSourceSet): bigint {
  return spongeDigest(DST_SET_DIGEST_SRC_V1, set);
}

/** SetDigestMod for module sets */
export function setDigestMod(set: CanonicalSourceSet): bigint {
  return spongeDigest(DST_SET_DIGEST_MOD_V1, set);
}

/** Legacy alias for backwards compat */
export function setDigest(set: CanonicalSourceSet): bigint {
  return setDigestSrc(set);
}
