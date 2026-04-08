/**
 * Source Compliance Commitments
 *
 * v6 (flat SetDigest binding):
 *   Com_src(D_src; rho) = Poseidon(DST_SRC_COMMIT_V7, D_src, rho)
 *   Com_mod(D_mod; rho) = Poseidon(DST_MOD_COMMIT_V1, D_mod, rho)
 *
 * v7 (canonical set tree root+count binding):
 *   Com_src(src_root, src_count; rho) = Poseidon(DST_SRC_COMMIT_V2, src_root, src_count, rho)
 *   Com_mod(mod_root, mod_count; rho) = Poseidon(DST_MOD_COMMIT_V2, mod_root, mod_count, rho)
 *   NoteComV4(note) = Poseidon(DST_NOTE_COM_V4, value, tokenHash, owner_pubkey, rho_value,
 *                               source_commitment, module_commitment, clean_epoch, NOTE_VERSION_V4)
 *
 * CommitVec(m, p_0,...,p_{m-1}; rho_p) — LENGTH-BINDING (shared v6/v7)
 */

import { poseidon } from '../utils/poseidon';
import {
  DST_SRC_COMMIT_V7, DST_MOD_COMMIT_V1, DST_COMMIT_VEC_V7,
  DST_SRC_COMMIT_V2, DST_MOD_COMMIT_V2, DST_NOTE_COM_V4,
  NOTE_VERSION_V4,
  DST_SRC_COMMIT_V3, DST_MOD_COMMIT_V3, DST_NOTE_COM_V5, NOTE_VERSION_V5,
  DST_DERIVE_RHO_SRC_V1, DST_DERIVE_RHO_MOD_V1,
} from './constants';

export const BN254_PRIME = BigInt(
  '21888242871839275222246405745257275088548364400416034343698204186575808495617',
);

export function dstToFieldElement(dst: string): bigint {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(dst);
  let val = 0n;
  for (const b of bytes) val = (val << 8n) | BigInt(b);
  return val % BN254_PRIME;
}

// ---------------------------------------------------------------------------
// v6 commitments (flat SetDigest binding)
// ---------------------------------------------------------------------------

/** Com_src(digest, rho) — v6 source set commitment */
export function comSrcset(digest: bigint, rho: bigint): bigint {
  return poseidon([dstToFieldElement(DST_SRC_COMMIT_V7), digest, rho]);
}

/** Com_mod(digest, rho) — v6 module set commitment */
export function comModset(digest: bigint, rho: bigint): bigint {
  return poseidon([dstToFieldElement(DST_MOD_COMMIT_V1), digest, rho]);
}

// ---------------------------------------------------------------------------
// v7 commitments (canonical set tree root+count binding)
// ---------------------------------------------------------------------------

/** Com_src(src_root, src_count; rho) — v7 source commitment with tree root binding */
export function comSrc(srcRoot: bigint, srcCount: number, rho: bigint): bigint {
  return poseidon([
    dstToFieldElement(DST_SRC_COMMIT_V2),
    srcRoot,
    BigInt(srcCount),
    rho,
  ]);
}

/** Com_mod(mod_root, mod_count; rho) — v7 module commitment with tree root binding */
export function comMod(modRoot: bigint, modCount: number, rho: bigint): bigint {
  return poseidon([
    dstToFieldElement(DST_MOD_COMMIT_V2),
    modRoot,
    BigInt(modCount),
    rho,
  ]);
}

/** NoteV4 fields */
export interface NoteV4 {
  value: bigint;
  tokenHash: bigint;
  ownerPubkey: bigint;
  rhoValue: bigint;
  sourceCommitment: bigint;
  moduleCommitment: bigint;
  cleanEpoch: bigint;
}

/** NoteComV4(note) — v7 note commitment binding all 8 fields */
export function noteComV4(note: NoteV4): bigint {
  return poseidon([
    dstToFieldElement(DST_NOTE_COM_V4),
    note.value,
    note.tokenHash,
    note.ownerPubkey,
    note.rhoValue,
    note.sourceCommitment,
    note.moduleCommitment,
    note.cleanEpoch,
    BigInt(NOTE_VERSION_V4),
  ]);
}

// ---------------------------------------------------------------------------
// v8.1 commitments (binary frontier descriptor binding)
// ---------------------------------------------------------------------------

/** Com_src(src_root, src_count; rho_src) — v8.1 source commitment */
export function comSrcV8(srcRoot: bigint, srcCount: number, rhoSrc: bigint): bigint {
  return poseidon([
    dstToFieldElement(DST_SRC_COMMIT_V3),
    srcRoot,
    BigInt(srcCount),
    rhoSrc,
  ]);
}

/** Com_mod(mod_root, mod_count; rho_mod) — v8.1 module commitment */
export function comModV8(modRoot: bigint, modCount: number, rhoMod: bigint): bigint {
  return poseidon([
    dstToFieldElement(DST_MOD_COMMIT_V3),
    modRoot,
    BigInt(modCount),
    rhoMod,
  ]);
}

/** DeriveRhoSrc — deterministic blinding factor from note seed */
export function deriveRhoSrc(
  rhoValue: bigint,
  ownerPubkey: bigint,
  outputIndex: number,
): bigint {
  return poseidon([
    dstToFieldElement(DST_DERIVE_RHO_SRC_V1),
    rhoValue,
    ownerPubkey,
    BigInt(outputIndex),
  ]);
}

/** DeriveRhoMod — deterministic blinding factor from note seed */
export function deriveRhoMod(
  rhoValue: bigint,
  ownerPubkey: bigint,
  outputIndex: number,
): bigint {
  return poseidon([
    dstToFieldElement(DST_DERIVE_RHO_MOD_V1),
    rhoValue,
    ownerPubkey,
    BigInt(outputIndex),
  ]);
}

/** NoteV5 fields */
export interface NoteV5 {
  value: bigint;
  tokenHash: bigint;
  ownerPubkey: bigint;
  rhoValue: bigint;
  sourceCommitment: bigint;
  moduleCommitment: bigint;
  cleanEpoch: bigint;
}

/** NoteComV5(note) — v8.1 note commitment binding all fields + NOTE_VERSION_V5 */
export function noteComV5(note: NoteV5): bigint {
  return poseidon([
    dstToFieldElement(DST_NOTE_COM_V5),
    note.value,
    note.tokenHash,
    note.ownerPubkey,
    note.rhoValue,
    note.sourceCommitment,
    note.moduleCommitment,
    note.cleanEpoch,
    BigInt(NOTE_VERSION_V5),
  ]);
}

// ---------------------------------------------------------------------------
// Shared: CommitVec (length-binding prime-vector commitment)
// ---------------------------------------------------------------------------

export function commitVec(primes: bigint[], rhoP: bigint): bigint {
  const dstElement = dstToFieldElement(DST_COMMIT_VEC_V7);
  const m = BigInt(primes.length);
  let state = poseidon([dstElement, m]);
  for (let i = 0; i < primes.length; i++) {
    state = poseidon([state, primes[i] % BN254_PRIME]);
  }
  state = poseidon([state, rhoP]);
  return state;
}
