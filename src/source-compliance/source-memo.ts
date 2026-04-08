/**
 * Source & Module Memo — Receiver-Private Lineage Delivery (v8.1)
 *
 * Implements AEAD-encrypted lineage payload delivery per spec §4.1.5:
 *
 * Source side:
 * - buildSourcePayload / decodeSourcePayload
 * - buildSourcePackageId
 * - verifySourcePayload
 * - SourceCache
 *
 * Module side:
 * - buildModulePayload / decodeModulePayload
 * - buildModulePackageId
 * - verifyModulePayload
 * - ModuleCache
 *
 * Unified lineage memo (carries BOTH source and module):
 * - buildLineageMemoAD
 * - encryptLineageMemo / decryptLineageMemo
 *
 * Legacy source-only memo (retained for backwards compat):
 * - buildMemoAD
 * - encryptSourceMemo / decryptSourceMemo
 *
 * Normative rule: receiver must be able to reconstruct exact source AND
 * module lists from note ciphertexts WITHOUT assuming sender-side cache skip.
 */

import { poseidon } from '../utils/poseidon';
import { dstToFieldElement } from './commitments';
import { comSrcV8, comModV8, deriveRhoSrc, deriveRhoMod } from './commitments';
import {
  DST_MEMO_AD_V1,
  DST_LINEAGE_MEMO_AD_V1,
  DST_SRC_PACKAGE_ID_V1,
  DST_MOD_PACKAGE_ID_V1,
  NOTE_VERSION_V5,
} from './constants';
import { buildSourceDescriptor } from './source-descriptor';
import type { SourceDescriptor } from './source-descriptor';
import { buildModuleDescriptor } from './module-descriptor';
import type { ModuleDescriptor } from './module-descriptor';
import { encodeCanonicalModuleBytes, decodeCanonicalModuleBytes } from './module-tag-encoding';

// ============================================================
// Source Payload — canonical serialization
// ============================================================

/**
 * Build canonical source payload from sorted unique source primes.
 * Format: [count (4 bytes BE), prime_0 (32 bytes BE), ..., prime_{n-1} (32 bytes BE)]
 */
export function buildSourcePayload(sortedUniqueSources: bigint[]): Uint8Array {
  const count = sortedUniqueSources.length;
  const buf = new Uint8Array(4 + count * 32);

  // 4-byte big-endian count
  buf[0] = (count >> 24) & 0xff;
  buf[1] = (count >> 16) & 0xff;
  buf[2] = (count >> 8) & 0xff;
  buf[3] = count & 0xff;

  // Each prime as 32-byte big-endian
  for (let i = 0; i < count; i++) {
    const p = sortedUniqueSources[i];
    for (let j = 31; j >= 0; j--) {
      buf[4 + i * 32 + (31 - j)] = Number((p >> BigInt(j * 8)) & 0xffn);
    }
  }
  return buf;
}

/**
 * Decode source payload back to sorted unique source primes.
 */
export function decodeSourcePayload(payload: Uint8Array): bigint[] {
  if (payload.length < 4) throw new Error('Source payload too short');
  const count = (payload[0] << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3];
  if (payload.length !== 4 + count * 32) {
    throw new Error(`Source payload length mismatch: expected ${4 + count * 32}, got ${payload.length}`);
  }

  const primes: bigint[] = [];
  for (let i = 0; i < count; i++) {
    let p = 0n;
    for (let j = 0; j < 32; j++) {
      p = (p << 8n) | BigInt(payload[4 + i * 32 + j]);
    }
    primes.push(p);
  }
  return primes;
}

// ============================================================
// Source Package ID — content-addressed cache key
// ============================================================

/**
 * Compute source_package_id = H(DST_SRC_PACKAGE_ID_V1, src_root, src_count, H(payload))
 */
export function buildSourcePackageId(
  srcRoot: bigint,
  srcCount: number,
  sourcePayload: Uint8Array,
): bigint {
  // Hash the payload bytes via Poseidon sponge (absorb 32-byte chunks)
  const payloadHash = hashBytes(sourcePayload);
  return poseidon([
    dstToFieldElement(DST_SRC_PACKAGE_ID_V1),
    srcRoot,
    BigInt(srcCount),
    payloadHash,
  ]);
}

// ============================================================
// Memo Associated Data — binds ciphertext to note context
// ============================================================

/**
 * Compute memoAD = H(DST_MEMO_AD_V1, chainid, noteCommitment, outputIndex,
 *                     source_commitment, module_commitment, clean_epoch, NOTE_VERSION_V5)
 *
 * This is the associated data for AEAD encryption. It ensures the ciphertext
 * is authenticated to a specific note and cannot be swapped between outputs.
 */
export function buildMemoAD(
  chainid: bigint,
  noteCommitment: bigint,
  outputIndex: number,
  sourceCommitment: bigint,
  moduleCommitment: bigint,
  cleanEpoch: bigint,
): bigint {
  return poseidon([
    dstToFieldElement(DST_MEMO_AD_V1),
    chainid,
    noteCommitment,
    BigInt(outputIndex),
    sourceCommitment,
    moduleCommitment,
    cleanEpoch,
    BigInt(NOTE_VERSION_V5),
  ]);
}

// ============================================================
// AEAD Encrypt / Decrypt
// ============================================================

/**
 * Encrypt source payload with AEAD.
 *
 * In production, use a proper AEAD scheme (e.g., ChaCha20-Poly1305).
 * This implementation uses XOR with Poseidon-derived keystream + Poseidon MAC
 * as a simplified AEAD suitable for the protocol model.
 */
export function encryptSourceMemo(
  sharedSecret: bigint,
  memoAD: bigint,
  sourcePayload: Uint8Array,
): Uint8Array {
  // Derive key from shared secret + memoAD
  const key = poseidon([sharedSecret, memoAD, BigInt(sourcePayload.length)]);

  // XOR-encrypt payload with Poseidon-derived keystream
  const ciphertext = new Uint8Array(sourcePayload.length + 32); // payload + 32-byte tag
  const keystream = deriveKeystream(key, sourcePayload.length);
  for (let i = 0; i < sourcePayload.length; i++) {
    ciphertext[i] = sourcePayload[i] ^ keystream[i];
  }

  // Compute authentication tag: H(key, memoAD, ciphertext_hash)
  const ctHash = hashBytes(ciphertext.subarray(0, sourcePayload.length));
  const tag = poseidon([key, memoAD, ctHash]);

  // Append tag as 32 bytes
  const tagBytes = bigintToBytes32(tag);
  ciphertext.set(tagBytes, sourcePayload.length);

  return ciphertext;
}

/**
 * Decrypt source payload with AEAD.
 * Returns null if authentication fails.
 */
export function decryptSourceMemo(
  sharedSecret: bigint,
  memoAD: bigint,
  ciphertext: Uint8Array,
): Uint8Array | null {
  if (ciphertext.length < 32) return null;

  const payloadLen = ciphertext.length - 32;
  const key = poseidon([sharedSecret, memoAD, BigInt(payloadLen)]);

  // Verify authentication tag
  const ctHash = hashBytes(ciphertext.subarray(0, payloadLen));
  const expectedTag = poseidon([key, memoAD, ctHash]);
  const actualTag = bytes32ToBigint(ciphertext.subarray(payloadLen));

  if (expectedTag !== actualTag) return null;

  // Decrypt
  const keystream = deriveKeystream(key, payloadLen);
  const plaintext = new Uint8Array(payloadLen);
  for (let i = 0; i < payloadLen; i++) {
    plaintext[i] = ciphertext[i] ^ keystream[i];
  }

  return plaintext;
}

// ============================================================
// Receiver-Side Verification
// ============================================================

/**
 * Verify a decrypted source payload against the note's source_commitment.
 *
 * Per spec §4.3.18:
 *   1. Decode payload → sorted source list
 *   2. Verify sorted + unique
 *   3. BuildSourceDescriptor(list) = (src_root, src_count)
 *   4. Com_src(src_root, src_count; rho_src_note) == note.source_commitment
 *
 * rho_src_note is derived deterministically from note seed.
 */
export function verifySourcePayload(
  sourcePayload: Uint8Array,
  sourceCommitment: bigint,
  rhoValue: bigint,
  ownerPubkey: bigint,
  outputIndex: number,
): { valid: boolean; descriptor?: SourceDescriptor; sources?: bigint[] } {
  try {
    // 1. Decode
    const sources = decodeSourcePayload(sourcePayload);

    // 2. Verify sorted + unique
    for (let i = 1; i < sources.length; i++) {
      if (sources[i] <= sources[i - 1]) {
        return { valid: false };
      }
    }

    // 3. Build descriptor
    const descriptor = buildSourceDescriptor(sources);

    // 4. Derive rho_src and check commitment
    const rhoSrc = deriveRhoSrc(rhoValue, ownerPubkey, outputIndex);
    const expectedCommitment = comSrcV8(descriptor.srcRoot, descriptor.srcCount, rhoSrc);

    if (expectedCommitment !== sourceCommitment) {
      return { valid: false };
    }

    return { valid: true, descriptor, sources };
  } catch {
    return { valid: false };
  }
}

// ============================================================
// Source Cache
// ============================================================

/**
 * Local source cache: source_package_id → source_payload.
 *
 * Per spec §4.1.5: cache-skip optimization is allowed ONLY with
 * explicit receiver acknowledgement for the source_package_id.
 */
export class SourceCache {
  private cache = new Map<string, Uint8Array>();

  /** Store a verified source payload. */
  put(sourcePackageId: bigint, sourcePayload: Uint8Array): void {
    this.cache.set(sourcePackageId.toString(), new Uint8Array(sourcePayload));
  }

  /** Retrieve cached source payload, or undefined. */
  get(sourcePackageId: bigint): Uint8Array | undefined {
    const cached = this.cache.get(sourcePackageId.toString());
    return cached ? new Uint8Array(cached) : undefined;
  }

  /** Check if a source payload is cached. */
  has(sourcePackageId: bigint): boolean {
    return this.cache.has(sourcePackageId.toString());
  }

  /** Remove a cached entry. */
  delete(sourcePackageId: bigint): boolean {
    return this.cache.delete(sourcePackageId.toString());
  }

  /** Get cache size. */
  get size(): number {
    return this.cache.size;
  }

  /** Clear all cached entries. */
  clear(): void {
    this.cache.clear();
  }
}

// ============================================================
// Module Payload — canonical serialization (D.4b)
// ============================================================

/**
 * Build canonical module payload from sorted unique module primes.
 * Format: [count (4 bytes BE), prime_0 (36 bytes BE), ..., prime_{n-1} (36 bytes BE)]
 * Module primes are 288-bit (36 bytes).
 */
export function buildModulePayload(sortedUniqueModules: bigint[]): Uint8Array {
  return encodeCanonicalModuleBytes(sortedUniqueModules);
}

/**
 * Decode module payload back to sorted unique module primes.
 */
export function decodeModulePayload(payload: Uint8Array): bigint[] {
  return decodeCanonicalModuleBytes(payload);
}

// ============================================================
// Module Package ID — content-addressed cache key (D.4d)
// ============================================================

/**
 * Compute module_package_id = H(DST_MOD_PACKAGE_ID_V1, mod_root, mod_count, H(payload))
 */
export function buildModulePackageId(
  modRoot: bigint,
  modCount: number,
  modulePayload: Uint8Array,
): bigint {
  const payloadHash = hashBytes(modulePayload);
  return poseidon([
    dstToFieldElement(DST_MOD_PACKAGE_ID_V1),
    modRoot,
    BigInt(modCount),
    payloadHash,
  ]);
}

// ============================================================
// Unified Lineage Memo AD (D.4f)
// ============================================================

/**
 * Compute lineage memo AD that binds BOTH source and module context.
 *
 * lineageMemoAD = H(DST_LINEAGE_MEMO_AD_V1, chainid, noteCommitment, outputIndex,
 *                    source_commitment, module_commitment, clean_epoch, NOTE_VERSION_V5)
 */
export function buildLineageMemoAD(
  chainid: bigint,
  noteCommitment: bigint,
  outputIndex: number,
  sourceCommitment: bigint,
  moduleCommitment: bigint,
  cleanEpoch: bigint,
): bigint {
  return poseidon([
    dstToFieldElement(DST_LINEAGE_MEMO_AD_V1),
    chainid,
    noteCommitment,
    BigInt(outputIndex),
    sourceCommitment,
    moduleCommitment,
    cleanEpoch,
    BigInt(NOTE_VERSION_V5),
  ]);
}

// ============================================================
// Unified Lineage Memo — carries BOTH source + module (D.4f)
// ============================================================

/**
 * Lineage payload wire format:
 *   [src_payload_len (4 bytes BE), source_payload, module_payload]
 *
 * This carries both source and module openings in a single encrypted memo,
 * ensuring receivers can spend received notes.
 */

function buildLineagePayload(
  sourcePayload: Uint8Array,
  modulePayload: Uint8Array,
): Uint8Array {
  const srcLen = sourcePayload.length;
  const buf = new Uint8Array(4 + srcLen + modulePayload.length);

  // 4-byte big-endian source payload length
  buf[0] = (srcLen >> 24) & 0xff;
  buf[1] = (srcLen >> 16) & 0xff;
  buf[2] = (srcLen >> 8) & 0xff;
  buf[3] = srcLen & 0xff;

  buf.set(sourcePayload, 4);
  buf.set(modulePayload, 4 + srcLen);
  return buf;
}

function splitLineagePayload(
  payload: Uint8Array,
): { sourcePayload: Uint8Array; modulePayload: Uint8Array } | null {
  if (payload.length < 4) return null;
  const srcLen = (payload[0] << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3];
  if (payload.length < 4 + srcLen) return null;

  return {
    sourcePayload: payload.slice(4, 4 + srcLen),
    modulePayload: payload.slice(4 + srcLen),
  };
}

/**
 * Encrypt unified lineage memo carrying BOTH source and module payloads.
 */
export function encryptLineageMemo(
  sharedSecret: bigint,
  lineageMemoAD: bigint,
  sourcePayload: Uint8Array,
  modulePayload: Uint8Array,
): Uint8Array {
  const combined = buildLineagePayload(sourcePayload, modulePayload);

  const key = poseidon([sharedSecret, lineageMemoAD, BigInt(combined.length)]);

  const ciphertext = new Uint8Array(combined.length + 32);
  const keystream = deriveKeystream(key, combined.length);
  for (let i = 0; i < combined.length; i++) {
    ciphertext[i] = combined[i] ^ keystream[i];
  }

  const ctHash = hashBytes(ciphertext.subarray(0, combined.length));
  const tag = poseidon([key, lineageMemoAD, ctHash]);
  const tagBytes = bigintToBytes32(tag);
  ciphertext.set(tagBytes, combined.length);

  return ciphertext;
}

/**
 * Decrypt unified lineage memo.
 * Returns null if authentication fails.
 */
export function decryptLineageMemo(
  sharedSecret: bigint,
  lineageMemoAD: bigint,
  ciphertext: Uint8Array,
): { sourcePayload: Uint8Array; modulePayload: Uint8Array } | null {
  if (ciphertext.length < 32) return null;

  const payloadLen = ciphertext.length - 32;
  const key = poseidon([sharedSecret, lineageMemoAD, BigInt(payloadLen)]);

  // Verify tag
  const ctHash = hashBytes(ciphertext.subarray(0, payloadLen));
  const expectedTag = poseidon([key, lineageMemoAD, ctHash]);
  const actualTag = bytes32ToBigint(ciphertext.subarray(payloadLen));
  if (expectedTag !== actualTag) return null;

  // Decrypt
  const keystream = deriveKeystream(key, payloadLen);
  const plaintext = new Uint8Array(payloadLen);
  for (let i = 0; i < payloadLen; i++) {
    plaintext[i] = ciphertext[i] ^ keystream[i];
  }

  return splitLineagePayload(plaintext);
}

// ============================================================
// Module Verification — receiver-side (D.5b)
// ============================================================

/**
 * Verify a decrypted module payload against the note's module_commitment.
 *
 * Analogous to verifySourcePayload:
 *   1. Decode payload -> sorted module list
 *   2. Verify sorted + unique
 *   3. BuildModuleDescriptor(list) = (mod_root, mod_count)
 *   4. Com_mod(mod_root, mod_count; rho_mod_note) == note.module_commitment
 *
 * rho_mod_note is derived deterministically from note seed.
 */
export function verifyModulePayload(
  modulePayload: Uint8Array,
  moduleCommitment: bigint,
  rhoValue: bigint,
  ownerPubkey: bigint,
  outputIndex: number,
): { valid: boolean; descriptor?: ModuleDescriptor; modules?: bigint[] } {
  try {
    // 1. Decode
    const modules = decodeModulePayload(modulePayload);

    // 2. Verify sorted + unique
    for (let i = 1; i < modules.length; i++) {
      if (modules[i] <= modules[i - 1]) {
        return { valid: false };
      }
    }

    // 3. Build descriptor
    const descriptor = buildModuleDescriptor(modules);

    // 4. Derive rho_mod and check commitment
    const rhoMod = deriveRhoMod(rhoValue, ownerPubkey, outputIndex);
    const expectedCommitment = comModV8(descriptor.modRoot, descriptor.modCount, rhoMod);

    if (expectedCommitment !== moduleCommitment) {
      return { valid: false };
    }

    return { valid: true, descriptor, modules };
  } catch {
    return { valid: false };
  }
}

// ============================================================
// Module Cache (D.6b)
// ============================================================

/**
 * Local module cache: module_package_id -> module_payload.
 *
 * Same semantics as SourceCache: cache-skip optimization is allowed ONLY
 * with explicit receiver acknowledgement for the module_package_id.
 */
export class ModuleCache {
  private cache = new Map<string, Uint8Array>();

  put(modulePackageId: bigint, modulePayload: Uint8Array): void {
    this.cache.set(modulePackageId.toString(), new Uint8Array(modulePayload));
  }

  get(modulePackageId: bigint): Uint8Array | undefined {
    const cached = this.cache.get(modulePackageId.toString());
    return cached ? new Uint8Array(cached) : undefined;
  }

  has(modulePackageId: bigint): boolean {
    return this.cache.has(modulePackageId.toString());
  }

  delete(modulePackageId: bigint): boolean {
    return this.cache.delete(modulePackageId.toString());
  }

  get size(): number {
    return this.cache.size;
  }

  clear(): void {
    this.cache.clear();
  }
}

// ============================================================
// Internal helpers
// ============================================================

/** Hash arbitrary bytes via Poseidon sponge (absorb 31-byte chunks as field elements). */
function hashBytes(data: Uint8Array): bigint {
  if (data.length === 0) return poseidon([0n]);
  let state = 0n;
  for (let i = 0; i < data.length; i += 31) {
    const end = Math.min(i + 31, data.length);
    let chunk = 0n;
    for (let j = i; j < end; j++) {
      chunk = (chunk << 8n) | BigInt(data[j]);
    }
    state = poseidon([state, chunk]);
  }
  return state;
}

/** Derive keystream bytes from a Poseidon-based PRF. */
function deriveKeystream(key: bigint, length: number): Uint8Array {
  const ks = new Uint8Array(length);
  let counter = 0n;
  let offset = 0;
  while (offset < length) {
    const block = poseidon([key, counter]);
    const blockBytes = bigintToBytes32(block);
    const toCopy = Math.min(32, length - offset);
    ks.set(blockBytes.subarray(0, toCopy), offset);
    offset += toCopy;
    counter += 1n;
  }
  return ks;
}

/** Convert bigint to 32-byte big-endian Uint8Array. */
function bigintToBytes32(n: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  let val = n;
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(val & 0xffn);
    val >>= 8n;
  }
  return bytes;
}

/** Convert 32-byte big-endian Uint8Array to bigint. */
function bytes32ToBigint(bytes: Uint8Array): bigint {
  let val = 0n;
  for (let i = 0; i < 32; i++) {
    val = (val << 8n) | BigInt(bytes[i]);
  }
  return val;
}
