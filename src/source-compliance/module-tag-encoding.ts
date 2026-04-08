/**
 * Module / Tag Canonical Encoding Helpers — v8.1
 *
 * Provides canonical normalization and encoding for:
 * - Module locators (contract address / identifier → canonical bytes → prime)
 * - Boundary tags (string label → canonical bytes → prime)
 * - Module tag sets (combined module + tag → sorted prime list)
 *
 * All encoding uses deterministic normalization so that the same logical
 * module/tag always produces the same prime regardless of input formatting.
 */

import { createHash } from 'crypto';
import { dstToFieldElement } from './commitments';
import { DST_MOD_TAG_ENCODE_V1 } from './constants';
import { hashToPrimeMod } from './di-hash';

// ---------------------------------------------------------------------------
// Module Locator Normalization
// ---------------------------------------------------------------------------

/**
 * Normalize a module locator string to canonical bytes.
 *
 * Rules:
 * - Hex addresses: strip 0x prefix, lowercase, pad to 20 bytes
 * - String identifiers: UTF-8 encode, prefix with length byte
 * - Already-bytes: use directly
 */
export function normalizeModuleLocator(locator: string | Uint8Array): Uint8Array {
  if (locator instanceof Uint8Array) {
    return locator;
  }

  // Hex address (0x-prefixed or 40-char hex)
  const hexMatch = locator.match(/^(?:0x)?([0-9a-fA-F]{40})$/);
  if (hexMatch) {
    const hex = hexMatch[1].toLowerCase();
    const bytes = new Uint8Array(20);
    for (let i = 0; i < 20; i++) {
      bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  // String identifier: length-prefixed UTF-8
  const encoder = new TextEncoder();
  const strBytes = encoder.encode(locator);
  const result = new Uint8Array(1 + strBytes.length);
  result[0] = strBytes.length & 0xff;
  result.set(strBytes, 1);
  return result;
}

/**
 * Encode a module locator to its canonical prime in P_mod domain.
 */
export function encodeModuleLocator(locator: string | Uint8Array): bigint {
  const normalized = normalizeModuleLocator(locator);
  return hashToPrimeMod(normalized);
}

// ---------------------------------------------------------------------------
// Tag Encoding
// ---------------------------------------------------------------------------

/**
 * Encode a boundary tag string to its canonical prime in P_mod domain.
 *
 * Tags are domain-separated from module locators via DST_MOD_TAG_ENCODE_V1.
 */
export function encodeTag(tag: string): bigint {
  const encoder = new TextEncoder();
  const tagBytes = encoder.encode(tag);
  const dstBytes = encoder.encode(DST_MOD_TAG_ENCODE_V1);

  // Domain-separated: H(DST || tag_bytes)
  const combined = new Uint8Array(dstBytes.length + tagBytes.length);
  combined.set(dstBytes, 0);
  combined.set(tagBytes, dstBytes.length);

  return hashToPrimeMod(combined);
}

// ---------------------------------------------------------------------------
// Module Tag Set Builder
// ---------------------------------------------------------------------------

/**
 * Build a sorted, unique prime list from module locators and/or tags.
 *
 * @param modules - module locator strings or bytes
 * @param tags - boundary tag strings
 * @returns sorted unique primes suitable for buildModuleDescriptor
 */
export function buildModuleTagSet(
  modules: Array<string | Uint8Array>,
  tags: string[],
): bigint[] {
  const primeSet = new Set<bigint>();

  for (const mod of modules) {
    primeSet.add(encodeModuleLocator(mod));
  }
  for (const tag of tags) {
    primeSet.add(encodeTag(tag));
  }

  const sorted = [...primeSet].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return sorted;
}

// ---------------------------------------------------------------------------
// Canonical Module Bytes (for payload serialization)
// ---------------------------------------------------------------------------

/**
 * Encode a sorted unique module prime list to canonical bytes.
 * Format: [count (4 bytes BE), prime_0 (36 bytes BE), ..., prime_{n-1} (36 bytes BE)]
 *
 * Module primes are 288-bit (36 bytes), vs source primes which are 256-bit (32 bytes).
 */
export function encodeCanonicalModuleBytes(sortedUniqueModules: bigint[]): Uint8Array {
  const count = sortedUniqueModules.length;
  const PRIME_BYTES = 36; // 288 bits
  const buf = new Uint8Array(4 + count * PRIME_BYTES);

  // 4-byte big-endian count
  buf[0] = (count >> 24) & 0xff;
  buf[1] = (count >> 16) & 0xff;
  buf[2] = (count >> 8) & 0xff;
  buf[3] = count & 0xff;

  // Each prime as 36-byte big-endian
  for (let i = 0; i < count; i++) {
    const p = sortedUniqueModules[i];
    for (let j = PRIME_BYTES - 1; j >= 0; j--) {
      buf[4 + i * PRIME_BYTES + (PRIME_BYTES - 1 - j)] = Number((p >> BigInt(j * 8)) & 0xffn);
    }
  }
  return buf;
}

/**
 * Decode canonical module bytes back to sorted unique module primes.
 */
export function decodeCanonicalModuleBytes(payload: Uint8Array): bigint[] {
  if (payload.length < 4) throw new Error('Module payload too short');
  const count = (payload[0] << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3];
  const PRIME_BYTES = 36;
  if (payload.length !== 4 + count * PRIME_BYTES) {
    throw new Error(
      `Module payload length mismatch: expected ${4 + count * PRIME_BYTES}, got ${payload.length}`,
    );
  }

  const primes: bigint[] = [];
  for (let i = 0; i < count; i++) {
    let p = 0n;
    for (let j = 0; j < PRIME_BYTES; j++) {
      p = (p << 8n) | BigInt(payload[4 + i * PRIME_BYTES + j]);
    }
    primes.push(p);
  }
  return primes;
}
