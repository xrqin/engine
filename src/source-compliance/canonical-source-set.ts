/**
 * CanonicalSourceSet
 *
 * Represents a sorted, unique set of prime numbers used as source identifiers
 * in the RAILGUN Source Compliance protocol.
 *
 * Invariants:
 * - All elements are odd primes > 2
 * - Elements are strictly increasing (sorted, no duplicates)
 * - All elements pass Miller-Rabin primality test
 */

import { isPrime } from './di-hash';

export class CanonicalSourceSet {
  private readonly _primes: bigint[];

  /**
   * Create a CanonicalSourceSet from a list of primes.
   * Validates PrimeListValid: strictly increasing, all odd, all > 2, all prime.
   * @throws Error if validation fails
   */
  constructor(primes: bigint[]) {
    this._primes = [...primes]; // defensive copy
    if (!this.isValid()) {
      throw new Error('CanonicalSourceSet: PrimeListValid check failed');
    }
  }

  /**
   * Create a singleton source set containing a single prime.
   */
  static singleton(p: bigint): CanonicalSourceSet {
    return new CanonicalSourceSet([p]);
  }

  /**
   * Compute the canonical union of multiple source sets.
   * Uses linear merge of sorted arrays (NOT concat-then-sort).
   *
   * For two sets: standard sorted-merge with dedup.
   * For N sets: iterative pairwise merge.
   */
  static canonicalUnion(sets: CanonicalSourceSet[]): CanonicalSourceSet {
    if (sets.length === 0) {
      return new CanonicalSourceSet([]);
    }
    if (sets.length === 1) {
      return new CanonicalSourceSet([...sets[0]._primes]);
    }

    let result = sets[0]._primes;
    for (let i = 1; i < sets.length; i++) {
      result = mergeSorted(result, sets[i]._primes);
    }

    return new CanonicalSourceSet(result);
  }

  /**
   * Number of primes in the set.
   */
  get size(): number {
    return this._primes.length;
  }

  /**
   * Read-only access to the prime list.
   */
  get primes(): readonly bigint[] {
    return this._primes;
  }

  /**
   * Validate PrimeListValid:
   * - Strictly increasing
   * - All odd
   * - All > 2
   * - All pass Miller-Rabin with 20 witnesses
   */
  isValid(): boolean {
    if (this._primes.length === 0) return true;

    for (let i = 0; i < this._primes.length; i++) {
      const p = this._primes[i];

      // Must be > 2 and odd
      if (p <= 2n) return false;
      if (p % 2n === 0n) return false;

      // Must be strictly increasing
      if (i > 0 && p <= this._primes[i - 1]) return false;

      // Must pass Miller-Rabin
      if (!isPrime(p, 20)) return false;
    }

    return true;
  }

  /**
   * Check if a prime is contained in the set.
   * Uses binary search since the list is sorted.
   */
  contains(p: bigint): boolean {
    let lo = 0;
    let hi = this._primes.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      if (this._primes[mid] === p) return true;
      if (this._primes[mid] < p) lo = mid + 1;
      else hi = mid - 1;
    }
    return false;
  }

  /**
   * Encode the set as Enc_set(S) = (m, p_0, ..., p_{m-1}) in big-endian bytes.
   *
   * Format:
   * - First 4 bytes: m (set size) as uint32 big-endian
   * - Then for each prime: PRIME_BYTE_WIDTH bytes big-endian
   *
   * PRIME_BYTE_WIDTH = 48 (384 bits), large enough for all four prime domains:
   *   P_src=256bit, P_mod=288bit, P_epoch=320bit, P_alias=384bit
   */
  encode(): Uint8Array {
    const m = this._primes.length;
    const buf = new Uint8Array(4 + m * PRIME_BYTE_WIDTH);

    // Write m as 4-byte big-endian
    buf[0] = (m >> 24) & 0xff;
    buf[1] = (m >> 16) & 0xff;
    buf[2] = (m >> 8) & 0xff;
    buf[3] = m & 0xff;

    // Write each prime as PRIME_BYTE_WIDTH-byte big-endian
    for (let i = 0; i < m; i++) {
      const primeBytes = bigintToFixedBytes(this._primes[i], PRIME_BYTE_WIDTH);
      buf.set(primeBytes, 4 + i * PRIME_BYTE_WIDTH);
    }

    return buf;
  }

  /**
   * Compute the squarefree product of all primes in the set.
   * Used for RSA accumulator operations (burn/verify only).
   *
   * WARNING: This can be very large for large sets.
   */
  squarefreeProduct(): bigint {
    if (this._primes.length === 0) return 1n;
    let product = 1n;
    for (const p of this._primes) {
      product *= p;
    }
    return product;
  }
}

/**
 * Linear merge of two sorted bigint arrays, producing a sorted unique result.
 */
function mergeSorted(a: bigint[], b: bigint[]): bigint[] {
  const result: bigint[] = [];
  let i = 0;
  let j = 0;

  while (i < a.length && j < b.length) {
    if (a[i] < b[j]) {
      result.push(a[i]);
      i++;
    } else if (a[i] > b[j]) {
      result.push(b[j]);
      j++;
    } else {
      // Equal: dedup
      result.push(a[i]);
      i++;
      j++;
    }
  }

  // Append remaining
  while (i < a.length) {
    result.push(a[i]);
    i++;
  }
  while (j < b.length) {
    result.push(b[j]);
    j++;
  }

  return result;
}

/**
 * Fixed width for encoding primes in Enc_set.
 * 48 bytes (384 bits) accommodates all four prime domains:
 * P_src=256, P_mod=288, P_epoch=320, P_alias=384.
 */
const PRIME_BYTE_WIDTH = 48;

/**
 * Convert a bigint to a fixed-width big-endian Uint8Array.
 * Pads with leading zeros; throws if value exceeds width.
 */
function bigintToFixedBytes(n: bigint, width: number): Uint8Array {
  const bytes = new Uint8Array(width);
  let val = n;
  for (let i = width - 1; i >= 0; i--) {
    bytes[i] = Number(val & 0xffn);
    val >>= 8n;
  }
  if (val > 0n) {
    throw new Error(`Prime too large for ${width}-byte encoding`);
  }
  return bytes;
}
