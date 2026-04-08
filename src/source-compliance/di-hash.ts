/**
 * DI-Hash: Domain-separated Hash-to-Prime (v6)
 *
 * Four disjoint prime domains:
 * - P_src:   256-bit primes (source primes)
 * - P_mod:   288-bit primes (module primes) — NEW in v6
 * - P_epoch: 320-bit primes (epoch randomizer)
 * - P_alias: 384-bit primes (alias randomizer)
 */

import { createHash } from 'crypto';
import {
  PRIME_BITS_SRC,
  PRIME_BITS_MOD,
  PRIME_BITS_EPOCH,
  PRIME_BITS_ALIAS,
  DST_SRC_PRIME_V6,
  DST_MOD_PRIME_V1,
  DST_EPOCH_PRIME_V6,
} from './constants';

const DST_ALIAS_PRIME_SAMPLE = 'RAILGUN_SOURCE_ALIAS_PRIME_SAMPLE';

export function modpow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod === 1n) return 0n;
  base = ((base % mod) + mod) % mod;
  let result = 1n;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

export function isPrime(n: bigint, witnesses: number = 20): boolean {
  if (n < 2n) return false;
  if (n === 2n || n === 3n) return true;
  if (n % 2n === 0n) return false;
  if (n < 9n) return true;
  let d = n - 1n;
  let r = 0;
  while (d % 2n === 0n) { d >>= 1n; r += 1; }
  const testBases = getWitnesses(n, witnesses);
  for (const a of testBases) {
    if (a <= 1n || a >= n - 1n) continue;
    let x = modpow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    let composite = true;
    for (let i = 0; i < r - 1; i++) {
      x = modpow(x, 2n, n);
      if (x === n - 1n) { composite = false; break; }
    }
    if (composite) return false;
  }
  return true;
}

function getWitnesses(n: bigint, count: number): bigint[] {
  const witnesses: bigint[] = [];
  const smallPrimes = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n];
  for (const p of smallPrimes) {
    if (p < n - 1n) witnesses.push(p);
    if (witnesses.length >= count) return witnesses;
  }
  let seed = n;
  while (witnesses.length < count) {
    const hash = createHash('sha256');
    hash.update(bigintToBytes(seed));
    const witness = (bytesToBigint(hash.digest()) % (n - 3n)) + 2n;
    if (witness > 1n && witness < n - 1n) witnesses.push(witness);
    seed += 1n;
  }
  return witnesses;
}

function bigintToBytes(n: bigint): Buffer {
  if (n === 0n) return Buffer.from([0]);
  let hex = n.toString(16);
  if (hex.length % 2 !== 0) hex = '0' + hex;
  return Buffer.from(hex, 'hex');
}

function bytesToBigint(buf: Buffer): bigint {
  if (buf.length === 0) return 0n;
  return BigInt('0x' + buf.toString('hex'));
}

function hashToPrime(dst: string, input: Uint8Array, targetBits: number): bigint {
  const hash = createHash('sha256');
  hash.update(Buffer.from(dst, 'utf-8'));
  hash.update(input);
  let digest = hash.digest();
  while (digest.length * 8 < targetBits) {
    const ext = createHash('sha256');
    ext.update(digest);
    ext.update(Buffer.from([digest.length & 0xff]));
    digest = Buffer.concat([digest, ext.digest()]);
  }
  const targetBytes = Math.ceil(targetBits / 8);
  let candidate = bytesToBigint(digest.subarray(0, targetBytes));
  const mask = (1n << BigInt(targetBits)) - 1n;
  const topBit = 1n << BigInt(targetBits - 1);
  candidate = (candidate & mask) | topBit;
  if (candidate % 2n === 0n) candidate += 1n;
  while (!isPrime(candidate)) candidate += 2n;
  return candidate;
}

/** P_src domain: 256-bit source primes */
export function hashToPrimeSrc(sigma: Uint8Array): bigint {
  return hashToPrime(DST_SRC_PRIME_V6, sigma, PRIME_BITS_SRC);
}

/** P_mod domain: 288-bit module primes — NEW in v6 */
export function hashToPrimeMod(moduleLocator: Uint8Array): bigint {
  return hashToPrime(DST_MOD_PRIME_V1, moduleLocator, PRIME_BITS_MOD);
}

/** P_epoch domain: 320-bit epoch primes */
export function hashToPrimeEpoch(policyEpoch: number): bigint {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(policyEpoch));
  return hashToPrime(DST_EPOCH_PRIME_V6, buf, PRIME_BITS_EPOCH);
}

/** P_alias domain: 384-bit alias primes */
export function sampleAliasPrime(seed: Uint8Array): bigint {
  return hashToPrime(DST_ALIAS_PRIME_SAMPLE, seed, PRIME_BITS_ALIAS);
}

/** Legacy alias */
export function diHash(input: Uint8Array): bigint {
  return hashToPrimeSrc(input);
}
