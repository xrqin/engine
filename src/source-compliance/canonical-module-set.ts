/**
 * CanonicalModuleSet
 *
 * Represents a sorted, unique set of prime numbers used as module identifiers
 * in the RAILGUN Source Compliance protocol.
 *
 * Shares the same invariants as CanonicalSourceSet but operates in the P_mod domain (288-bit).
 * In v7, these sets serve as input to CanonicalSetTree (not flat SetDigest).
 */

import { isPrime } from './di-hash';

export class CanonicalModuleSet {
  private readonly _primes: bigint[];

  constructor(primes: bigint[]) {
    this._primes = [...primes];
    if (!this.isValid()) {
      throw new Error('CanonicalModuleSet: PrimeListValid check failed');
    }
  }

  static singleton(p: bigint): CanonicalModuleSet {
    return new CanonicalModuleSet([p]);
  }

  static empty(): CanonicalModuleSet {
    return new CanonicalModuleSet([]);
  }

  static canonicalUnion(sets: CanonicalModuleSet[]): CanonicalModuleSet {
    if (sets.length === 0) {
      return new CanonicalModuleSet([]);
    }
    if (sets.length === 1) {
      return new CanonicalModuleSet([...sets[0]._primes]);
    }

    let result = sets[0]._primes;
    for (let i = 1; i < sets.length; i++) {
      result = mergeSorted(result, sets[i]._primes);
    }

    return new CanonicalModuleSet(result);
  }

  get size(): number {
    return this._primes.length;
  }

  get primes(): readonly bigint[] {
    return this._primes;
  }

  isValid(): boolean {
    if (this._primes.length === 0) return true;

    for (let i = 0; i < this._primes.length; i++) {
      const p = this._primes[i];
      if (p <= 2n) return false;
      if (p % 2n === 0n) return false;
      if (i > 0 && p <= this._primes[i - 1]) return false;
      if (!isPrime(p, 20)) return false;
    }

    return true;
  }

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

  squarefreeProduct(): bigint {
    if (this._primes.length === 0) return 1n;
    let product = 1n;
    for (const p of this._primes) {
      product *= p;
    }
    return product;
  }
}

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
      result.push(a[i]);
      i++;
      j++;
    }
  }

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
