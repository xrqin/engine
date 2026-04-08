/**
 * Unified Policy Accumulator v6/v7
 *
 * Combines source primes AND module primes into a single accumulator:
 * AllowedAtoms = CleanSources ∪ AllowedModules
 * A_policy = g^{U_policy * q_epoch} mod N
 *
 * policy_epoch increments on:
 *   1. source blacklist (addSourceToBlacklist)
 *   2. module disallow (disallowModule)
 *   3. deny-set expansion (expandDenySet) — v7 addition
 */

import { modpow, hashToPrimeEpoch } from './di-hash';

export class PolicyAccumulator {
  private readonly N: bigint;
  private readonly g: bigint;
  private acc: bigint;
  private _policyEpoch: number;
  private _regSeq: number;
  private _qEpoch: bigint;
  private cleanSources: bigint[];
  private allowedModules: bigint[];
  private blacklistedSources: Set<string>;
  private disallowedModules: Set<string>;

  constructor(N: bigint, g: bigint, initialEpoch: number = 0) {
    this.N = N;
    this.g = g;
    this.cleanSources = [];
    this.allowedModules = [];
    this.blacklistedSources = new Set();
    this.disallowedModules = new Set();
    this._policyEpoch = initialEpoch;
    this._regSeq = 0;
    this._qEpoch = hashToPrimeEpoch(initialEpoch);
    this.acc = modpow(g, this._qEpoch, N);
  }

  get policyEpoch(): number { return this._policyEpoch; }
  get regSeq(): number { return this._regSeq; }
  get qEpoch(): bigint { return this._qEpoch; }
  get accumulator(): bigint { return this.acc; }

  /** Register a source prime. Only increments reg_seq. */
  registerSource(p: bigint): void {
    if (p <= 2n) throw new Error('Prime must be > 2');
    const key = p.toString();
    if (this.cleanSources.some(x => x === p)) throw new Error('Source already registered');
    if (this.blacklistedSources.has(key)) throw new Error('Source is blacklisted');
    this.cleanSources.push(p);
    this.cleanSources.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    this._regSeq += 1;
    this.recompute();
  }

  /** Register a module prime. Only increments reg_seq. */
  registerModule(p: bigint): void {
    if (p <= 2n) throw new Error('Prime must be > 2');
    const key = p.toString();
    if (this.allowedModules.some(x => x === p)) throw new Error('Module already registered');
    if (this.disallowedModules.has(key)) throw new Error('Module is disallowed');
    this.allowedModules.push(p);
    this.allowedModules.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    this._regSeq += 1;
    this.recompute();
  }

  /** Blacklist a source. Increments policy_epoch. */
  addSourceToBlacklist(p: bigint): void {
    const key = p.toString();
    const idx = this.cleanSources.findIndex(x => x === p);
    if (idx !== -1) this.cleanSources.splice(idx, 1);
    this.blacklistedSources.add(key);
    this._policyEpoch += 1;
    this._qEpoch = hashToPrimeEpoch(this._policyEpoch);
    this.recompute();
  }

  /** Disallow a module. Increments policy_epoch. */
  disallowModule(p: bigint): void {
    const key = p.toString();
    const idx = this.allowedModules.findIndex(x => x === p);
    if (idx !== -1) this.allowedModules.splice(idx, 1);
    this.disallowedModules.add(key);
    this._policyEpoch += 1;
    this._qEpoch = hashToPrimeEpoch(this._policyEpoch);
    this.recompute();
  }

  /**
   * Expand deny-set (v7 third policy_epoch trigger).
   * Removes multiple sources/modules from allowed sets in one batch.
   * Increments policy_epoch exactly once.
   * Spec: policy_epoch increments on source blacklist, module disallow, OR deny-set expansion.
   */
  expandDenySet(entries: Array<{ kind: 'source' | 'module'; prime: bigint }>): void {
    if (entries.length === 0) throw new Error('Deny-set expansion must have at least one entry');
    for (const entry of entries) {
      const key = entry.prime.toString();
      if (entry.kind === 'source') {
        const idx = this.cleanSources.findIndex(x => x === entry.prime);
        if (idx !== -1) this.cleanSources.splice(idx, 1);
        this.blacklistedSources.add(key);
      } else {
        const idx = this.allowedModules.findIndex(x => x === entry.prime);
        if (idx !== -1) this.allowedModules.splice(idx, 1);
        this.disallowedModules.add(key);
      }
    }
    this._policyEpoch += 1;
    this._qEpoch = hashToPrimeEpoch(this._policyEpoch);
    this.recompute();
  }

  /**
   * Generate base subset witness for a combined set of source + module primes.
   * C_mid_base = g^{complementProduct}
   */
  subsetWitnessBase(subset: bigint[]): bigint {
    const allAllowed = [...this.cleanSources, ...this.allowedModules];
    for (const p of subset) {
      if (!allAllowed.some(x => x === p)) {
        throw new Error(`Prime ${p} is not in allowed set`);
      }
    }
    const subsetSet = new Set(subset.map(p => p.toString()));
    let complementProduct = 1n;
    for (const p of allAllowed) {
      if (!subsetSet.has(p.toString())) complementProduct *= p;
    }
    return modpow(this.g, complementProduct, this.N);
  }

  /**
   * Verify subset: C_mid^{x(S) * q_epoch} === A_policy
   */
  verifySubset(subset: bigint[], cMid: bigint): boolean {
    if (cMid === 1n || cMid === this.N - 1n) return false;
    let subsetProduct = 1n;
    for (const p of subset) subsetProduct *= p;
    const exponent = subsetProduct * this._qEpoch;
    return modpow(cMid, exponent, this.N) === this.acc;
  }

  private recompute(): void {
    const allAllowed = [...this.cleanSources, ...this.allowedModules];
    let product = this._qEpoch;
    for (const p of allAllowed) product *= p;
    this.acc = modpow(this.g, product, this.N);
  }
}
