import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
import { initPoseidonPromise } from '../../utils/poseidon';
import { CanonicalSourceSet } from '../canonical-source-set';
import { isPrime, hashToPrimeSrc, hashToPrimeMod, hashToPrimeEpoch, sampleAliasPrime } from '../di-hash';
import { setDigestSrc, setDigestMod } from '../set-digest';
import { comSrcset, comModset, commitVec } from '../commitments';
import { PolicyAccumulator } from '../clean-accumulator';
import { createAlias, liftWitness, verifyAliasSubset } from '../alias';
import {
  DualLineage,
  generateShieldV3,
  generateTransferV3Fast, verifyTransferV3Fast,
  generateTransferV3Refresh, verifyTransferV3Refresh,
  generateUnshieldV3, verifyUnshieldV3,
  generateTypedCallExact, generateTypedCallBoundary,
} from '../v6-proof';
import { RSA_N, NOTE_VERSION_V3 } from '../constants';

chai.use(chaiAsPromised);
const { expect } = chai;
const N = RSA_N;
const G = 65537n;

describe('Source Compliance v6 (dual lineage: SrcSet + ModSet)', function () {
  this.timeout(120_000);

  before(async () => { await initPoseidonPromise; });

  it('NOTE_VERSION_V3 = 0x3', () => { expect(NOTE_VERSION_V3).to.equal(0x3); });

  // ============================================================
  // Four-domain prime separation
  // ============================================================
  describe('Four prime domains', () => {
    it('P_src (256-bit), P_mod (288-bit), P_epoch (320-bit), P_alias (384-bit) are disjoint', () => {
      const pSrc = hashToPrimeSrc(new TextEncoder().encode('src'));
      const pMod = hashToPrimeMod(new TextEncoder().encode('mod'));
      const pEpoch = hashToPrimeEpoch(0);
      const pAlias = sampleAliasPrime(new TextEncoder().encode('alias'));

      expect(pSrc < (1n << 260n)).to.be.true;  // P_src < 260 bits
      expect(pMod >= (1n << 287n)).to.be.true;  // P_mod >= 287 bits
      expect(pMod < (1n << 292n)).to.be.true;   // P_mod < 292 bits
      expect(pEpoch >= (1n << 319n)).to.be.true; // P_epoch >= 319 bits
      expect(pAlias >= (1n << 383n)).to.be.true; // P_alias >= 383 bits

      // All primes
      expect(isPrime(pSrc)).to.be.true;
      expect(isPrime(pMod)).to.be.true;
      expect(isPrime(pEpoch)).to.be.true;
      expect(isPrime(pAlias)).to.be.true;
    });

    it('hashToPrimeMod is deterministic', () => {
      const input = new TextEncoder().encode('uniswap_eth_usdc');
      expect(hashToPrimeMod(input)).to.equal(hashToPrimeMod(input));
    });
  });

  // ============================================================
  // Dual digests and commitments
  // ============================================================
  describe('Dual digests and commitments', () => {
    it('SetDigestSrc != SetDigestMod for same set (different DST)', () => {
      const set = new CanonicalSourceSet([3n, 7n, 11n]);
      expect(setDigestSrc(set)).to.not.equal(setDigestMod(set));
    });

    it('comSrcset != comModset for same digest (different DST)', () => {
      expect(comSrcset(123n, 42n)).to.not.equal(comModset(123n, 42n));
    });

    it('commitVec is length-binding', () => {
      expect(commitVec([3n, 7n], 42n)).to.not.equal(commitVec([3n, 7n, 11n], 42n));
    });
  });

  // ============================================================
  // Unified Policy Accumulator
  // ============================================================
  describe('PolicyAccumulator (unified)', () => {
    let acc: PolicyAccumulator;
    beforeEach(() => { acc = new PolicyAccumulator(N, G, 0); });

    it('registerSource increments reg_seq not policy_epoch', () => {
      acc.registerSource(3n);
      expect(acc.regSeq).to.equal(1);
      expect(acc.policyEpoch).to.equal(0);
    });

    it('registerModule increments reg_seq not policy_epoch', () => {
      acc.registerModule(hashToPrimeMod(new TextEncoder().encode('mod1')));
      expect(acc.regSeq).to.equal(1);
      expect(acc.policyEpoch).to.equal(0);
    });

    it('addSourceToBlacklist increments policy_epoch', () => {
      acc.registerSource(3n);
      acc.addSourceToBlacklist(3n);
      expect(acc.policyEpoch).to.equal(1);
    });

    it('disallowModule increments policy_epoch', () => {
      const pMod = hashToPrimeMod(new TextEncoder().encode('mod1'));
      acc.registerModule(pMod);
      acc.disallowModule(pMod);
      expect(acc.policyEpoch).to.equal(1);
    });

    it('combined subset proof: source + module primes', () => {
      const pMod = hashToPrimeMod(new TextEncoder().encode('swap'));
      acc.registerSource(3n);
      acc.registerSource(5n);
      acc.registerModule(pMod);

      // Subset of source+module
      const subset = [3n, pMod];
      const cMidBase = acc.subsetWitnessBase(subset);
      expect(acc.verifySubset(subset, cMidBase)).to.be.true;
    });

    it('subset fails after source blacklist', () => {
      acc.registerSource(3n);
      acc.registerSource(5n);
      const cMidBase = acc.subsetWitnessBase([3n, 5n]);
      acc.addSourceToBlacklist(3n);
      expect(acc.verifySubset([3n, 5n], cMidBase)).to.be.false;
    });

    it('subset fails after module disallow', () => {
      const pMod = hashToPrimeMod(new TextEncoder().encode('m'));
      acc.registerSource(3n);
      acc.registerModule(pMod);
      const cMidBase = acc.subsetWitnessBase([3n, pMod]);
      acc.disallowModule(pMod);
      expect(acc.verifySubset([3n, pMod], cMidBase)).to.be.false;
    });
  });

  // ============================================================
  // ShieldV3
  // ============================================================
  describe('ShieldV3', () => {
    it('creates singleton SrcSet and empty ModSet', () => {
      const result = generateShieldV3(3n, 42n, 99n, 0);
      expect(result.cleanEpoch).to.equal(0);
      expect(result.srcCommitment > 0n).to.be.true;
      expect(result.modCommitment > 0n).to.be.true;
      // Same shield with same params -> same commitments
      const result2 = generateShieldV3(3n, 42n, 99n, 0);
      expect(result.srcCommitment).to.equal(result2.srcCommitment);
    });
  });

  // ============================================================
  // TransferV3 Fast
  // ============================================================
  describe('TransferV3 Fast', () => {
    it('exact union of both SrcSet and ModSet', () => {
      const pMod = hashToPrimeMod(new TextEncoder().encode('swap'));
      const l1: DualLineage = { srcSet: new CanonicalSourceSet([3n, 7n]), modSet: new CanonicalSourceSet([]) };
      const l2: DualLineage = { srcSet: new CanonicalSourceSet([5n]), modSet: new CanonicalSourceSet([pMod]) };
      const result = generateTransferV3Fast([l1, l2], [0, 0], 0, 42n, 99n);
      expect(result.outputCleanEpoch).to.equal(0);
      expect(verifyTransferV3Fast(result, [l1, l2], 0)).to.be.true;
    });

    it('fails when input is stale', () => {
      const l1: DualLineage = { srcSet: new CanonicalSourceSet([3n]), modSet: new CanonicalSourceSet([]) };
      expect(() => generateTransferV3Fast([l1], [0], 1, 42n, 99n)).to.throw('stale');
    });
  });

  // ============================================================
  // TransferV3 Refresh
  // ============================================================
  describe('TransferV3 Refresh', () => {
    it('generates valid dual refresh proof', () => {
      const pMod = hashToPrimeMod(new TextEncoder().encode('swap'));
      const acc = new PolicyAccumulator(N, G, 0);
      acc.registerSource(3n);
      acc.registerSource(5n);
      acc.registerModule(pMod);

      const l1: DualLineage = { srcSet: new CanonicalSourceSet([3n, 5n]), modSet: new CanonicalSourceSet([pMod]) };
      const qa = sampleAliasPrime(new TextEncoder().encode('refresh'));
      const proof = generateTransferV3Refresh([l1], 42n, 99n, 11n, 22n, acc, qa, N);
      expect(proof.outputCleanEpoch).to.equal(0);
      expect(verifyTransferV3Refresh(proof, [l1], acc, N)).to.be.true;
    });
  });

  // ============================================================
  // UnshieldV3
  // ============================================================
  describe('UnshieldV3', () => {
    it('dual subset proof passes for clean lineage', () => {
      const pMod = hashToPrimeMod(new TextEncoder().encode('vault'));
      const acc = new PolicyAccumulator(N, G, 0);
      acc.registerSource(3n);
      acc.registerModule(pMod);

      const lineage: DualLineage = { srcSet: new CanonicalSourceSet([3n]), modSet: new CanonicalSourceSet([pMod]) };
      const qa = sampleAliasPrime(new TextEncoder().encode('unshield'));
      const proof = generateUnshieldV3(lineage, 42n, 99n, 11n, 22n, acc, qa, N);
      expect(verifyUnshieldV3(proof, lineage, acc, N)).to.be.true;
    });

    it('fails after source blacklist', () => {
      const acc = new PolicyAccumulator(N, G, 0);
      acc.registerSource(3n);
      acc.registerSource(5n);
      const lineage: DualLineage = { srcSet: new CanonicalSourceSet([3n]), modSet: new CanonicalSourceSet([]) };
      const qa = sampleAliasPrime(new TextEncoder().encode('u'));
      const proof = generateUnshieldV3(lineage, 42n, 99n, 11n, 22n, acc, qa, N);
      expect(verifyUnshieldV3(proof, lineage, acc, N)).to.be.true;

      acc.addSourceToBlacklist(3n);
      expect(verifyUnshieldV3(proof, lineage, acc, N)).to.be.false;
    });

    it('fails after module disallow', () => {
      const pMod = hashToPrimeMod(new TextEncoder().encode('m'));
      const acc = new PolicyAccumulator(N, G, 0);
      acc.registerSource(3n);
      acc.registerModule(pMod);
      const lineage: DualLineage = { srcSet: new CanonicalSourceSet([3n]), modSet: new CanonicalSourceSet([pMod]) };
      const qa = sampleAliasPrime(new TextEncoder().encode('u'));
      const proof = generateUnshieldV3(lineage, 42n, 99n, 11n, 22n, acc, qa, N);
      expect(verifyUnshieldV3(proof, lineage, acc, N)).to.be.true;

      acc.disallowModule(pMod);
      expect(verifyUnshieldV3(proof, lineage, acc, N)).to.be.false;
    });
  });

  // ============================================================
  // TypedCallV1 — Exact vs Boundary
  // ============================================================
  describe('TypedCallV1', () => {
    it('Exact Module: ModSet unchanged', () => {
      const pMod = hashToPrimeMod(new TextEncoder().encode('swap'));
      const l1: DualLineage = { srcSet: new CanonicalSourceSet([3n]), modSet: new CanonicalSourceSet([pMod]) };
      const result = generateTypedCallExact([l1], 0, 42n, 99n);
      expect(result.moduleType).to.equal('exact');
      // ModSet should be same as input
      const expectedModDigest = setDigestMod(new CanonicalSourceSet([pMod]));
      expect(result.outputModDigest).to.equal(expectedModDigest);
    });

    it('Boundary Module: ModSet += boundary tags', () => {
      const pMod1 = hashToPrimeMod(new TextEncoder().encode('existing'));
      const pModSwap = hashToPrimeMod(new TextEncoder().encode('uniswap_eth_usdc'));
      const l1: DualLineage = { srcSet: new CanonicalSourceSet([3n]), modSet: new CanonicalSourceSet([pMod1]) };
      const result = generateTypedCallBoundary([l1], [pModSwap], 0, 42n, 99n);
      expect(result.moduleType).to.equal('boundary');
      // ModSet should be {pMod1, pModSwap}
      const expectedModSet = CanonicalSourceSet.canonicalUnion([
        new CanonicalSourceSet([pMod1]),
        new CanonicalSourceSet([pModSwap]),
      ]);
      expect(result.outputModDigest).to.equal(setDigestMod(expectedModSet));
    });

    it('Boundary Module: SrcSet always exact union (preserved)', () => {
      const pModSwap = hashToPrimeMod(new TextEncoder().encode('swap'));
      const l1: DualLineage = { srcSet: new CanonicalSourceSet([3n, 7n]), modSet: new CanonicalSourceSet([]) };
      const result = generateTypedCallBoundary([l1], [pModSwap], 0, 42n, 99n);
      // SrcSet should be unchanged
      const expectedSrcDigest = setDigestSrc(new CanonicalSourceSet([3n, 7n]));
      expect(result.outputSrcDigest).to.equal(expectedSrcDigest);
    });
  });

  // ============================================================
  // Integration: Full v6 lifecycle
  // ============================================================
  describe('Integration', () => {
    it('Shield -> Transfer -> Swap (boundary) -> Unshield', () => {
      const pModSwap = hashToPrimeMod(new TextEncoder().encode('uniswap'));
      const acc = new PolicyAccumulator(N, G, 0);
      acc.registerSource(3n);
      acc.registerModule(pModSwap);

      // 1. Shield
      const shield = generateShieldV3(3n, 42n, 99n, 0);
      expect(shield.cleanEpoch).to.equal(0);

      // 2. Transfer fast (same bucket)
      const l1: DualLineage = { srcSet: CanonicalSourceSet.singleton(3n), modSet: new CanonicalSourceSet([]) };
      const transfer = generateTransferV3Fast([l1], [0], 0, 100n, 200n);
      expect(verifyTransferV3Fast(transfer, [l1], 0)).to.be.true;

      // 3. TypedCallV1 Boundary (swap)
      const swapResult = generateTypedCallBoundary([l1], [pModSwap], 0, 300n, 400n);
      expect(swapResult.moduleType).to.equal('boundary');

      // 4. Unshield with ModSet={pModSwap}
      const postSwapLineage: DualLineage = {
        srcSet: CanonicalSourceSet.singleton(3n),
        modSet: new CanonicalSourceSet([pModSwap]),
      };
      const qa = sampleAliasPrime(new TextEncoder().encode('unshield'));
      const unshield = generateUnshieldV3(postSwapLineage, 500n, 600n, 700n, 800n, acc, qa, N);
      expect(verifyUnshieldV3(unshield, postSwapLineage, acc, N)).to.be.true;
    });

    it('Dual containment: source blacklist blocks, module disallow blocks independently', () => {
      const pModSwap = hashToPrimeMod(new TextEncoder().encode('swap'));
      const acc = new PolicyAccumulator(N, G, 0);
      acc.registerSource(3n);
      acc.registerSource(5n);
      acc.registerModule(pModSwap);

      // Note with source {3} and module {pModSwap}
      const lineage: DualLineage = {
        srcSet: CanonicalSourceSet.singleton(3n),
        modSet: new CanonicalSourceSet([pModSwap]),
      };

      // Before any policy change: unshield works
      let qa = sampleAliasPrime(new TextEncoder().encode('a'));
      let proof = generateUnshieldV3(lineage, 42n, 99n, 11n, 22n, acc, qa, N);
      expect(verifyUnshieldV3(proof, lineage, acc, N)).to.be.true;

      // Blacklist source 3 -> blocks even though module is fine
      acc.addSourceToBlacklist(3n);
      expect(() => {
        acc.subsetWitnessBase([3n, pModSwap]);
      }).to.throw('not in allowed set');

      // Note with source {5} and module {pModSwap} still works
      const cleanLineage: DualLineage = {
        srcSet: CanonicalSourceSet.singleton(5n),
        modSet: new CanonicalSourceSet([pModSwap]),
      };
      qa = sampleAliasPrime(new TextEncoder().encode('b'));
      proof = generateUnshieldV3(cleanLineage, 42n, 99n, 11n, 22n, acc, qa, N);
      expect(verifyUnshieldV3(proof, cleanLineage, acc, N)).to.be.true;

      // Now disallow module -> blocks even clean source
      acc.disallowModule(pModSwap);
      expect(() => {
        acc.subsetWitnessBase([5n, pModSwap]);
      }).to.throw('not in allowed set');

      // Note with source {5} and NO module still works
      const noModLineage: DualLineage = {
        srcSet: CanonicalSourceSet.singleton(5n),
        modSet: new CanonicalSourceSet([]),
      };
      qa = sampleAliasPrime(new TextEncoder().encode('c'));
      proof = generateUnshieldV3(noModLineage, 42n, 99n, 11n, 22n, acc, qa, N);
      expect(verifyUnshieldV3(proof, noModLineage, acc, N)).to.be.true;
    });
  });
});
