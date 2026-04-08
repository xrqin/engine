/**
 * v8.1 Source Descriptor — Unit Tests
 *
 * Tests the binary append-only frontier + bag folding descriptor.
 */

import chai from 'chai';
import { initPoseidonPromise } from '../../utils/poseidon';

import {
  buildSourceDescriptor,
  verifySourceDescriptor,
  emptyDescFrontier,
  appendLeafSrcDesc,
  finalizeSourceFrontier,
  leafHashSrc,
  nodeHashSrc,
  bagHashSrc,
  rootHashSrc,
} from '../source-descriptor';
import type { DescFrontier } from '../source-descriptor';

import { buildCanonicalSetTree } from '../canonical-set-tree';
import { comSrcV8, deriveRhoSrc, deriveRhoMod, noteComV5 } from '../commitments';
import type { NoteV5 } from '../commitments';
import { NOTE_VERSION_V5, D_DESC } from '../constants';

const { expect } = chai;

function makeSources(n: number): bigint[] {
  const sources: bigint[] = [];
  for (let i = 0; i < n; i++) {
    sources.push(BigInt(1000 + i * 7));
  }
  return sources;
}

describe('v8.1 Source Descriptor', function () {
  this.timeout(60_000);

  before(async () => {
    await initPoseidonPromise;
  });

  // =========================================================================
  // TD-01: Empty set descriptor
  // =========================================================================
  it('TD-01: empty set produces canonical descriptor', () => {
    const desc = buildSourceDescriptor([]);
    expect(desc.srcCount).to.equal(0);
    expect(desc.srcRoot).to.be.a('bigint');
    // Root should be RootHash(0, EMPTY_BAG=0)
    const expectedRoot = rootHashSrc(0, 0n);
    expect(desc.srcRoot).to.equal(expectedRoot);
  });

  // =========================================================================
  // TD-02: Single element
  // =========================================================================
  it('TD-02: single source produces count=1', () => {
    const desc = buildSourceDescriptor([42n]);
    expect(desc.srcCount).to.equal(1);
    // Verify via independent rebuild
    expect(verifySourceDescriptor(desc.srcRoot, desc.srcCount, [42n])).to.be.true;
    // Root must be deterministic
    const desc2 = buildSourceDescriptor([42n]);
    expect(desc.srcRoot).to.equal(desc2.srcRoot);
  });

  // =========================================================================
  // TD-03: Two elements — binary carry chain
  // =========================================================================
  it('TD-03: two sources — carry chain merges at level 1', () => {
    const s0 = 10n;
    const s1 = 20n;
    const desc = buildSourceDescriptor([s0, s1]);
    expect(desc.srcCount).to.equal(2);
    // Verify via rebuild
    expect(verifySourceDescriptor(desc.srcRoot, desc.srcCount, [s0, s1])).to.be.true;
    // Different pair → different root
    const desc2 = buildSourceDescriptor([s0, 30n]);
    expect(desc.srcRoot).to.not.equal(desc2.srcRoot);
  });

  // =========================================================================
  // TD-04: 8 sources
  // =========================================================================
  it('TD-04: 8 sources produces consistent descriptor', () => {
    const sources = makeSources(8);
    const desc = buildSourceDescriptor(sources);
    expect(desc.srcCount).to.equal(8);
    expect(verifySourceDescriptor(desc.srcRoot, desc.srcCount, sources)).to.be.true;
  });

  // =========================================================================
  // TD-05: 64 sources
  // =========================================================================
  it('TD-05: 64 sources descriptor consistency', () => {
    const sources = makeSources(64);
    const desc = buildSourceDescriptor(sources);
    expect(desc.srcCount).to.equal(64);
    expect(verifySourceDescriptor(desc.srcRoot, desc.srcCount, sources)).to.be.true;
  });

  // =========================================================================
  // TD-06: 256 sources
  // =========================================================================
  it('TD-06: 256 sources descriptor consistency', () => {
    const sources = makeSources(256);
    const desc = buildSourceDescriptor(sources);
    expect(desc.srcCount).to.equal(256);
    expect(verifySourceDescriptor(desc.srcRoot, desc.srcCount, sources)).to.be.true;
  });

  // =========================================================================
  // TD-07: 1024 sources (MAX_SRC_COUNT)
  // =========================================================================
  it('TD-07: 1024 sources descriptor consistency', () => {
    const sources = makeSources(1024);
    const desc = buildSourceDescriptor(sources);
    expect(desc.srcCount).to.equal(1024);
    expect(verifySourceDescriptor(desc.srcRoot, desc.srcCount, sources)).to.be.true;
  });

  // =========================================================================
  // TD-08: Determinism — same list always produces same descriptor
  // =========================================================================
  it('TD-08: determinism — same list gives same descriptor', () => {
    const sources = makeSources(16);
    const d1 = buildSourceDescriptor(sources);
    const d2 = buildSourceDescriptor([...sources]);
    expect(d1.srcRoot).to.equal(d2.srcRoot);
    expect(d1.srcCount).to.equal(d2.srcCount);
  });

  // =========================================================================
  // TD-09: Different lists produce different descriptors
  // =========================================================================
  it('TD-09: different lists produce different roots', () => {
    const s1 = makeSources(8);
    const s2 = makeSources(9);
    const d1 = buildSourceDescriptor(s1);
    const d2 = buildSourceDescriptor(s2);
    // Different count guarantees different root (count is in RootHash)
    expect(d1.srcRoot).to.not.equal(d2.srcRoot);
  });

  // =========================================================================
  // TD-10: Non-sorted input rejects
  // =========================================================================
  it('TD-10: non-sorted input throws', () => {
    expect(() => buildSourceDescriptor([20n, 10n])).to.throw('strictly increasing');
  });

  // =========================================================================
  // TD-11: Duplicate input rejects
  // =========================================================================
  it('TD-11: duplicate input throws', () => {
    expect(() => buildSourceDescriptor([10n, 10n])).to.throw('strictly increasing');
  });

  // =========================================================================
  // TD-12: verify rejects wrong count
  // =========================================================================
  it('TD-12: verifySourceDescriptor rejects wrong count', () => {
    const sources = makeSources(4);
    const desc = buildSourceDescriptor(sources);
    expect(verifySourceDescriptor(desc.srcRoot, 5, sources)).to.be.false;
  });

  // =========================================================================
  // TD-13: verify rejects wrong root
  // =========================================================================
  it('TD-13: verifySourceDescriptor rejects wrong root', () => {
    const sources = makeSources(4);
    const desc = buildSourceDescriptor(sources);
    expect(verifySourceDescriptor(desc.srcRoot + 1n, desc.srcCount, sources)).to.be.false;
  });

  // =========================================================================
  // TD-14: Incompatibility with old B=4 tree
  // =========================================================================
  it('TD-14: v8.1 descriptor differs from v7 B=4 tree', () => {
    const primes = makeSources(4);
    const v7Tree = buildCanonicalSetTree('src', primes);
    const v8Desc = buildSourceDescriptor(primes);

    // Same count, but root MUST differ
    expect(v7Tree.count).to.equal(v8Desc.srcCount);
    expect(v7Tree.root).to.not.equal(v8Desc.srcRoot);
  });

  // =========================================================================
  // TD-15: Incremental append equals batch build
  // =========================================================================
  it('TD-15: incremental append equals batch build', () => {
    const sources = makeSources(13); // non-power-of-2
    const batchDesc = buildSourceDescriptor(sources);

    const frontier = emptyDescFrontier();
    for (const s of sources) {
      appendLeafSrcDesc(frontier, s);
    }
    const incrDesc = finalizeSourceFrontier(frontier);

    expect(incrDesc.srcRoot).to.equal(batchDesc.srcRoot);
    expect(incrDesc.srcCount).to.equal(batchDesc.srcCount);
  });

  // =========================================================================
  // TD-16: Power-of-2 sizes (clean binary trees)
  // =========================================================================
  for (const n of [1, 2, 4, 8, 16, 32]) {
    it(`TD-16-${n}: power-of-2 size ${n} is consistent`, () => {
      const sources = makeSources(n);
      const desc = buildSourceDescriptor(sources);
      expect(desc.srcCount).to.equal(n);
      expect(verifySourceDescriptor(desc.srcRoot, desc.srcCount, sources)).to.be.true;
    });
  }

  // =========================================================================
  // TD-17: Non-power-of-2 sizes (bag folding with multiple subtrees)
  // =========================================================================
  for (const n of [3, 5, 7, 10, 15, 33, 100]) {
    it(`TD-17-${n}: non-power-of-2 size ${n} is consistent`, () => {
      const sources = makeSources(n);
      const desc = buildSourceDescriptor(sources);
      expect(desc.srcCount).to.equal(n);
      expect(verifySourceDescriptor(desc.srcRoot, desc.srcCount, sources)).to.be.true;
    });
  }

  // =========================================================================
  // TD-20: NoteV5 commitment + deterministic rho derivation
  // =========================================================================
  it('TD-20: NoteV5 commitment with derived rho_src', () => {
    const rhoValue = 12345n;
    const ownerPubkey = 67890n;
    const outputIndex = 0;

    const rhoSrc = deriveRhoSrc(rhoValue, ownerPubkey, outputIndex);
    const rhoMod = deriveRhoMod(rhoValue, ownerPubkey, outputIndex);

    expect(rhoSrc).to.be.a('bigint');
    expect(rhoMod).to.be.a('bigint');
    expect(rhoSrc).to.not.equal(rhoMod); // different DSTs → different values

    // Com_src with derived rho
    const sources = makeSources(4);
    const desc = buildSourceDescriptor(sources);
    const srcCommitment = comSrcV8(desc.srcRoot, desc.srcCount, rhoSrc);
    expect(srcCommitment).to.be.a('bigint');

    // NoteV5 commitment
    const note: NoteV5 = {
      value: 1000n,
      tokenHash: 2000n,
      ownerPubkey,
      rhoValue,
      sourceCommitment: srcCommitment,
      moduleCommitment: 0n,
      cleanEpoch: 1n,
    };
    const noteCom = noteComV5(note);
    expect(noteCom).to.be.a('bigint');

    // Determinism
    expect(noteComV5(note)).to.equal(noteCom);
  });

  // =========================================================================
  // TD-21: DeriveRhoSrc determinism
  // =========================================================================
  it('TD-21: DeriveRhoSrc is deterministic', () => {
    const r1 = deriveRhoSrc(100n, 200n, 0);
    const r2 = deriveRhoSrc(100n, 200n, 0);
    expect(r1).to.equal(r2);

    // Different output index → different rho
    const r3 = deriveRhoSrc(100n, 200n, 1);
    expect(r1).to.not.equal(r3);
  });
});
