import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
import { initPoseidonPromise } from '../../utils/poseidon';
import { CanonicalSourceSet } from '../canonical-source-set';
import { diHash, hashToPrimeMod, sampleAliasPrime } from '../di-hash';
import { setDigestSrc, setDigestMod } from '../set-digest';
import { comSrcset, comModset, commitVec } from '../commitments';
import { PolicyAccumulator } from '../clean-accumulator';
import { generateUnshieldV3, verifyUnshieldV3, DualLineage } from '../v6-proof';
import { RSA_N } from '../constants';

chai.use(chaiAsPromised);

const SIZES = [1, 2, 4, 8, 16, 32, 64, 128, 256];
const RSA_CAP = 128;
const G = 65537n;

function generatePrimes(count: number): bigint[] {
  const primes: bigint[] = [];
  const enc = new TextEncoder();
  for (let i = 0; i < count; i++) primes.push(diHash(enc.encode(`bench_${i}`)));
  primes.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return primes;
}

function generateModPrimes(count: number): bigint[] {
  const primes: bigint[] = [];
  const enc = new TextEncoder();
  for (let i = 0; i < count; i++) primes.push(hashToPrimeMod(enc.encode(`mod_${i}`)));
  primes.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return primes;
}

function now(): number { return typeof performance !== 'undefined' ? performance.now() : Date.now(); }
function fmt(ms: number): string {
  if (ms < 0.001) return `${(ms * 1e6).toFixed(0)} ns`;
  if (ms < 1) return `${(ms * 1000).toFixed(1)} us`;
  if (ms < 1000) return `${ms.toFixed(2)} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

describe('Source Compliance v6 Benchmark (dual lineage)', function () {
  this.timeout(600_000);
  const srcPools: Map<number, bigint[]> = new Map();
  const modPools: Map<number, bigint[]> = new Map();

  before(async () => {
    await initPoseidonPromise;
    console.log('\n  Generating prime pools...');
    let t0 = now();
    const maxSrc = Math.max(...SIZES);
    const allSrc = generatePrimes(maxSrc);
    console.log(`  ${maxSrc} source primes in ${fmt(now() - t0)}`);
    t0 = now();
    const allMod = generateModPrimes(Math.min(maxSrc, 24)); // ModSet much smaller
    console.log(`  ${allMod.length} module primes in ${fmt(now() - t0)}`);
    for (const s of SIZES) {
      srcPools.set(s, allSrc.slice(0, s));
      modPools.set(s, allMod.slice(0, Math.min(s, allMod.length)));
    }
  });

  it('should benchmark all operations', () => {
    console.log('\n');
    console.log('  +---------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+');
    console.log('  | SrcSize | SrcCreation | SrcDigest   | ModDigest   | ComSrcset   | ComModset   | CommitVecS  | SubsetWit   | FullProof   |');
    console.log('  +---------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+');

    for (const size of SIZES) {
      const srcPrimes = srcPools.get(size)!;
      const modPrimes = modPools.get(size)!.slice(0, Math.min(4, size)); // ModSet cap at 4 for bench
      const row: Record<string, number> = {};

      let t0 = now();
      const srcSet = new CanonicalSourceSet(srcPrimes);
      row.srcCreation = now() - t0;

      let modSet: CanonicalSourceSet;
      try { modSet = new CanonicalSourceSet(modPrimes); } catch { modSet = new CanonicalSourceSet([]); }

      t0 = now(); setDigestSrc(srcSet); row.srcDigest = now() - t0;
      t0 = now(); setDigestMod(modSet); row.modDigest = now() - t0;
      t0 = now(); comSrcset(123n, 42n); row.comSrc = now() - t0;
      t0 = now(); comModset(456n, 99n); row.comMod = now() - t0;
      t0 = now(); commitVec([...srcPrimes], 42n); row.commitVecS = now() - t0;

      row.subsetWit = -1;
      row.fullProof = -1;

      if (size <= RSA_CAP) {
        const accBuild = now();
        const acc = new PolicyAccumulator(RSA_N, G, 0);
        for (const p of srcPrimes) acc.registerSource(p);
        for (const p of modPrimes) acc.registerModule(p);
        console.log(`    [src=${size},mod=${modPrimes.length}] acc build: ${fmt(now() - accBuild)}`);

        const allP = [...srcPrimes, ...modPrimes];
        t0 = now();
        acc.subsetWitnessBase(allP);
        row.subsetWit = now() - t0;

        const lineage: DualLineage = { srcSet, modSet };
        const qa = sampleAliasPrime(new TextEncoder().encode('bench'));
        t0 = now();
        const proof = generateUnshieldV3(lineage, 42n, 99n, 11n, 22n, acc, qa, RSA_N);
        verifyUnshieldV3(proof, lineage, acc, RSA_N);
        row.fullProof = now() - t0;
      }

      const fields = [
        String(size).padStart(7),
        fmt(row.srcCreation).padStart(11),
        fmt(row.srcDigest).padStart(11),
        fmt(row.modDigest).padStart(11),
        fmt(row.comSrc).padStart(11),
        fmt(row.comMod).padStart(11),
        fmt(row.commitVecS).padStart(11),
        (row.subsetWit >= 0 ? fmt(row.subsetWit) : 'N/A').padStart(11),
        (row.fullProof >= 0 ? fmt(row.fullProof) : 'N/A').padStart(11),
      ];
      console.log(`  | ${fields.join(' | ')} |`);
    }
    console.log('  +---------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+');
    console.log(`\n  RSA ops capped at ${RSA_CAP} sources. ModSet capped at 4 for bench.\n`);
  });
});
