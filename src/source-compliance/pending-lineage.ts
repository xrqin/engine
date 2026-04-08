/**
 * Pending Lineage Store — Rescan/Recovery for Late-Arriving Lineage (D.7)
 *
 * When a receiver decrypts a note but its lineage payload arrives late
 * (e.g., via dedup reference or deferred delivery), the note is tracked
 * in PendingLineageStore. When the missing payload arrives, the store
 * triggers verification and marks the note as lineage-complete.
 *
 * This ensures the v8.1 normative rule: receivers can always reconstruct
 * exact source AND module lists needed for future spending.
 */

import { verifySourcePayload, verifyModulePayload } from './source-memo';
import type { SourceDescriptor } from './source-descriptor';
import type { ModuleDescriptor } from './module-descriptor';

// ============================================================
// Types
// ============================================================

export interface PendingNoteLineage {
  /** Note commitment (unique identifier) */
  noteCommitment: bigint;
  /** Note's source_commitment field */
  sourceCommitment: bigint;
  /** Note's module_commitment field */
  moduleCommitment: bigint;
  /** Note seed values for rho derivation */
  rhoValue: bigint;
  ownerPubkey: bigint;
  outputIndex: number;
  /** Which lineage parts are still missing */
  missingSource: boolean;
  missingModule: boolean;
  /** Resolved payloads once verified */
  sourcePayload?: Uint8Array;
  modulePayload?: Uint8Array;
  /** Timestamp when the note was first seen */
  firstSeenMs: number;
}

export interface LineageResolution {
  noteCommitment: bigint;
  sourceDescriptor?: SourceDescriptor;
  sourceList?: bigint[];
  moduleDescriptor?: ModuleDescriptor;
  moduleList?: bigint[];
  complete: boolean;
}

// ============================================================
// PendingLineageStore
// ============================================================

export class PendingLineageStore {
  private pending = new Map<string, PendingNoteLineage>();

  /**
   * Register a note that needs lineage resolution.
   * Call this when a note is decrypted but source/module payloads are missing.
   */
  registerPending(
    noteCommitment: bigint,
    sourceCommitment: bigint,
    moduleCommitment: bigint,
    rhoValue: bigint,
    ownerPubkey: bigint,
    outputIndex: number,
    missingSource: boolean,
    missingModule: boolean,
  ): void {
    const key = noteCommitment.toString();
    if (this.pending.has(key)) return; // already tracked

    this.pending.set(key, {
      noteCommitment,
      sourceCommitment,
      moduleCommitment,
      rhoValue,
      ownerPubkey,
      outputIndex,
      missingSource,
      missingModule,
      firstSeenMs: Date.now(),
    });
  }

  /**
   * Attempt to resolve a pending note's source lineage with an arriving payload.
   * Returns the resolution result, or null if the note is not pending.
   */
  resolveSource(
    noteCommitment: bigint,
    sourcePayload: Uint8Array,
  ): LineageResolution | null {
    const key = noteCommitment.toString();
    const entry = this.pending.get(key);
    if (!entry || !entry.missingSource) return null;

    const result = verifySourcePayload(
      sourcePayload,
      entry.sourceCommitment,
      entry.rhoValue,
      entry.ownerPubkey,
      entry.outputIndex,
    );

    if (!result.valid) return null;

    entry.missingSource = false;
    entry.sourcePayload = new Uint8Array(sourcePayload);

    const complete = !entry.missingSource && !entry.missingModule;
    if (complete) this.pending.delete(key);

    return {
      noteCommitment,
      sourceDescriptor: result.descriptor,
      sourceList: result.sources,
      complete,
    };
  }

  /**
   * Attempt to resolve a pending note's module lineage with an arriving payload.
   */
  resolveModule(
    noteCommitment: bigint,
    modulePayload: Uint8Array,
  ): LineageResolution | null {
    const key = noteCommitment.toString();
    const entry = this.pending.get(key);
    if (!entry || !entry.missingModule) return null;

    const result = verifyModulePayload(
      modulePayload,
      entry.moduleCommitment,
      entry.rhoValue,
      entry.ownerPubkey,
      entry.outputIndex,
    );

    if (!result.valid) return null;

    entry.missingModule = false;
    entry.modulePayload = new Uint8Array(modulePayload);

    const complete = !entry.missingSource && !entry.missingModule;
    if (complete) this.pending.delete(key);

    return {
      noteCommitment,
      moduleDescriptor: result.descriptor,
      moduleList: result.modules,
      complete,
    };
  }

  /**
   * Attempt to resolve both source and module lineage at once
   * (e.g., when a unified lineage memo is decrypted).
   */
  resolveBoth(
    noteCommitment: bigint,
    sourcePayload: Uint8Array,
    modulePayload: Uint8Array,
  ): LineageResolution | null {
    const key = noteCommitment.toString();
    const entry = this.pending.get(key);
    if (!entry) return null;

    const srcResult = entry.missingSource
      ? verifySourcePayload(
          sourcePayload,
          entry.sourceCommitment,
          entry.rhoValue,
          entry.ownerPubkey,
          entry.outputIndex,
        )
      : { valid: true };

    const modResult = entry.missingModule
      ? verifyModulePayload(
          modulePayload,
          entry.moduleCommitment,
          entry.rhoValue,
          entry.ownerPubkey,
          entry.outputIndex,
        )
      : { valid: true };

    if (!srcResult.valid || !modResult.valid) return null;

    entry.missingSource = false;
    entry.missingModule = false;
    entry.sourcePayload = new Uint8Array(sourcePayload);
    entry.modulePayload = new Uint8Array(modulePayload);

    this.pending.delete(key);

    return {
      noteCommitment,
      sourceDescriptor: 'descriptor' in srcResult ? srcResult.descriptor : undefined,
      sourceList: 'sources' in srcResult ? srcResult.sources : undefined,
      moduleDescriptor: 'descriptor' in modResult ? (modResult as any).descriptor : undefined,
      moduleList: 'modules' in modResult ? (modResult as any).modules : undefined,
      complete: true,
    };
  }

  /** Check if a note has pending lineage. */
  isPending(noteCommitment: bigint): boolean {
    return this.pending.has(noteCommitment.toString());
  }

  /** Get all pending notes. */
  getPendingNotes(): PendingNoteLineage[] {
    return [...this.pending.values()];
  }

  /** Get pending notes older than a threshold (for retry/cleanup). */
  getStaleEntries(maxAgeMs: number): PendingNoteLineage[] {
    const cutoff = Date.now() - maxAgeMs;
    return [...this.pending.values()].filter(e => e.firstSeenMs <= cutoff);
  }

  /** Remove a pending entry (e.g., note was spent or abandoned). */
  remove(noteCommitment: bigint): boolean {
    return this.pending.delete(noteCommitment.toString());
  }

  get size(): number {
    return this.pending.size;
  }

  clear(): void {
    this.pending.clear();
  }
}
