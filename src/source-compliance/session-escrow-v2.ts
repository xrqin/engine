/**
 * Session Escrow V2 — RAILGUN Source Compliance v7
 *
 * Closed-world session escrow with 10 mandatory invariants.
 * Only checks manifest-registered reachableTokenSuperset.
 *
 * Key difference from v6: invariant count goes from 9 -> 10,
 * with the addition of "finalize-only private return path" (invariant 10).
 */

// ============================================================
// Types
// ============================================================

export interface SessionEscrowV2Config {
  sessionId: bigint;
  sessionEscrow: bigint;
  /** Sorted, unique token hashes declared in manifest */
  declaredTokenUniverse: bigint[];
  /** Sorted, unique superset of tokens reachable by the module */
  reachableTokenSuperset: bigint[];
}

export interface SessionReceipt {
  sessionId: bigint;
  /** Per-declared-token return amounts, aligned with declaredTokenUniverse */
  returnVec: bigint[];
  /** Balances observed at session start (must all be 0) */
  startBalances: Map<string, bigint>;
  /** Balances observed at session end */
  endBalances: Map<string, bigint>;
  /** Tokens that appeared during session execution */
  observedTokens: Set<string>;
  /** Whether any public sink was used */
  hasPublicSink: boolean;
  /** Whether pool re-entry occurred */
  hasReentrantPoolEntry: boolean;
  /** Whether delegatecall was used */
  hasDelegatecall: boolean;
  /** Whether undeclared callback domains were invoked */
  hasUndeclaredCallbackDomain: boolean;
  /** Whether non-finalize private return paths were used */
  hasNonFinalizePrivateReturn: boolean;
}

// ============================================================
// Invariant Validators
// ============================================================

export type InvariantResult = { ok: true } | { ok: false; invariant: number; reason: string };

/**
 * Validate all 10 Session Escrow V2 invariants.
 *
 * 1.  sessionEscrow unique + fresh per session_id
 * 2.  reachableTokenSuperset zero-start
 * 3.  declaredTokenUniverse fixed-order sweep to pool
 * 4.  reachable but undeclared token final balance = 0
 * 5.  token outside reachableTokenSuperset -> revert
 * 6.  noPublicSink
 * 7.  noReentrantPoolEntry
 * 8.  noDelegatecall
 * 9.  no undeclared callback domain
 * 10. finalize-only private return path
 */
export function validateSessionEscrowV2(
  config: SessionEscrowV2Config,
  receipt: SessionReceipt,
  knownSessionIds: Set<string>,
): InvariantResult {
  // Invariant 1: sessionEscrow unique + fresh per session_id
  const sessionKey = config.sessionId.toString();
  if (knownSessionIds.has(sessionKey)) {
    return { ok: false, invariant: 1, reason: 'sessionEscrow not unique: session_id already used' };
  }
  if (config.sessionEscrow === 0n) {
    return { ok: false, invariant: 1, reason: 'sessionEscrow must be non-zero (fresh)' };
  }

  // Invariant 2: reachableTokenSuperset zero-start
  for (const tok of config.reachableTokenSuperset) {
    const tokKey = tok.toString();
    const startBal = receipt.startBalances.get(tokKey) ?? 0n;
    if (startBal !== 0n) {
      return {
        ok: false,
        invariant: 2,
        reason: `reachable token ${tokKey} has non-zero start balance: ${startBal}`,
      };
    }
  }

  // Invariant 3: declaredTokenUniverse fixed-order sweep to pool
  if (receipt.returnVec.length !== config.declaredTokenUniverse.length) {
    return {
      ok: false,
      invariant: 3,
      reason: `returnVec length (${receipt.returnVec.length}) != declaredTokenUniverse length (${config.declaredTokenUniverse.length})`,
    };
  }
  for (let i = 0; i < config.declaredTokenUniverse.length; i++) {
    const tok = config.declaredTokenUniverse[i];
    const tokKey = tok.toString();
    const endBal = receipt.endBalances.get(tokKey) ?? 0n;
    // The return amount must equal the end balance (all swept back)
    if (receipt.returnVec[i] !== endBal) {
      return {
        ok: false,
        invariant: 3,
        reason: `declared token ${tokKey} returnVec[${i}]=${receipt.returnVec[i]} != endBalance=${endBal}`,
      };
    }
  }

  // Invariant 4: reachable but undeclared token final balance = 0
  const declaredSet = new Set(config.declaredTokenUniverse.map(t => t.toString()));
  for (const tok of config.reachableTokenSuperset) {
    const tokKey = tok.toString();
    if (!declaredSet.has(tokKey)) {
      const endBal = receipt.endBalances.get(tokKey) ?? 0n;
      if (endBal !== 0n) {
        return {
          ok: false,
          invariant: 4,
          reason: `reachable but undeclared token ${tokKey} has non-zero end balance: ${endBal}`,
        };
      }
    }
  }

  // Invariant 5: token outside reachableTokenSuperset -> revert
  const reachableSet = new Set(config.reachableTokenSuperset.map(t => t.toString()));
  for (const tokKey of receipt.observedTokens) {
    if (!reachableSet.has(tokKey)) {
      return {
        ok: false,
        invariant: 5,
        reason: `token ${tokKey} appeared during session but is not in reachableTokenSuperset`,
      };
    }
  }

  // Invariant 6: noPublicSink
  if (receipt.hasPublicSink) {
    return { ok: false, invariant: 6, reason: 'public sink detected during session' };
  }

  // Invariant 7: noReentrantPoolEntry
  if (receipt.hasReentrantPoolEntry) {
    return { ok: false, invariant: 7, reason: 'generic pool re-entry detected during session' };
  }

  // Invariant 8: noDelegatecall
  if (receipt.hasDelegatecall) {
    return { ok: false, invariant: 8, reason: 'delegatecall detected during session' };
  }

  // Invariant 9: no undeclared callback domain
  if (receipt.hasUndeclaredCallbackDomain) {
    return { ok: false, invariant: 9, reason: 'undeclared callback domain invoked during session' };
  }

  // Invariant 10: finalize-only private return path
  if (receipt.hasNonFinalizePrivateReturn) {
    return { ok: false, invariant: 10, reason: 'non-finalize private return path detected' };
  }

  return { ok: true };
}

// ============================================================
// Helpers
// ============================================================

/**
 * Validate that declaredTokenUniverse is a subset of reachableTokenSuperset.
 * Both must be sorted and unique.
 */
export function validateDeclaredSubsetOfReachable(
  declared: bigint[],
  reachable: bigint[],
): boolean {
  const reachableSet = new Set(reachable.map(t => t.toString()));
  for (const tok of declared) {
    if (!reachableSet.has(tok.toString())) return false;
  }
  return true;
}

/**
 * Validate canonical token ordering: sorted, unique, no duplicates.
 * Throws if invalid.
 */
export function assertCanonicalTokenOrder(tokens: bigint[], label: string): void {
  for (let i = 1; i < tokens.length; i++) {
    if (tokens[i] <= tokens[i - 1]) {
      throw new Error(
        `${label}: tokens must be sorted and unique. ` +
        `tokens[${i - 1}]=${tokens[i - 1]}, tokens[${i}]=${tokens[i]}`,
      );
    }
  }
}

/**
 * Create a SessionEscrowV2Config with validation.
 */
export function createSessionEscrowV2(
  sessionId: bigint,
  sessionEscrow: bigint,
  declaredTokenUniverse: bigint[],
  reachableTokenSuperset: bigint[],
): SessionEscrowV2Config {
  assertCanonicalTokenOrder(declaredTokenUniverse, 'declaredTokenUniverse');
  assertCanonicalTokenOrder(reachableTokenSuperset, 'reachableTokenSuperset');

  if (!validateDeclaredSubsetOfReachable(declaredTokenUniverse, reachableTokenSuperset)) {
    throw new Error('declaredTokenUniverse must be a subset of reachableTokenSuperset');
  }

  return {
    sessionId,
    sessionEscrow,
    declaredTokenUniverse,
    reachableTokenSuperset,
  };
}
