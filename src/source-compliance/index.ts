/**
 * RAILGUN Source Compliance
 *
 * v6: Dual lineage (SrcSet + ModSet), NoteV3, unified policy accumulator, TypedCallV1
 * v7: Canonical set tree (root+count), NoteV4, lineageBinding, policyBinding, TypedCallV2
 * v8.1: Binary frontier descriptor, NoteV5, inputLineageBinding, updated bindings
 */

// ---------------------------------------------------------------------------
// Constants — v6 + v7
// ---------------------------------------------------------------------------

export {
  // Shared
  RSA_N, RSA_BITS,
  PRIME_BITS_SRC, PRIME_BITS_MOD, PRIME_BITS_EPOCH, PRIME_BITS_ALIAS,
  ACTION_UNSHIELD_ALIAS, ACTION_TRANSFER_REFRESH_ALIAS,
  // v6
  NOTE_VERSION_V3,
  MAX_SRCSET_CLIENT_SMALL, MAX_SRCSET_SERVER_ONLY,
  MAX_MODSET_CLIENT_SMALL, MAX_MODSET_SERVER_ONLY,
  DST_SET_DIGEST_SRC_V1, DST_SET_DIGEST_MOD_V1,
  DST_SRC_COMMIT_V7, DST_MOD_COMMIT_V1,
  DST_NOTE_COM_V3, DST_COMMIT_VEC_V7,
  DST_ALIAS_CERT_V7, DST_EPOCH_PRIME_V6,
  DST_SRC_PRIME_V6, DST_MOD_PRIME_V1,
  DST_REFRESH_ID_V7,
  // v7
  SOURCE_PROOF_VERSION, NOTE_VERSION_V4,
  SET_TREE_ARITY,
  MERGE_STEP_FANIN, MERGE_CHUNK_LEAVES, SUBSET_CHUNK_LEAVES,
  MAX_RECIPE_STEPS, MAX_BOUNDARY_TAGS_ADDED, MAX_DECLARED_TOKENS,
  DST_LEAF_SRC_V1, DST_LEAF_MOD_V1,
  DST_NODE_SRC_V1, DST_NODE_MOD_V1,
  DST_SRC_COMMIT_V2, DST_MOD_COMMIT_V2,
  DST_NOTE_COM_V4,
  DST_INPUT_NOTE_BIND_V3, DST_INPUT_BIND_V10,
  DST_OUTPUT_BIND_V10, DST_PUBLIC_OUTPUT_BIND_V6,
  DST_BUCKET_SRC_COM_V1, DST_BUCKET_MOD_COM_V1,
  DST_BUCKET_SRC_IN_REF_V1, DST_BUCKET_MOD_IN_REF_V1,
  DST_BUCKET_META_V1,
  DST_LINEAGE_BIND_V2, DST_POLICY_BIND_V2,
  DST_RETURN_BALANCE_BIND_V2, DST_EXEC_BIND_V2,
  DST_DECLARED_TOKEN_BIND_V1, DST_REACHABLE_TOKEN_BIND_V1,
  DST_RUNTIME_ARGS_V1,
  // v8.1
  NOTE_VERSION_V5, SOURCE_PROOF_VERSION_V8,
  D_DESC, B_SCAN, B_MERGE,
  MAX_SRC_COUNT, MAX_STREAM_CHUNKS, MAX_IVC_STEPS,
  DST_SRC_LEAF_V3, DST_SRC_NODE_V3, DST_SRC_BAG_V1, DST_SRC_ROOT_V1,
  DST_SRC_COMMIT_V3, DST_MOD_COMMIT_V3, DST_NOTE_COM_V5,
  DST_MOD_LEAF_V3, DST_MOD_NODE_V3, DST_MOD_BAG_V1, DST_MOD_ROOT_V1,
  DST_MOD_TAG_ENCODE_V1,
  DST_DERIVE_RHO_SRC_V1, DST_DERIVE_RHO_MOD_V1,
  DST_INPUT_NOTE_BIND_V4, DST_INPUT_BIND_V11,
  DST_INPUT_LINEAGE_NOTE_BIND_V1, DST_INPUT_LINEAGE_BIND_V1,
  DST_OUTPUT_BIND_V11, DST_PUBLIC_OUTPUT_BIND_V7,
  DST_BUCKET_SRC_IN_REF_V2, DST_BUCKET_MOD_IN_REF_V2,
  DST_BUCKET_SRC_META_V1, DST_BUCKET_META_V3,
  DST_LINEAGE_BIND_V3, DST_POLICY_BIND_V3,
  DST_MEMO_AD_V1, DST_SRC_PACKAGE_ID_V1,
  DST_MOD_PACKAGE_ID_V1, DST_LINEAGE_MEMO_AD_V1,
} from './constants';

// ---------------------------------------------------------------------------
// Canonical sets
// ---------------------------------------------------------------------------

export { CanonicalSourceSet } from './canonical-source-set';
export { CanonicalModuleSet } from './canonical-module-set';

// ---------------------------------------------------------------------------
// DI-Hash (4 domain-separated prime generators)
// ---------------------------------------------------------------------------

export {
  isPrime, modpow, diHash,
  hashToPrimeSrc, hashToPrimeMod, hashToPrimeEpoch, sampleAliasPrime,
} from './di-hash';

// ---------------------------------------------------------------------------
// v7 Canonical Set Tree (B=4 Poseidon Merkle tree)
// ---------------------------------------------------------------------------

export {
  buildCanonicalSetTree, verifyCanonicalSetTree,
  leafHash, nodeHash, emptyNode,
} from './canonical-set-tree';
export type { CanonicalSetTree, SetTreeKind } from './canonical-set-tree';

// ---------------------------------------------------------------------------
// v6 SetDigest (flat encoding)
// ---------------------------------------------------------------------------

export { setDigestSrc, setDigestMod, setDigest } from './set-digest';

// ---------------------------------------------------------------------------
// Commitments — v6 (flat SetDigest) + v7 (tree root binding) + v8.1 (frontier)
// ---------------------------------------------------------------------------

export {
  // v6
  comSrcset as comSrcset_v6, comModset as comModset_v6, commitVec,
  // v7
  comSrc, comMod, noteComV4,
  // v8.1
  comSrcV8, comModV8, deriveRhoSrc, deriveRhoMod, noteComV5,
  // Shared utils
  dstToFieldElement, BN254_PRIME,
} from './commitments';
export type { NoteV4, NoteV5 } from './commitments';

// ---------------------------------------------------------------------------
// v8.1 Source Descriptor (binary frontier)
// ---------------------------------------------------------------------------

export {
  buildSourceDescriptor,
  verifySourceDescriptor,
  appendLeafSrcDesc,
  finalizeSourceFrontier,
  emptyDescFrontier,
  leafHashSrc, nodeHashSrc, bagHashSrc, rootHashSrc,
} from './source-descriptor';
export type { SourceDescriptor, DescFrontier } from './source-descriptor';

// ---------------------------------------------------------------------------
// v8.1 Module Descriptor (binary frontier)
// ---------------------------------------------------------------------------

export {
  buildModuleDescriptor,
  verifyModuleDescriptor,
  appendLeafModDesc,
  finalizeModuleFrontier,
  emptyModDescFrontier,
  leafHashMod, nodeHashMod, bagHashMod, rootHashMod,
} from './module-descriptor';
export type { ModuleDescriptor, ModDescFrontier } from './module-descriptor';

// ---------------------------------------------------------------------------
// v8.1 Module/Tag Encoding
// ---------------------------------------------------------------------------

export {
  normalizeModuleLocator,
  encodeModuleLocator,
  encodeTag,
  buildModuleTagSet,
  encodeCanonicalModuleBytes,
  decodeCanonicalModuleBytes,
} from './module-tag-encoding';

// ---------------------------------------------------------------------------
// v8.1 Binding Layer
// ---------------------------------------------------------------------------

export {
  // Input bindings
  computeInputNoteSemV8,
  computeInputBindingV8,
  // Input lineage binding (anti-splice)
  computeInputLineageNoteSem,
  computeInputLineageBinding,
  // Output bindings
  computeOutputBindingV8,
  computePublicOutputBindingV8,
  // Bucket lineage
  computeBucketSrcInRefDigest,
  computeBucketModInRefDigest,
  computeBucketSrcMeta,
  computeBucketSrcMetaNoteBacked,
  computeBucketMetaCommitV8,
  // Lineage + policy bindings
  computeLineageBindingV8,
  computePolicyBindingV8,
} from './bindings';

// ---------------------------------------------------------------------------
// v8.1 Source & Module Memo (receiver-private lineage delivery)
// ---------------------------------------------------------------------------

export {
  // Source side
  buildSourcePayload,
  decodeSourcePayload,
  buildSourcePackageId,
  verifySourcePayload,
  SourceCache,
  // Module side
  buildModulePayload,
  decodeModulePayload,
  buildModulePackageId,
  verifyModulePayload,
  ModuleCache,
  // Legacy source-only memo
  buildMemoAD,
  encryptSourceMemo,
  decryptSourceMemo,
  // Unified lineage memo (source + module)
  buildLineageMemoAD,
  encryptLineageMemo,
  decryptLineageMemo,
} from './source-memo';

// ---------------------------------------------------------------------------
// v8.1 Pending Lineage / Rescan Recovery
// ---------------------------------------------------------------------------

export { PendingLineageStore } from './pending-lineage';
export type {
  PendingNoteLineage,
  LineageResolution,
} from './pending-lineage';

// ---------------------------------------------------------------------------
// v8.1 Transaction Preflight Limit Checks
// ---------------------------------------------------------------------------

export {
  validatePreflightLimits,
  estimateIvcSteps,
  paddedMemoSize,
  MAX_BUCKET_COUNT,
  MAX_CARRY_INPUT_REFS,
  MAX_MEMO_PAYLOAD_BYTES,
  MAX_FLOW_MATRIX_DIM,
  MEMO_SIZE_BUCKETS,
} from './preflight';
export type { PreflightError, PreflightInput } from './preflight';

// ---------------------------------------------------------------------------
// v6 accumulator + alias
// ---------------------------------------------------------------------------

export { PolicyAccumulator } from './clean-accumulator';

export { createAlias, liftWitness, verifyAliasSubset } from './alias';

// ---------------------------------------------------------------------------
// v6 proof pipeline
// ---------------------------------------------------------------------------

export {
  DualLineage,
  generateShieldV3,
  generateTransferV3Fast, verifyTransferV3Fast,
  generateTransferV3Refresh, verifyTransferV3Refresh,
  generateUnshieldV3, verifyUnshieldV3,
  generateTypedCallExact, generateTypedCallBoundary,
} from './v6-proof';

// ---------------------------------------------------------------------------
// v7 proof pipeline
// ---------------------------------------------------------------------------

export {
  generateShieldV4,
  generateTransferV4Fast,
  generateTransferV4Refresh,
  generateUnshieldV4Set,
  generateTypedCallV2Exact,
  generateTypedCallV2Boundary,
  computeLineageBinding,
  computePolicyBinding,
  bucketSrcCommit, bucketModCommit,
  bucketSrcInRefDigest, bucketModInRefDigest,
  bucketMetaCommit,
} from './v7-proof';
export type {
  V7ShieldResult, V7TransferFastResult, V7TransferRefreshResult,
  V7UnshieldSetResult, V7TypedCallResult,
  InputNoteLineage,
} from './v7-proof';

// ---------------------------------------------------------------------------
// v7 canonical relations (separate files)
// ---------------------------------------------------------------------------

export {
  computeInputBinding, computeOutputBinding,
  computePublicOutputBinding,
  computeInputNoteSemantic,
  verifyTransferCanonicalV4,
} from './relations/transfer-canonical-v4';
export type {
  TransferCanonicalWitness, BucketAssignment,
  TransferInputNote, TransferOutputNote,
  PublicOutput,
} from './relations/transfer-canonical-v4';

export { verifyUnshieldCanonicalV4 } from './relations/unshield-canonical-v4';
export type {
  UnshieldCanonicalWitness, UnshieldInputNote, PublicBucketSpec,
} from './relations/unshield-canonical-v4';

export {
  computeDeclaredTokenBinding, computeReachableTokenBinding,
  computeReturnBalanceBinding, computeExecBinding,
  computeRuntimeArgsHash,
  verifyReturnVecConservationPerDeclaredToken,
  verifyTypedCallCanonicalV2,
} from './relations/typedcall-canonical-v2';
export type {
  TypedCallCanonicalWitness, ReturnVecConservationInput,
} from './relations/typedcall-canonical-v2';

export { verifyTypedCallLineageV2 } from './relations/typedcall-lineage-v2';
export type {
  CarriedInputLineage, TypedCallLineageWitness,
} from './relations/typedcall-lineage-v2';

// ---------------------------------------------------------------------------
// v7 Session Escrow V2
// ---------------------------------------------------------------------------

export {
  validateSessionEscrowV2,
  createSessionEscrowV2,
  validateDeclaredSubsetOfReachable,
  assertCanonicalTokenOrder,
} from './session-escrow-v2';
export type {
  SessionEscrowV2Config, SessionReceipt as SessionReceiptV2,
  InvariantResult,
} from './session-escrow-v2';

// ---------------------------------------------------------------------------
// v7 Manifest / Module Registry
// ---------------------------------------------------------------------------

export {
  ManifestRegistry,
  computeModuleManifestHash,
  isExactEligible, getExactEligibilityFailures,
  createLineageFlowMatrix, getFlow, deriveCarryIn,
  composeFlowMatrices,
  hashLineageFlowMatrix,
  hashTagTreeByOutputBucket,
  hashTargetCodeHashVector,
} from './manifest-registry';
export type {
  StepManifest, RecipeManifest, ResolvedManifest,
  LineageFlowMatrix, TagTreeByOutputBucket,
  StepClass, ExactEligibilityCheck,
} from './manifest-registry';

// ---------------------------------------------------------------------------
// v7 Proving backend
// ---------------------------------------------------------------------------

export { MockProvingBackend } from './proving/recursive-verifier';
export { DefaultWitnessBuilder } from './proving/witness-builder';
export {
  IVCProvingBackend,
  ivcProveMergeN,
  ivcVerifyMergeN,
  ivcInit,
  ivcMergeStep,
} from './proving/ivc-backend';
export type { IVCState, IVCStepInput, IVCProof } from './proving/ivc-backend';
export type {
  ProvingBackend, ProofObject, MergeForest, Merge2Result,
  SubsetFromTreeWitness, WitnessBuilder,
  BucketSpec, TransferWitness, TypedCallWitness, UnshieldWitness,
} from './proving/backend-interface';
