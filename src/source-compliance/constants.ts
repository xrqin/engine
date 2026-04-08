/**
 * RAILGUN Source Compliance Constants
 *
 * v6: Dual lineage (SrcSet + ModSet), NoteV3, unified policy accumulator, TypedCallV1
 * v7: Canonical set tree (root+count), NoteV4, lineageBinding, policyBinding, TypedCallV2
 */

// ---------------------------------------------------------------------------
// RSA accumulator modulus (shared v6/v7)
// ---------------------------------------------------------------------------

export const RSA_N: bigint = BigInt(
  '25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784' +
  '40691829064124951508218929855914917618450280848912007284499268739280728777673597141834727026189637' +
  '50149718246911650776133798590957000973304597488084284017974291006424586918171951187461215151726546' +
  '32282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163' +
  '81501067481045166037730605620161967625613384414360383390441495263443219011465754445417842402092461' +
  '65157233507787077498171257724679629263863563732899121548314381678998850404453640235273819513786365' +
  '64391212010397122822120720357',
);

export const RSA_BITS = 2048;

// ---------------------------------------------------------------------------
// Four disjoint prime domains (shared v6/v7)
// ---------------------------------------------------------------------------

export const PRIME_BITS_SRC = 256;
export const PRIME_BITS_MOD = 288;
export const PRIME_BITS_EPOCH = 320;
export const PRIME_BITS_ALIAS = 384;

// ---------------------------------------------------------------------------
// Note versions
// ---------------------------------------------------------------------------

export const NOTE_VERSION_V3 = 0x3; // v6 NoteV3
export const NOTE_VERSION_V4 = 0x4; // v7 NoteV4

// ---------------------------------------------------------------------------
// Protocol version
// ---------------------------------------------------------------------------

export const SOURCE_PROOF_VERSION = 0x7;

// ---------------------------------------------------------------------------
// v6 proving profiles (retained for v6 compat)
// ---------------------------------------------------------------------------

export const MAX_SRCSET_CLIENT_SMALL = 32;
export const MAX_SRCSET_CLIENT_STANDARD = 64;
export const MAX_SRCSET_REFRESH_STANDARD = 128;
export const MAX_SRCSET_SERVER_ONLY = 256;
export const MAX_MODSET_CLIENT_SMALL = 4;
export const MAX_MODSET_CLIENT_STANDARD = 8;
export const MAX_MODSET_REFRESH_STANDARD = 16;
export const MAX_MODSET_SERVER_ONLY = 24;

// ---------------------------------------------------------------------------
// v7 Canonical Set Tree parameters
// ---------------------------------------------------------------------------

export const SET_TREE_ARITY = 4;

// ---------------------------------------------------------------------------
// v7 Recursion / IVC operational parameters
// ---------------------------------------------------------------------------

export const MERGE_STEP_FANIN = 2;
export const MERGE_CHUNK_LEAVES = 32;
export const SUBSET_CHUNK_LEAVES = 32;

// ---------------------------------------------------------------------------
// v7 Session / Recipe limits
// ---------------------------------------------------------------------------

export const MAX_RECIPE_STEPS = 2;
export const MAX_BOUNDARY_TAGS_ADDED = 2;
export const MAX_DECLARED_TOKENS = 4;

// ---------------------------------------------------------------------------
// Domain Separation Tags — v6
// ---------------------------------------------------------------------------

export const DST_SET_DIGEST_SRC_V1 = 'RAILGUN_SET_DIGEST_SRC_V1';
export const DST_SET_DIGEST_MOD_V1 = 'RAILGUN_SET_DIGEST_MOD_V1';
export const DST_SRC_COMMIT_V7 = 'RAILGUN_SRC_COMMIT_V7';
export const DST_MOD_COMMIT_V1 = 'RAILGUN_MOD_COMMIT_V1';
export const DST_NOTE_COM_V3 = 'RAILGUN_NOTE_COM_V3';
export const DST_COMMIT_VEC_V7 = 'RAILGUN_SOURCE_PRIME_COMMIT_V7';
export const DST_ALIAS_CERT_V7 = 'RAILGUN_SOURCE_ALIAS_CERT_V7';
export const DST_EPOCH_PRIME_V6 = 'RAILGUN_SOURCE_EPOCH_PRIME_V6';
export const DST_SRC_PRIME_V6 = 'RAILGUN_SOURCE_SRC_PRIME_V6';
export const DST_MOD_PRIME_V1 = 'RAILGUN_MODULE_PRIME_V1';
export const DST_REFRESH_ID_V7 = 'RAILGUN_SOURCE_REFRESH_ID_V7';

// ---------------------------------------------------------------------------
// Domain Separation Tags — v7 (canonical set tree, commitments, bindings)
// ---------------------------------------------------------------------------

// Canonical set tree leaf/node hashing
export const DST_LEAF_SRC_V1 = 'RAILGUN_SOURCE_LEAF_SRC_V1';
export const DST_LEAF_MOD_V1 = 'RAILGUN_SOURCE_LEAF_MOD_V1';
export const DST_NODE_SRC_V1 = 'RAILGUN_SOURCE_NODE_SRC_V1';
export const DST_NODE_MOD_V1 = 'RAILGUN_SOURCE_NODE_MOD_V1';

// Commitments (v7 tree-root binding)
export const DST_SRC_COMMIT_V2 = 'RAILGUN_SOURCE_SRC_COMMIT_V2';
export const DST_MOD_COMMIT_V2 = 'RAILGUN_SOURCE_MOD_COMMIT_V2';
export const DST_NOTE_COM_V4 = 'RAILGUN_SOURCE_NOTE_COM_V4';

// Input/output bindings (v7)
export const DST_INPUT_NOTE_BIND_V3 = 'RAILGUN_SOURCE_INPUT_NOTE_BIND_V3';
export const DST_INPUT_BIND_V10 = 'RAILGUN_SOURCE_INPUT_BIND_V10';
export const DST_OUTPUT_BIND_V10 = 'RAILGUN_SOURCE_OUTPUT_BIND_V10';
export const DST_PUBLIC_OUTPUT_BIND_V6 = 'RAILGUN_SOURCE_PUBLIC_OUTPUT_BIND_V6';

// Bucket lineage commitments (v7)
export const DST_BUCKET_SRC_COM_V1 = 'RAILGUN_SOURCE_BUCKET_SRC_COM_V1';
export const DST_BUCKET_MOD_COM_V1 = 'RAILGUN_SOURCE_BUCKET_MOD_COM_V1';
export const DST_BUCKET_SRC_IN_REF_V1 = 'RAILGUN_SOURCE_BUCKET_SRC_IN_REF_V1';
export const DST_BUCKET_MOD_IN_REF_V1 = 'RAILGUN_SOURCE_BUCKET_MOD_IN_REF_V1';
export const DST_BUCKET_META_V1 = 'RAILGUN_SOURCE_BUCKET_META_V1';

// Lineage + policy bindings (v7)
export const DST_LINEAGE_BIND_V2 = 'RAILGUN_SOURCE_LINEAGE_BIND_V2';
export const DST_POLICY_BIND_V2 = 'RAILGUN_SOURCE_POLICY_BIND_V2';

// Exec / return / token bindings (v7)
export const DST_RETURN_BALANCE_BIND_V2 = 'RAILGUN_SOURCE_RETURN_BALANCE_BIND_V2';
export const DST_EXEC_BIND_V2 = 'RAILGUN_SOURCE_EXEC_BIND_V2';
export const DST_DECLARED_TOKEN_BIND_V1 = 'RAILGUN_SOURCE_DECLARED_TOKEN_BIND_V1';
export const DST_REACHABLE_TOKEN_BIND_V1 = 'RAILGUN_SOURCE_REACHABLE_TOKEN_BIND_V1';
export const DST_RUNTIME_ARGS_V1 = 'RAILGUN_SOURCE_RUNTIME_ARGS_V1';

// Prime hashing DSTs (v7, same values as v6 for domain continuity)
export const DST_SRC_PRIME_V6_V7 = DST_SRC_PRIME_V6;
export const DST_MOD_PRIME_V1_V7 = DST_MOD_PRIME_V1;
export const DST_EPOCH_PRIME_V6_V7 = DST_EPOCH_PRIME_V6;

// ---------------------------------------------------------------------------
// v8.1 Note version
// ---------------------------------------------------------------------------

export const NOTE_VERSION_V5 = 0x5;

// ---------------------------------------------------------------------------
// v8.1 Source Descriptor parameters
// ---------------------------------------------------------------------------

export const D_DESC = 64; // max frontier depth (supports up to 2^64 sources)
export const B_SCAN = 8; // sources per SCAN chunk
export const B_MERGE = 4; // micro-steps per MERGE2 step

// ---------------------------------------------------------------------------
// v8.1 Implementation upper bounds
// ---------------------------------------------------------------------------

export const MAX_SRC_COUNT = 1024;
export const MAX_STREAM_CHUNKS = 128; // ceil(MAX_SRC_COUNT / B_SCAN)
export const MAX_IVC_STEPS = 256;

// ---------------------------------------------------------------------------
// v8.1 Protocol version
// ---------------------------------------------------------------------------

export const SOURCE_PROOF_VERSION_V8 = 0x8;

// ---------------------------------------------------------------------------
// Domain Separation Tags — v8.1 (source descriptor, commitments, bindings)
// ---------------------------------------------------------------------------

// Source descriptor (binary frontier)
export const DST_SRC_LEAF_V3 = 'RAILGUN_SRC_LEAF_V3';
export const DST_SRC_NODE_V3 = 'RAILGUN_SRC_NODE_V3';
export const DST_SRC_BAG_V1 = 'RAILGUN_SRC_BAG_V1';
export const DST_SRC_ROOT_V1 = 'RAILGUN_SRC_ROOT_V1';

// Commitments (v8.1)
export const DST_SRC_COMMIT_V3 = 'RAILGUN_SRC_COMMIT_V3';
export const DST_NOTE_COM_V5 = 'RAILGUN_NOTE_COM_V5';

// Deterministic blinding factor derivation (v8.1)
export const DST_DERIVE_RHO_SRC_V1 = 'RAILGUN_DERIVE_RHO_SRC_V1';
export const DST_DERIVE_RHO_MOD_V1 = 'RAILGUN_DERIVE_RHO_MOD_V1';

// Input bindings (v8.1)
export const DST_INPUT_NOTE_BIND_V4 = 'RAILGUN_INPUT_NOTE_BIND_V4';
export const DST_INPUT_BIND_V11 = 'RAILGUN_INPUT_BIND_V11';
export const DST_INPUT_LINEAGE_NOTE_BIND_V1 = 'RAILGUN_INPUT_LINEAGE_NOTE_BIND_V1';
export const DST_INPUT_LINEAGE_BIND_V1 = 'RAILGUN_INPUT_LINEAGE_BIND_V1';

// Output bindings (v8.1)
export const DST_OUTPUT_BIND_V11 = 'RAILGUN_OUTPUT_BIND_V11';
export const DST_PUBLIC_OUTPUT_BIND_V7 = 'RAILGUN_PUBLIC_OUTPUT_BIND_V7';

// Bucket lineage (v8.1)
export const DST_BUCKET_SRC_IN_REF_V2 = 'RAILGUN_BUCKET_SRC_IN_REF_V2';
export const DST_BUCKET_MOD_IN_REF_V2 = 'RAILGUN_BUCKET_MOD_IN_REF_V2';
export const DST_BUCKET_SRC_META_V1 = 'RAILGUN_BUCKET_SRC_META_V1';
export const DST_BUCKET_META_V3 = 'RAILGUN_BUCKET_META_V3';

// Lineage + policy bindings (v8.1)
export const DST_LINEAGE_BIND_V3 = 'RAILGUN_LINEAGE_BIND_V3';
export const DST_POLICY_BIND_V3 = 'RAILGUN_POLICY_BIND_V3';

// Module descriptor (v8.1 binary frontier)
export const DST_MOD_LEAF_V3 = 'RAILGUN_MOD_LEAF_V3';
export const DST_MOD_NODE_V3 = 'RAILGUN_MOD_NODE_V3';
export const DST_MOD_BAG_V1 = 'RAILGUN_MOD_BAG_V1';
export const DST_MOD_ROOT_V1 = 'RAILGUN_MOD_ROOT_V1';

// Module commitment (v8.1)
export const DST_MOD_COMMIT_V3 = 'RAILGUN_MOD_COMMIT_V3';

// Module/tag encoding (v8.1)
export const DST_MOD_TAG_ENCODE_V1 = 'RAILGUN_MOD_TAG_ENCODE_V1';

// Source memo (v8.1)
export const DST_MEMO_AD_V1 = 'RAILGUN_MEMO_AD_V1';
export const DST_SRC_PACKAGE_ID_V1 = 'RAILGUN_SRC_PACKAGE_ID_V1';

// Module memo (v8.1)
export const DST_MOD_PACKAGE_ID_V1 = 'RAILGUN_MOD_PACKAGE_ID_V1';

// Lineage memo (v8.1 unified)
export const DST_LINEAGE_MEMO_AD_V1 = 'RAILGUN_LINEAGE_MEMO_AD_V1';

// ---------------------------------------------------------------------------
// Alias action types (shared v6/v7)
// ---------------------------------------------------------------------------

export const ACTION_UNSHIELD_ALIAS = 'UNSHIELD';
export const ACTION_TRANSFER_REFRESH_ALIAS = 'TRANSFER_REFRESH';
