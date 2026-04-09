// Copyright (c) Pi Squared, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * FastSet Escrow Flow — End-to-End Examples
 *
 * Demonstrates three escrow scenarios:
 *
 *   Flow 1 — Happy path (Complete):
 *     Config → Fund → Deliver → Complete → provider + evaluator paid
 *
 *   Flow 2 — Early rejection (before delivery):
 *     Config → Fund → Reject → client refunded, evaluator paid
 *
 *   Flow 3 — Post-delivery rejection:
 *     Config → Fund → Deliver → Reject → client refunded, evaluator paid
 *
 * Uses the proxy REST API (POST /v1/submit-transaction, GET /v1/escrow-jobs, etc.)
 * with BCS-encoded transactions signed via Ed25519.
 *
 * Usage:
 *   npm install
 *   PROXY_URL=https://staging.api.fast.xyz/proxy-rest NETWORK_ID=fast:devnet npx tsx escrow-flow.ts
 * 
 * See https://staging.api.fast.xyz/proxy-rest/api-docs for more info on the proxy REST API.
 */

import { bcs } from "@mysten/bcs";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2";
import { keccak_256 } from "@noble/hashes/sha3";
import { hexToBytes as nobleFromHex, bytesToHex as nobleToHex } from "@noble/hashes/utils";

// @noble/ed25519 v2 requires SHA-512 to be provided externally.
ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

// ============================================================================
// Configuration
// ============================================================================

const PROXY_URL = process.env.PROXY_URL ?? "http://localhost:8080";
const NETWORK_ID = process.env.NETWORK_ID ?? "fast:localnet";

const FAST_DECIMALS = 18;
const ONE_FAST = 10n ** BigInt(FAST_DECIMALS);

/** Native FAST token ID: 0xFA575E70 followed by 28 zero bytes */
const FAST_TOKEN_ID = new Uint8Array(32);
FAST_TOKEN_ID.set([0xfa, 0x57, 0x5e, 0x70], 0);

// ============================================================================
// BCS Schema Definitions — Release20260407
//
// These must match the on-network Rust types exactly. The enum variant ORDER
// determines the BCS variant index, so every variant must be listed even if
// unused in this example.
// ============================================================================

// --- Primitives ---

const AddressBcs = bcs.bytes(32); // Ed25519 public key
const SignatureBcs = bcs.bytes(64); // Ed25519 signature
const TokenIdBcs = bcs.bytes(32);
const NonceBcs = bcs.u64();

/**
 * Amount is a U256 stored as 4 little-endian u64 digits.
 * Input: hex string (no 0x prefix) representing the raw amount.
 * The transform converts hex → decimal string for @mysten/bcs u256.
 */
const AmountBcs = bcs.u256().transform({
  input: (val: string) => BigInt(`0x${val}`).toString(),
});

/** Optional 32-byte user data (transparent newtype over Option<[u8;32]>) */
const UserDataBcs = bcs.option(bcs.bytes(32));

// --- SignatureOrMultiSig (BCS enum sent alongside the transaction) ---

const MultiSigConfigBcs = bcs.struct("MultiSigConfig", {
  authorized_signers: bcs.vector(AddressBcs),
  quorum: bcs.u64(),
  nonce: NonceBcs,
});

const MultiSigBcs = bcs.struct("MultiSig", {
  config: MultiSigConfigBcs,
  signatures: bcs.vector(bcs.tuple([AddressBcs, SignatureBcs])),
});

const SignatureOrMultiSigBcs = bcs.enum("SignatureOrMultiSig", {
  Signature: SignatureBcs, // variant 0 — simple Ed25519
  MultiSig: MultiSigBcs, // variant 1
});

// --- Operation sub-types (Release20260407) ---

const TokenTransferBcs = bcs.struct("TokenTransfer", {
  token_id: TokenIdBcs,
  recipient: AddressBcs,
  amount: AmountBcs,
  user_data: UserDataBcs,
});

const TokenCreationBcs = bcs.struct("TokenCreation", {
  token_name: bcs.string(),
  decimals: bcs.u8(),
  initial_amount: AmountBcs,
  mints: bcs.vector(AddressBcs),
  user_data: UserDataBcs,
});

const AddressChangeBcs = bcs.enum("AddressChange", {
  Add: null,
  Remove: null,
});

const TokenManagementBcs = bcs.struct("TokenManagement", {
  token_id: TokenIdBcs,
  update_id: NonceBcs,
  new_admin: bcs.option(AddressBcs),
  mints: bcs.vector(bcs.tuple([AddressChangeBcs, AddressBcs])),
  user_data: UserDataBcs,
});

const MintBcs = bcs.struct("Mint", {
  token_id: TokenIdBcs,
  recipient: AddressBcs,
  amount: AmountBcs,
});

const BurnBcs = bcs.struct("Burn", {
  token_id: TokenIdBcs,
  amount: AmountBcs,
});

const StateKeyBcs = bcs.bytes(32);
const StateBcs = bcs.bytes(32);

const StateInitializationBcs = bcs.struct("StateInitialization", {
  key: StateKeyBcs,
  initial_state: StateBcs,
});

const StateUpdateBcs = bcs.struct("StateUpdate", {
  key: StateKeyBcs,
  previous_state: StateBcs,
  next_state: StateBcs,
  compute_claim_tx_hash: bcs.bytes(32),
  compute_claim_tx_timestamp: bcs.u128(),
});

const ExternalClaimBodyBcs = bcs.struct("ExternalClaimBody", {
  verifier_committee: bcs.vector(AddressBcs),
  verifier_quorum: bcs.u64(),
  claim_data: bcs.vector(bcs.u8()),
});

const VerifierSigBcs = bcs.struct("VerifierSig", {
  verifier_addr: AddressBcs,
  sig: SignatureBcs,
});

const ExternalClaimBcs = bcs.struct("ExternalClaim", {
  claim: ExternalClaimBodyBcs,
  signatures: bcs.vector(VerifierSigBcs),
});

const StateResetBcs = bcs.struct("StateReset", {
  key: StateKeyBcs,
  reset_state: StateBcs,
});

const ValidatorConfigBcs = bcs.struct("ValidatorConfig", {
  // Note: in the Rust type this field uses a custom serde that always
  // serializes as a bech32m string, even in BCS. We match that here.
  address: bcs.string(),
  host: bcs.string(),
  rpc_port: bcs.u32(),
});

const CommitteeChangeBcs = bcs.struct("CommitteeChange", {
  new_committee: bcs.struct("CommitteeConfig", {
    validators: bcs.vector(ValidatorConfigBcs),
  }),
  epoch: bcs.u32(),
});

// --- Escrow types ---

const FixedAmountOrBpsBcs = bcs.enum("FixedAmountOrBps", {
  Fixed: AmountBcs, // variant 0
  Bps: bcs.u16(), // variant 1 — basis points 0–10000
});

const EscrowCreateConfigBcs = bcs.struct("EscrowCreateConfig", {
  token_id: TokenIdBcs,
  evaluator: AddressBcs,
  evaluation_fee: FixedAmountOrBpsBcs,
  min_evaluator_fee: AmountBcs,
});

const EscrowCreateJobBcs = bcs.struct("EscrowCreateJob", {
  config_id: bcs.bytes(32), // EscrowConfigId (transparent newtype)
  provider: AddressBcs,
  provider_fee: AmountBcs,
  description: bcs.string(), // max 1024 bytes
});

const EscrowSubmitBcs = bcs.struct("EscrowSubmit", {
  job_id: bcs.bytes(32), // EscrowJobId (transparent newtype)
  deliverable: bcs.fixedArray(32, bcs.u8()), // [u8; 32] raw hash
});

const EscrowRejectBcs = bcs.struct("EscrowReject", {
  job_id: bcs.bytes(32),
});

const EscrowCompleteBcs = bcs.struct("EscrowComplete", {
  job_id: bcs.bytes(32),
});

const EscrowBcs = bcs.enum("Escrow", {
  CreateConfig: EscrowCreateConfigBcs, // variant 0
  CreateJob: EscrowCreateJobBcs, // variant 1
  Submit: EscrowSubmitBcs, // variant 2
  Reject: EscrowRejectBcs, // variant 3
  Complete: EscrowCompleteBcs, // variant 4
});

// --- Operation enum (variant order must match Rust) ---

const OperationBcs = bcs.enum("Operation", {
  TokenTransfer: TokenTransferBcs, // 0
  TokenCreation: TokenCreationBcs, // 1
  TokenManagement: TokenManagementBcs, // 2
  Mint: MintBcs, // 3
  Burn: BurnBcs, // 4
  StateInitialization: StateInitializationBcs, // 5
  StateUpdate: StateUpdateBcs, // 6
  ExternalClaim: ExternalClaimBcs, // 7
  StateReset: StateResetBcs, // 8
  JoinCommittee: ValidatorConfigBcs, // 9
  LeaveCommittee: null, // 10 (unit variant)
  ChangeCommittee: CommitteeChangeBcs, // 11
  Escrow: EscrowBcs, // 12
});

// --- Transaction (Release20260407) ---

const TransactionBcs = bcs.struct("Transaction", {
  network_id: bcs.string(),
  sender: AddressBcs,
  nonce: NonceBcs,
  timestamp_nanos: bcs.u128(),
  claims: bcs.vector(OperationBcs), // Claims is a transparent Vec<Operation>
  archival: bcs.bool(),
  fee_token: bcs.option(TokenIdBcs),
});

// --- VersionedTransaction envelope ---

// IMPORTANT: The variant order determines the BCS variant index.
// Release20260319 = 0, Release20260407 = 1.
// We only define Release20260407 here since that's what we submit,
// but we need a placeholder for Release20260319 to keep the index correct.
//
// We use a dummy struct for the old version — we never serialize it.
const DummyRelease20260319 = bcs.struct("Release20260319", {
  _unused: bcs.u8(),
});

const VersionedTransactionBcs = bcs.enum("VersionedTransaction", {
  Release20260319: DummyRelease20260319, // variant 0 (placeholder)
  Release20260407: TransactionBcs, // variant 1
});

/** Inferred type for an Operation value accepted by the BCS serializer */
type Operation = Parameters<typeof OperationBcs.serialize>[0];

// ============================================================================
// Hex Helpers
// ============================================================================

function bytesToHex(bytes: Uint8Array): string {
  return nobleToHex(bytes);
}

function hexToBytes(hex: string): Uint8Array {
  return nobleFromHex(hex.startsWith("0x") ? hex.slice(2) : hex);
}

/**
 * Convert a whole-number FAST amount to the hex string expected by AmountBcs.
 * Example: fastToHex(100n) → hex representation of 100 * 10^18
 */
function fastToHex(wholeFast: bigint): string {
  return (wholeFast * ONE_FAST).toString(16);
}

// ============================================================================
// Operation ID computation
//
// config_id and job_id are derived as:
//   keccak256(sender_32bytes || nonce_u64_le || operation_index_u64_le)
// ============================================================================

function computeOperationId(
  sender: Uint8Array,
  nonce: number,
  operationIndex: number
): Uint8Array {
  const buf = new Uint8Array(32 + 8 + 8);
  buf.set(sender, 0);

  const view = new DataView(new ArrayBuffer(16));
  view.setBigUint64(0, BigInt(nonce), true); // nonce as u64 LE
  view.setBigUint64(8, BigInt(operationIndex), true); // index as usize (u64) LE
  buf.set(new Uint8Array(view.buffer), 32);

  return keccak_256(buf);
}

// ============================================================================
// Transaction Signing & Submission
// ============================================================================

/**
 * Build a Release20260407 transaction, sign it, and submit to the proxy REST API.
 *
 * Signing message = "VersionedTransaction::" ++ BCS(VersionedTransaction)
 * The signature and transaction are each hex-encoded BCS bytes in the JSON body.
 */
async function submitTransaction(
  privateKey: Uint8Array,
  publicKey: Uint8Array,
  nonce: number,
  operations: Operation[]
): Promise<{ data: any; status: number }> {
  // Build the transaction
  const tx = {
    network_id: NETWORK_ID,
    sender: publicKey,
    nonce,
    timestamp_nanos: BigInt(Date.now()) * 1_000_000n,
    claims: operations,
    archival: false,
    fee_token: null,
  };

  // BCS-serialize as VersionedTransaction::Release20260407
  const txBytes = VersionedTransactionBcs.serialize({
    Release20260407: tx,
  }).toBytes();

  // Sign: prefix "VersionedTransaction::" + BCS bytes
  const prefix = new TextEncoder().encode("VersionedTransaction::");
  const sigMsg = new Uint8Array(prefix.length + txBytes.length);
  sigMsg.set(prefix, 0);
  sigMsg.set(txBytes, prefix.length);
  const rawSig = ed.sign(sigMsg, privateKey);

  // BCS-serialize as SignatureOrMultiSig::Signature
  const sigBytes = SignatureOrMultiSigBcs.serialize({
    Signature: rawSig,
  }).toBytes();

  // POST to proxy REST API
  const res = await fetch(`${PROXY_URL}/v1/submit-transaction`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      transaction: bytesToHex(txBytes),
      signature: bytesToHex(sigBytes),
    }),
  });

  const body = await res.json();
  if (!res.ok || body.error) {
    throw new Error(
      `submit-transaction failed (${res.status}): ${JSON.stringify(body.error ?? body)}`
    );
  }
  // Small delay to let the proxy settle the transaction before the next call.
  await new Promise((r) => setTimeout(r, 1000));

  return { data: body.data, status: res.status };
}

// ============================================================================
// Proxy REST Helpers
// ============================================================================

async function getNextNonce(address: string): Promise<number> {
  const res = await fetch(`${PROXY_URL}/v1/accounts/${address}`);
  const body = await res.json();
  if (!res.ok) {
    // Fresh account — nonce is 0
    if (res.status === 404) return 0;
    throw new Error(`getAccountInfo failed: ${JSON.stringify(body)}`);
  }
  return body.data.next_nonce;
}

async function faucetDrip(recipientHex: string, wholeFast: bigint): Promise<void> {
  const rawAmount = (wholeFast * ONE_FAST).toString();
  const res = await fetch(`${PROXY_URL}/v1/faucet-drip`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ recipient: recipientHex, amount: rawAmount }),
  });
  const body = await res.json();
  if (!res.ok || body.error) {
    throw new Error(`faucet-drip failed: ${JSON.stringify(body.error ?? body)}`);
  }
}

async function getEscrowJobs(
  role: "client" | "provider" | "evaluator",
  addressHex: string,
  status: "Funded" | "Submitted" | "Completed" | "Refunded"
): Promise<any[]> {
  const url = `${PROXY_URL}/v1/escrow-jobs?${role}=${addressHex}&status=${status}`;
  const res = await fetch(url);
  const body = await res.json();
  if (!res.ok) throw new Error(`getEscrowJobs failed: ${JSON.stringify(body)}`);
  return body.data;
}

async function getEscrowJob(jobIdHex: string): Promise<any> {
  const res = await fetch(`${PROXY_URL}/v1/escrow-jobs/${jobIdHex}?certs=true`);
  const body = await res.json();
  if (!res.ok) throw new Error(`getEscrowJob failed: ${JSON.stringify(body)}`);
  return body.data;
}

// ============================================================================
// Main: End-to-End Escrow Flow
// ============================================================================

// ============================================================================
// Flow 1: Happy Path (Complete)
// ============================================================================

async function happyPathFlow() {
  console.log("========================================");
  console.log("  Flow 1: Happy Path (Complete)");
  console.log("========================================\n");

  // ---- Generate three keypairs ----

  const evaluatorPriv = ed.utils.randomPrivateKey();
  const evaluatorPub = ed.getPublicKey(evaluatorPriv);
  const evaluatorHex = bytesToHex(evaluatorPub);

  const clientPriv = ed.utils.randomPrivateKey();
  const clientPub = ed.getPublicKey(clientPriv);
  const clientHex = bytesToHex(clientPub);

  const providerPriv = ed.utils.randomPrivateKey();
  const providerPub = ed.getPublicKey(providerPriv);
  const providerHex = bytesToHex(providerPub);

  console.log(`Evaluator (Eve):  ${evaluatorHex}`);
  console.log(`Client (Alice):   ${clientHex}`);
  console.log(`Provider (Bob):   ${providerHex}\n`);

  // ---- Step 1: Fund the client ----
  // The client needs enough balance to cover provider_fee + evaluator_fee.
  // The evaluator needs no balance to create a config (CreateConfig is free).

  console.log("--- Step 1: Fund Client via Faucet ---");
  await faucetDrip(clientHex, 1000n);
  console.log("Funded Alice with 1000 FAST\n");

  // ---- Step 2: Evaluator creates an escrow config ----
  // The config defines the fee structure: 10% of provider_fee (1000 bps),
  // with a minimum evaluator fee of 1 FAST.

  console.log("--- Step 2: Evaluator Creates Config ---");
  const evalNonce = await getNextNonce(evaluatorHex);
  await submitTransaction(evaluatorPriv, evaluatorPub, evalNonce, [
    {
      Escrow: {
        CreateConfig: {
          token_id: FAST_TOKEN_ID,
          evaluator: evaluatorPub,
          evaluation_fee: { Bps: 1000 }, // 10%
          min_evaluator_fee: fastToHex(1n), // minimum 1 FAST
        },
      },
    },
  ]);

  // The config_id is deterministically derived from the transaction:
  //   config_id = keccak256(sender || nonce_le || claim_index_le)
  const configId = computeOperationId(evaluatorPub, evalNonce, 0);
  console.log(`Config ID:      ${bytesToHex(configId)}`);
  console.log("Evaluation fee: 10% (1000 bps), min 1 FAST\n");

  // ---- Step 3: Client creates and funds an escrow job ----
  // Alice creates a job offering Bob 100 FAST. The evaluator fee is computed
  // on-chain: max(100 * 10%, 1) = 10 FAST. Alice pays 110 FAST total.

  console.log("--- Step 3: Client Creates Escrow Job ---");
  const clientNonce = await getNextNonce(clientHex);
  await submitTransaction(clientPriv, clientPub, clientNonce, [
    {
      Escrow: {
        CreateJob: {
          config_id: configId,
          provider: providerPub,
          provider_fee: fastToHex(100n), // 100 FAST to provider
          description: "Build the landing page",
        },
      },
    },
  ]);

  const jobId = computeOperationId(clientPub, clientNonce, 0);
  console.log(`Job ID:         ${bytesToHex(jobId)}`);
  console.log("Provider fee:   100 FAST");
  console.log("Evaluator fee:  10 FAST (10% of 100)");
  console.log("Total locked:   110 FAST\n");

  // ---- Step 4: Provider discovers the job ----

  console.log("--- Step 4: Provider Polls for Jobs ---");
  const providerJobs = await getEscrowJobs("provider", providerHex, "Funded");
  console.log(`Found ${providerJobs.length} job(s) for provider:`);
  for (const j of providerJobs) {
    console.log(`  Job ${j.job_id}: status=${j.status}, provider_fee=${j.provider_fee}`);
  }
  console.log();

  // ---- Step 5: Provider submits a deliverable ----
  // The deliverable is a 32-byte hash commitment (e.g. SHA-256 of the actual work).

  console.log("--- Step 5: Provider Submits Deliverable ---");
  const deliverableHash = keccak_256(new TextEncoder().encode("landing-page-v1.zip"));
  const providerNonce = await getNextNonce(providerHex);
  await submitTransaction(providerPriv, providerPub, providerNonce, [
    {
      Escrow: {
        Submit: {
          job_id: jobId,
          deliverable: Array.from(deliverableHash),
        },
      },
    },
  ]);
  console.log(`Submitted deliverable: ${bytesToHex(deliverableHash)}\n`);

  // ---- Step 6: Evaluator reviews and completes the job ----
  // The evaluator queries for submitted jobs, reviews, and completes.

  console.log("--- Step 6: Evaluator Reviews Submitted Jobs ---");
  const evalJobs = await getEscrowJobs("evaluator", evaluatorHex, "Submitted");
  console.log(`Found ${evalJobs.length} job(s) for evaluator:`);
  for (const j of evalJobs) {
    console.log(`  Job ${j.job_id}: status=${j.status}`);
  }
  console.log();

  console.log("--- Step 7: Evaluator Completes Job ---");
  const evalNonce2 = await getNextNonce(evaluatorHex);
  await submitTransaction(evaluatorPriv, evaluatorPub, evalNonce2, [
    {
      Escrow: {
        Complete: {
          job_id: jobId,
        },
      },
    },
  ]);
  console.log("Job completed!");
  console.log("  -> Provider (Bob) receives 100 FAST");
  console.log("  -> Evaluator (Eve) receives 10 FAST\n");

  // ---- Step 8: Verify final state ----

  console.log("--- Step 8: Verify Final State ---");
  const finalJob = await getEscrowJob(bytesToHex(jobId));
  console.log(`Job ${finalJob.job.job_id}:`);
  console.log(`  Status:        ${finalJob.job.status}`);
  console.log(`  Provider fee:  ${finalJob.job.provider_fee}`);
  console.log(`  Evaluator fee: ${finalJob.job.evaluator_fee}`);
  console.log(`  Certificates:  ${finalJob.certificates?.length ?? 0}`);

  console.log("\n=== Happy path flow complete! ===\n");
}

// ============================================================================
// Flow 2: Early Rejection (Evaluator rejects before provider delivers)
// ============================================================================

async function earlyRejectionFlow() {
  console.log("========================================");
  console.log("  Flow 2: Early Rejection");
  console.log("  (Evaluator rejects before delivery)");
  console.log("========================================\n");

  // ---- Generate three keypairs ----

  const evaluatorPriv = ed.utils.randomPrivateKey();
  const evaluatorPub = ed.getPublicKey(evaluatorPriv);
  const evaluatorHex = bytesToHex(evaluatorPub);

  const clientPriv = ed.utils.randomPrivateKey();
  const clientPub = ed.getPublicKey(clientPriv);
  const clientHex = bytesToHex(clientPub);

  const providerPriv = ed.utils.randomPrivateKey();
  const providerPub = ed.getPublicKey(providerPriv);
  const providerHex = bytesToHex(providerPub);

  console.log(`Evaluator (Eve):  ${evaluatorHex}`);
  console.log(`Client (Alice):   ${clientHex}`);
  console.log(`Provider (Bob):   ${providerHex}\n`);

  // ---- Step 1: Fund the client ----

  console.log("--- Step 1: Fund Client via Faucet ---");
  await faucetDrip(clientHex, 1000n);
  console.log("Funded Alice with 1000 FAST\n");

  // ---- Step 2: Evaluator creates an escrow config ----

  console.log("--- Step 2: Evaluator Creates Config ---");
  const evalNonce = await getNextNonce(evaluatorHex);
  await submitTransaction(evaluatorPriv, evaluatorPub, evalNonce, [
    {
      Escrow: {
        CreateConfig: {
          token_id: FAST_TOKEN_ID,
          evaluator: evaluatorPub,
          evaluation_fee: { Bps: 1000 }, // 10%
          min_evaluator_fee: fastToHex(1n),
        },
      },
    },
  ]);

  const configId = computeOperationId(evaluatorPub, evalNonce, 0);
  console.log(`Config ID:      ${bytesToHex(configId)}`);
  console.log("Evaluation fee: 10% (1000 bps), min 1 FAST\n");

  // ---- Step 3: Client creates and funds an escrow job ----

  console.log("--- Step 3: Client Creates Escrow Job ---");
  const clientNonce = await getNextNonce(clientHex);
  await submitTransaction(clientPriv, clientPub, clientNonce, [
    {
      Escrow: {
        CreateJob: {
          config_id: configId,
          provider: providerPub,
          provider_fee: fastToHex(100n),
          description: "Build the landing page",
        },
      },
    },
  ]);

  const jobId = computeOperationId(clientPub, clientNonce, 0);
  console.log(`Job ID:         ${bytesToHex(jobId)}`);
  console.log("Provider fee:   100 FAST");
  console.log("Evaluator fee:  10 FAST (10% of 100)");
  console.log("Total locked:   110 FAST\n");

  // ---- Step 4: Evaluator rejects the job BEFORE provider submits ----
  // The evaluator can reject a Funded job at any time. This refunds the
  // provider_fee to the client. The evaluator still receives their fee.

  console.log("--- Step 4: Evaluator Rejects Job (before delivery) ---");
  const evalNonce2 = await getNextNonce(evaluatorHex);
  await submitTransaction(evaluatorPriv, evaluatorPub, evalNonce2, [
    {
      Escrow: {
        Reject: {
          job_id: jobId,
        },
      },
    },
  ]);
  console.log("Job rejected!");
  console.log("  -> Client (Alice) refunded 100 FAST (provider_fee)");
  console.log("  -> Evaluator (Eve) receives 10 FAST (evaluator_fee)");
  console.log("  -> Provider (Bob) receives nothing\n");

  // ---- Step 5: Verify final state ----

  console.log("--- Step 5: Verify Final State ---");
  const finalJob = await getEscrowJob(bytesToHex(jobId));
  console.log(`Job ${finalJob.job.job_id}:`);
  console.log(`  Status:        ${finalJob.job.status}`);
  console.log(`  Provider fee:  ${finalJob.job.provider_fee}`);
  console.log(`  Evaluator fee: ${finalJob.job.evaluator_fee}`);
  console.log(`  Deliverable:   ${finalJob.job.deliverable ?? "(none)"}`);
  console.log(`  Certificates:  ${finalJob.certificates?.length ?? 0}`);

  console.log("\n=== Early rejection flow complete! ===\n");
}

// ============================================================================
// Flow 3: Post-Delivery Rejection (Evaluator rejects after provider delivers)
// ============================================================================

async function postDeliveryRejectionFlow() {
  console.log("========================================");
  console.log("  Flow 3: Post-Delivery Rejection");
  console.log("  (Evaluator rejects after delivery)");
  console.log("========================================\n");

  // ---- Generate three keypairs ----

  const evaluatorPriv = ed.utils.randomPrivateKey();
  const evaluatorPub = ed.getPublicKey(evaluatorPriv);
  const evaluatorHex = bytesToHex(evaluatorPub);

  const clientPriv = ed.utils.randomPrivateKey();
  const clientPub = ed.getPublicKey(clientPriv);
  const clientHex = bytesToHex(clientPub);

  const providerPriv = ed.utils.randomPrivateKey();
  const providerPub = ed.getPublicKey(providerPriv);
  const providerHex = bytesToHex(providerPub);

  console.log(`Evaluator (Eve):  ${evaluatorHex}`);
  console.log(`Client (Alice):   ${clientHex}`);
  console.log(`Provider (Bob):   ${providerHex}\n`);

  // ---- Step 1: Fund the client ----

  console.log("--- Step 1: Fund Client via Faucet ---");
  await faucetDrip(clientHex, 1000n);
  console.log("Funded Alice with 1000 FAST\n");

  // ---- Step 2: Evaluator creates an escrow config ----

  console.log("--- Step 2: Evaluator Creates Config ---");
  const evalNonce = await getNextNonce(evaluatorHex);
  await submitTransaction(evaluatorPriv, evaluatorPub, evalNonce, [
    {
      Escrow: {
        CreateConfig: {
          token_id: FAST_TOKEN_ID,
          evaluator: evaluatorPub,
          evaluation_fee: { Bps: 1000 }, // 10%
          min_evaluator_fee: fastToHex(1n),
        },
      },
    },
  ]);

  const configId = computeOperationId(evaluatorPub, evalNonce, 0);
  console.log(`Config ID:      ${bytesToHex(configId)}`);
  console.log("Evaluation fee: 10% (1000 bps), min 1 FAST\n");

  // ---- Step 3: Client creates and funds an escrow job ----

  console.log("--- Step 3: Client Creates Escrow Job ---");
  const clientNonce = await getNextNonce(clientHex);
  await submitTransaction(clientPriv, clientPub, clientNonce, [
    {
      Escrow: {
        CreateJob: {
          config_id: configId,
          provider: providerPub,
          provider_fee: fastToHex(100n),
          description: "Build the landing page",
        },
      },
    },
  ]);

  const jobId = computeOperationId(clientPub, clientNonce, 0);
  console.log(`Job ID:         ${bytesToHex(jobId)}`);
  console.log("Provider fee:   100 FAST");
  console.log("Evaluator fee:  10 FAST (10% of 100)");
  console.log("Total locked:   110 FAST\n");

  // ---- Step 4: Provider submits a deliverable ----

  console.log("--- Step 4: Provider Submits Deliverable ---");
  const deliverableHash = keccak_256(new TextEncoder().encode("landing-page-draft.zip"));
  const providerNonce = await getNextNonce(providerHex);
  await submitTransaction(providerPriv, providerPub, providerNonce, [
    {
      Escrow: {
        Submit: {
          job_id: jobId,
          deliverable: Array.from(deliverableHash),
        },
      },
    },
  ]);
  console.log(`Submitted deliverable: ${bytesToHex(deliverableHash)}\n`);

  // ---- Step 5: Evaluator reviews and rejects the deliverable ----
  // The evaluator determines the work is unsatisfactory and rejects.
  // This refunds the provider_fee to the client. The evaluator still
  // receives their fee for the evaluation work.

  console.log("--- Step 5: Evaluator Reviews and Rejects ---");
  const evalJobs = await getEscrowJobs("evaluator", evaluatorHex, "Submitted");
  console.log(`Found ${evalJobs.length} submitted job(s) for evaluator`);

  const evalNonce2 = await getNextNonce(evaluatorHex);
  await submitTransaction(evaluatorPriv, evaluatorPub, evalNonce2, [
    {
      Escrow: {
        Reject: {
          job_id: jobId,
        },
      },
    },
  ]);
  console.log("Job rejected after delivery!");
  console.log("  -> Client (Alice) refunded 100 FAST (provider_fee)");
  console.log("  -> Evaluator (Eve) receives 10 FAST (evaluator_fee)");
  console.log("  -> Provider (Bob) receives nothing\n");

  // ---- Step 6: Verify final state ----

  console.log("--- Step 6: Verify Final State ---");
  const finalJob = await getEscrowJob(bytesToHex(jobId));
  console.log(`Job ${finalJob.job.job_id}:`);
  console.log(`  Status:        ${finalJob.job.status}`);
  console.log(`  Provider fee:  ${finalJob.job.provider_fee}`);
  console.log(`  Evaluator fee: ${finalJob.job.evaluator_fee}`);
  console.log(`  Deliverable:   ${finalJob.job.deliverable ?? "(none)"}`);
  console.log(`  Certificates:  ${finalJob.certificates?.length ?? 0}`);

  console.log("\n=== Post-delivery rejection flow complete! ===\n");
}

// ============================================================================
// Main
// ============================================================================

async function main() {
  console.log("=== FastSet Escrow Flow Examples ===\n");
  console.log(`Proxy:   ${PROXY_URL}`);
  console.log(`Network: ${NETWORK_ID}\n`);

  await happyPathFlow();
  await earlyRejectionFlow();
  await postDeliveryRejectionFlow();

  console.log("=== All escrow flows complete! ===");
}

main().catch((err) => {
  console.error("Error:", err.message ?? err);
  process.exit(1);
});
