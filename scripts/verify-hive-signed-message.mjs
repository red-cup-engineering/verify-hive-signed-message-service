#!/usr/bin/env node
// Recovers or verifies a Hive Keychain `signBuffer` compact signature over a
// UTF-8 message (SHA-256 digest, per hive-tx's documented Keychain recovery
// recipe: https://github.com/mahdiyari/hive-tx/blob/master/docs/keys.html,
// observed 2026-09-05), then confirms the signing key is a live posting or
// active authority for the named Hive account by reading condenser_api's
// get_accounts independently from two public JSON-RPC nodes and refusing
// when they disagree. All secp256k1 point arithmetic, base58, and
// RIPEMD-160 come from the shared data capabilities. Hive key formatting stays
// in the client.
import { sha256 } from "@red-cup-engineering/cryptographic-computer-data-engineering-services-section/hash";
import { verify, recover } from "@red-cup-engineering/cryptographic-computer-data-engineering-services-section/secp256k1";
import { PublicKey } from "@red-cup-engineering/hive-blockchain-client-service/keys.mjs";
import { RpcClient, DEFAULT_NODES } from "@red-cup-engineering/hive-blockchain-client-service/rpc.mjs";
import { runJavascriptNodeOperation } from "@red-cup-engineering/javascript-node-services-section/operation";

const SIGNATURE_PATTERN = /^(0x)?[0-9a-fA-F]{130}$/;

function parseCompactSignature(signature) {
  if (typeof signature !== "string" || !SIGNATURE_PATTERN.test(signature)) {
    throw new Error("signature must be a 130-character hex compact Hive signature");
  }
  const hex = signature.startsWith("0x") || signature.startsWith("0X") ? signature.slice(2) : signature;
  const buffer = Buffer.from(hex, "hex");
  const header = buffer[0];
  const recovery = header >= 31 && header <= 34 ? header - 31 : header - 27;
  if (recovery < 0 || recovery > 3) throw new Error("signature header byte does not encode a valid recovery id");
  return { recovery, body: buffer.subarray(1) };
}

async function readAccountKeyAuths(rpc, account) {
  const [record] = await rpc.call("condenser_api.get_accounts", [[account]]);
  if (!record) throw new Error(`account "${account}" was not found`);
  return {
    posting: (record.posting?.key_auths ?? []).map(([key]) => key),
    active: (record.active?.key_auths ?? []).map(([key]) => key),
  };
}

function sameKeySet(left, right) {
  if (left.length !== right.length) return false;
  const a = [...left].sort();
  const b = [...right].sort();
  return a.every((key, index) => key === b[index]);
}

/**
 * Recovers or verifies a Hive Keychain `signBuffer` compact signature over
 * `message`, then confirms the signing public key is a live posting or
 * active authority for `account`, cross-read from two public Hive JSON-RPC
 * nodes.
 * @param {object} request A HiveSignedMessageVerificationRequest.
 * @param {string} request.account Hive account name the signature claims to speak for.
 * @param {string} request.message The exact UTF-8 text that was signed (the pre-digest challenge).
 * @param {string} request.signature 130-character hex compact secp256k1 signature (Keychain `signBuffer` wire format: 1-byte recovery header + 64-byte R||S).
 * @param {string} [request.publicKey] An `STM...` Hive public key the caller expects the signature to belong to; when given, the signature is verified directly against it instead of recovered.
 * @param {string[]} [request.nodes] At least two Hive JSON-RPC node base URLs to cross-read the account from; defaults to two curated public nodes.
 * @param {{transport?: (url: string, body: object) => Promise<{status: number, body: string}>}} [options] `transport` overrides the underlying JSON-RPC HTTP call for tests; defaults to real HTTPS.
 * @returns {Promise<{verified: true, account: string, publicKey: string, role: "posting"|"active"} | {verified: false, reason: string}>}
 */
export async function verifyHiveSignedMessage(request, options = {}) {
  try {
    if (request === null || typeof request !== "object" || Array.isArray(request)) {
      return { verified: false, reason: "request must be a JSON object" };
    }
    const { account, message, signature, publicKey, nodes } = request;
    if (typeof account !== "string" || account.length === 0) {
      return { verified: false, reason: "account must be a non-empty string" };
    }
    if (typeof message !== "string" || message.length === 0) {
      return { verified: false, reason: "message must be a non-empty string" };
    }
    const nodeList = Array.isArray(nodes) && nodes.length >= 2 ? nodes.slice(0, 2) : DEFAULT_NODES.slice(0, 2);

    let recoveryParse;
    try {
      recoveryParse = parseCompactSignature(signature);
    } catch (error) {
      return { verified: false, reason: error.message };
    }
    const digest = sha256(Buffer.from(message, "utf8"));

    let recoveredPublicKey;
    if (typeof publicKey === "string" && publicKey.length > 0) {
      let pub;
      try {
        pub = PublicKey.from(publicKey);
      } catch (error) {
        return { verified: false, reason: `publicKey is not a valid Hive public key: ${error.message}` };
      }
      if (!verify(digest, recoveryParse.body, pub.toBuffer())) {
        return { verified: false, reason: "signature does not verify against the provided publicKey" };
      }
      recoveredPublicKey = pub.toString();
    } else {
      let pub33;
      try {
        pub33 = recover(digest, recoveryParse.body, recoveryParse.recovery);
      } catch (error) {
        return { verified: false, reason: `could not recover a public key from the signature: ${error.message}` };
      }
      recoveredPublicKey = PublicKey.fromBuffer(pub33).toString();
    }

    let authorities;
    try {
      const [first, second] = await Promise.all(
        nodeList.map((node) => readAccountKeyAuths(new RpcClient({ nodes: [node], transport: options.transport }), account)),
      );
      if (!sameKeySet(first.posting, second.posting) || !sameKeySet(first.active, second.active)) {
        return { verified: false, reason: "the two Hive nodes disagree on the account's key authorities" };
      }
      authorities = first;
    } catch (error) {
      return { verified: false, reason: `could not read account authorities from Hive nodes: ${error.message}` };
    }

    if (authorities.posting.includes(recoveredPublicKey)) {
      return { verified: true, account, publicKey: recoveredPublicKey, role: "posting" };
    }
    if (authorities.active.includes(recoveredPublicKey)) {
      return { verified: true, account, publicKey: recoveredPublicKey, role: "active" };
    }
    return { verified: false, reason: "public key is not an authorized posting or active key for the account" };
  } catch (error) {
    return { verified: false, reason: error instanceof Error ? error.message : String(error) };
  }
}

if (import.meta.main) {
  const result = await runJavascriptNodeOperation({ name: "verify-hive-signed-message", description: "Recovers or verifies a Hive Keychain `signBuffer` compact signature over `message`, then confirms the signing public key is a live posting or active authority for `account`, cross-read from two public Hive JSON-RPC nodes.", operation: verifyHiveSignedMessage }, { arguments: process.argv.slice(2), standardInput: process.stdin, standardOutput: process.stdout });
  process.exitCode = result.exitCode;
}
