import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "node:crypto";
import { PrivateKey } from "@red-cup-engineering/hive-blockchain-client-service/keys.mjs";
import { sha256 } from "@red-cup-engineering/cryptographic-computer-data-engineering-services-section/hash";
import { verifyHiveSignedMessage } from "../scripts/verify-hive-signed-message.mjs";

// A throwaway key generated fresh for this test run via the house client's
// own PrivateKey/sign primitives — never a real WIF.
function throwawayKey() {
  while (true) {
    try {
      return new PrivateKey(randomBytes(32));
    } catch {
      // out-of-range scalar; try again.
    }
  }
}

function signMessage(key, message) {
  const digest = sha256(Buffer.from(message, "utf8"));
  return key.sign(digest).toString("hex");
}

function accountFixture(publicKeyString, { postingOverride, activeOverride } = {}) {
  return {
    posting: { key_auths: postingOverride ?? [[publicKeyString, 1]] },
    active: { key_auths: activeOverride ?? [[publicKeyString, 1]] },
  };
}

function transportFor(accountsByNode) {
  return async (url, envelope) => {
    const record = accountsByNode[url];
    const [[account]] = envelope.params;
    const found = record ? record[account] : undefined;
    return {
      status: 200,
      body: JSON.stringify({ jsonrpc: "2.0", id: envelope.id, result: [found ?? null] }),
    };
  };
}

const NODE_A = "https://node-a.example";
const NODE_B = "https://node-b.example";

test("verifies a posting-authority signature by recovering the public key", async () => {
  const key = throwawayKey();
  const pub = key.createPublic().toString();
  const message = JSON.stringify({ username: "emsenn0", type: "login", app: "ops.561.group", expiry: 1893456000, nonce: "abc" });
  const signature = signMessage(key, message);
  const transport = transportFor({
    [NODE_A]: { emsenn0: accountFixture(pub) },
    [NODE_B]: { emsenn0: accountFixture(pub) },
  });
  const result = await verifyHiveSignedMessage(
    { account: "emsenn0", message, signature, nodes: [NODE_A, NODE_B] },
    { transport },
  );
  assert.deepEqual(result, { verified: true, account: "emsenn0", publicKey: pub, role: "posting" });
});

test("verifies directly against a supplied publicKey without recovery", async () => {
  const key = throwawayKey();
  const pub = key.createPublic().toString();
  const message = "hello ops";
  const signature = signMessage(key, message);
  const transport = transportFor({
    [NODE_A]: { emsenn0: accountFixture(pub) },
    [NODE_B]: { emsenn0: accountFixture(pub) },
  });
  const result = await verifyHiveSignedMessage(
    { account: "emsenn0", message, signature, publicKey: pub, nodes: [NODE_A, NODE_B] },
    { transport },
  );
  assert.equal(result.verified, true);
  assert.equal(result.publicKey, pub);
});

test("names the active role when the key is only an active authority", async () => {
  const key = throwawayKey();
  const pub = key.createPublic().toString();
  const message = "active-role message";
  const signature = signMessage(key, message);
  const transport = transportFor({
    [NODE_A]: { emsenn0: accountFixture(pub, { postingOverride: [["STMotherposting", 1]], activeOverride: [[pub, 1]] }) },
    [NODE_B]: { emsenn0: accountFixture(pub, { postingOverride: [["STMotherposting", 1]], activeOverride: [[pub, 1]] }) },
  });
  const result = await verifyHiveSignedMessage(
    { account: "emsenn0", message, signature, nodes: [NODE_A, NODE_B] },
    { transport },
  );
  assert.equal(result.verified, true);
  assert.equal(result.role, "active");
});

test("refuses when the two nodes disagree on key_auths", async () => {
  const key = throwawayKey();
  const pub = key.createPublic().toString();
  const message = "disagreement message";
  const signature = signMessage(key, message);
  const transport = transportFor({
    [NODE_A]: { emsenn0: accountFixture(pub) },
    [NODE_B]: { emsenn0: accountFixture("STMdifferentkeyentirely00000000000000000000000000") },
  });
  const result = await verifyHiveSignedMessage(
    { account: "emsenn0", message, signature, nodes: [NODE_A, NODE_B] },
    { transport },
  );
  assert.equal(result.verified, false);
  assert.match(result.reason, /disagree/);
});

test("refuses a key that is not an authorized posting or active key", async () => {
  const key = throwawayKey();
  const otherKey = throwawayKey();
  const message = "unauthorized message";
  const signature = signMessage(key, message);
  const otherPub = otherKey.createPublic().toString();
  const transport = transportFor({
    [NODE_A]: { emsenn0: accountFixture(otherPub) },
    [NODE_B]: { emsenn0: accountFixture(otherPub) },
  });
  const result = await verifyHiveSignedMessage(
    { account: "emsenn0", message, signature, nodes: [NODE_A, NODE_B] },
    { transport },
  );
  assert.equal(result.verified, false);
  assert.match(result.reason, /not an authorized/);
});

test("refuses signature verification against the wrong supplied publicKey", async () => {
  const key = throwawayKey();
  const otherKey = throwawayKey();
  const message = "wrong key message";
  const signature = signMessage(key, message);
  const otherPub = otherKey.createPublic().toString();
  const result = await verifyHiveSignedMessage(
    { account: "emsenn0", message, signature, publicKey: otherPub, nodes: [NODE_A, NODE_B] },
    { transport: transportFor({}) },
  );
  assert.equal(result.verified, false);
  assert.match(result.reason, /does not verify/);
});

test("refuses a malformed signature string", async () => {
  const result = await verifyHiveSignedMessage(
    { account: "emsenn0", message: "hi", signature: "not-hex", nodes: [NODE_A, NODE_B] },
    { transport: transportFor({}) },
  );
  assert.equal(result.verified, false);
  assert.match(result.reason, /130-character hex/);
});

test("refuses a missing account", async () => {
  const result = await verifyHiveSignedMessage({ message: "hi", signature: "00".repeat(65) }, { transport: transportFor({}) });
  assert.equal(result.verified, false);
  assert.match(result.reason, /account must be/);
});

test("refuses when the account is not found on the nodes", async () => {
  const key = throwawayKey();
  const message = "no such account";
  const signature = signMessage(key, message);
  const result = await verifyHiveSignedMessage(
    { account: "no-such-account", message, signature, nodes: [NODE_A, NODE_B] },
    { transport: transportFor({ [NODE_A]: {}, [NODE_B]: {} }) },
  );
  assert.equal(result.verified, false);
  assert.match(result.reason, /could not read account authorities/);
});
