import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { verifyHiveSignedMessage } from "../scripts/verify-hive-signed-message.mjs";

const examples = [
  {
    "type": "JavascriptNodeOperationExample",
    "name": "a malformed signature is refused before any network read",
    "input": {
      "account": "emsenn0",
      "message": "hello ops",
      "signature": "not-hex"
    },
    "output": {
      "verified": false,
      "reason": "signature must be a 130-character hex compact Hive signature"
    }
  },
  {
    "type": "JavascriptNodeOperationExample",
    "name": "a missing account is refused before any signature or network work",
    "input": {
      "message": "hello ops",
      "signature": "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    },
    "output": {
      "verified": false,
      "reason": "account must be a non-empty string"
    }
  }
];

for (const example of examples) {
  test(example.name, async () => {
    const importedOutput = await verifyHiveSignedMessage(example.input);
    assert.deepEqual(importedOutput, example.output);
    const command = spawnSync(process.execPath, [fileURLToPath(new URL("../scripts/verify-hive-signed-message.mjs", import.meta.url))], {
      input: JSON.stringify(example.input) + "\n",
      encoding: "utf8",
    });
    assert.equal(command.status, 0, command.stderr);
    const commandOutput = JSON.parse(command.stdout.trim());
    assert.deepEqual(commandOutput, example.output);
    assert.deepEqual(commandOutput, importedOutput);
  });
}
