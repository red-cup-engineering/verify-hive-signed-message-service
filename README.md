# @red-cup-engineering/verify-hive-signed-message-service

<!-- 561-group-standards:badges:start -->
[![Red Cup Engineering](https://img.shields.io/badge/561%20Group-Red%20Cup%20Engineering-c0392b)](https://github.com/red-cup-engineering)
[![License: MIT](https://img.shields.io/badge/license-MIT-c0392b)](LICENSE)
[![Indigenous data: CARE](https://img.shields.io/badge/Indigenous%20data-CARE-4b6f44)](https://github.com/red-cup-engineering/.github/blob/main/GOVERNANCE.md)
[![Tips welcome](https://img.shields.io/badge/tips-welcome-d4a017)](https://github.com/561-group/.github/blob/main/TIPS.md)
<!-- 561-group-standards:badges:end -->

Recovers or verifies a Hive Keychain `signBuffer` compact signature over
`message`, then confirms the signing public key is a live posting or
active authority for `account`, cross-read from two public Hive JSON-RPC
nodes.

## Operation

~~~js
export async function verifyHiveSignedMessage(request, options = {})
~~~

### Parameters

- request (@param {string} request.account Hive account name the signature claims to speak for.
 * @param {string} request.message The exact UTF-8 text that was signed (the pre-digest challenge).
 * @param {string} request.signature 130-character hex compact secp256k1 signature (Keychain `signBuffer` wire format: 1-byte recovery header + 64-byte R||S).
 * @param {string} [request.publicKey] An `STM...` Hive public key the caller expects the signature to belong to; when given, the signature is verified directly against it instead of recovered.
 * @param {string[]} [request.nodes] At least two Hive JSON-RPC node base URLs to cross-read the account from; defaults to two curated public nodes.
 * ): A HiveSignedMessageVerificationRequest.
- options ({transport?: (url: string, body: object) => Promise<{status: number, body: string}>}): `transport` overrides the underlying JSON-RPC HTTP call for tests; defaults to real HTTPS.

### Returns

Promise<{verified: true, account: string, publicKey: string, role: "posting"|"active"} | {verified: false, reason: string}>: 

## Command

verify-hive-signed-message reads one JSON value per input line and writes one JSON value per output line.

## Examples

### a malformed signature is refused before any network read

Input:

~~~json
{
  "account": "emsenn0",
  "message": "hello ops",
  "signature": "not-hex"
}
~~~

Output:

~~~json
{
  "verified": false,
  "reason": "signature must be a 130-character hex compact Hive signature"
}
~~~

### a missing account is refused before any signature or network work

Input:

~~~json
{
  "message": "hello ops",
  "signature": "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
}
~~~

Output:

~~~json
{
  "verified": false,
  "reason": "account must be a non-empty string"
}
~~~
