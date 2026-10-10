# Attest agreement evidence format

An Attest signed copy is a PDF with files attached (PDF embedded files, listed by any PDF reader):

| Attachment | Content |
| --- | --- |
| `attest-evidence.json` | The evidence, in the format below |
| `original-document.pdf` | The document exactly as signed (format v2) |
| `attest-verifier.html` | The verifier that was current when the copy was made |

The certificate PDF that Attest serves for an agreement carries `attest-evidence.json` and `attest-verifier.html`, without the original document, which only the parties hold.

All fingerprints are SHA-256, lowercase hex. All text is UTF-8. Times are ISO 8601 in UTC.

## Format v2 (`attest.agreement_evidence.v2`)

Signed copies made from 2026-10-10.

```
format              "attest.agreement_evidence.v2"
agreementId         agreement identifier (agr_...)
title               agreement title
verificationCode    code printed on every signature stamp (8 characters, shown as ATT-XXXX-XXXX)
completedAt         completion time
document.sha256     fingerprint of the original document
document.file       "original-document.pdf"
webauthn.origin     origin the passkey assertions must name (https://attest.datahubz.com)
webauthn.rpId       relying party ID (attest.datahubz.com)
signers[]           one per signer:
  email, name, signedAt
  statement         the exact JSON text the signer's passkey signed
  entries           the exact text of the signer's entries (canonical JSON), or null if none
  entriesSha256     SHA-256 of entries
  passkey.publicKeySpki   public key, base64 SPKI
  passkey.alg             COSE algorithm: -7 (ES256), -257 (RS256) or -8 (EdDSA)
  webauthnAssertion.authenticatorData   base64url
  webauthnAssertion.clientDataJSON      base64url
  webauthnAssertion.signature           base64url (DER for ES256)
  signatureReceiptId      receipt anchoring this signature on its own
signedState.message  the exact signed-state text
signedState.sha256   its fingerprint (the anchored value)
anchor.chainId       EVM chain ID (26514: Horizen mainnet)
anchor.rpc           a public JSON-RPC endpoint for that chain
anchor.explorer      block explorer link to the transaction
anchor.contract      anchoring contract address
anchor.txHash        anchoring transaction
anchor.blockNumber   its block
anchor.receiptId     the signed state's receipt
anchor.leaf          SHA-256 of "<receiptId>:<signedState.sha256>"
anchor.leafIndex     the leaf's position in the batch
anchor.merkleProof   sibling hashes, bottom up
anchor.merkleRoot    the root the transaction records
proofs[]            zero-knowledge proofs about the agreement:
  id, statement, revealed, circuit
  proof, publicSignals, verificationKey   Groth16 (snarkjs JSON)
  zkverify.status, zkverify.txHash        verification on zkVerify
checks[]            the checks below, in plain words
online              live certificate URL
```

### Checks

1. **Document.** `SHA-256(original-document.pdf) == document.sha256`.
2. **Entries.** For each signer with entries: `SHA-256(entries) == entriesSha256`.
3. **Statement.** Each `statement` parses as JSON with `documentSha256 == document.sha256` and, when the signer has entries, `fieldsSha256 == entriesSha256`.
4. **Passkey signature (WebAuthn).** Decode `clientDataJSON`: `type == "webauthn.get"`, `challenge == base64url(SHA-256(statement))`, `origin == webauthn.origin`. `authenticatorData` begins with `SHA-256(webauthn.rpId)`, and its flags byte (offset 32) has user present (0x01) and user verified (0x04). The signature verifies over `authenticatorData || SHA-256(clientDataJSON)` with `passkey.publicKeySpki`. For ES256 the signature is DER-encoded and is converted to raw `r || s` for WebCrypto.
5. **Signed state.** `SHA-256(signedState.message) == signedState.sha256`, and the message (JSON) lists `document.sha256` and every signer with their entries fingerprint.
6. **Merkle path.** `node = SHA-256("<anchor.receiptId>:<signedState.sha256>")` (equals `anchor.leaf`). For each sibling in `anchor.merkleProof`: `node = SHA-256(min(node, sibling) || max(node, sibling))`, comparing the 32-byte values as lowercase hex strings and concatenating the bytes. The result equals `anchor.merkleRoot`. Batches with a single record have an empty path and `merkleRoot == leaf`.
7. **On chain.** `eth_getTransactionReceipt(anchor.txHash)` from any node of `anchor.chainId` has status `0x1` and a log emitted by `anchor.contract` whose `data` begins with `anchor.merkleRoot` (the `RootAnchored` event). The block's timestamp is when it was sealed.
8. **Zero-knowledge proofs.** `groth16 verify(verificationKey, publicSignals, proof)`, for example `npx snarkjs groth16 verify vk.json public.json proof.json`. Each proof is also verified on zkVerify (`zkverify.txHash`).

## Format v1 (`attest.agreement_evidence.v1`)

Signed copies made before 2026-10-10. It carries the signatures and the fingerprints, not the original document, the entries text, the signed state's text or the Merkle path.

```
format, agreementId, title, documentSha256, signedStateSha256, completedAt
anchor.chainId, anchor.txHash, anchor.explorer, anchor.receiptId
signers[]: email, name, signedAt, entriesSha256, consentJson (the signed statement),
           passkeyPublicKey, passkeyAlg, authenticatorData, clientDataJSON, signature, receiptId
proofs[]: id, revealed, zkverifyStatus, zkverifyTxHash
verify   live certificate URL
```

Checks 3 and 4 apply (with `consentJson` as the statement and the WebAuthn origin taken from `verify`). The original document can be checked against `documentSha256` by whoever holds it.

## Compatibility

The format's version changes only when fields are added or a check changes. Each verifier release reads every earlier format. A verifier that meets a newer format reports it and points to the latest release; it never reports such a document as failed.
