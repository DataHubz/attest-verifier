# Attest evidence formats

Every Attest record can be checked without Attest: its evidence holds everything needed, and anchors are read from a public node of the chain they are on.

| Format | Record | Where it comes from |
| --- | --- | --- |
| `attest.agreement_evidence.v1`, `v2`, `v3` | Signed agreement | Attached to every signed PDF |
| `attest.receipt_evidence.v1` | Receipt, scan proof | `/api/evidence/<rcpt_ or zk_ id>`, the receipt's page |
| `attest.certificate_evidence.v1` | Certificate | `/api/evidence/<cert_ id>`, the certificate's page |
| `attest.card_evidence.v1` | Shared Proof Card | `/api/evidence/<shr_ id>`, the shared card's page |
| `attest.proof_evidence.v1` | Agreement proof | `/api/evidence/<azk_ id>`, the proof's page |

Common definitions:

- Fingerprints are SHA-256, lowercase hex. Text is UTF-8. Times are ISO 8601 in UTC.
- `canonicalJson(x)`: JSON with object keys sorted, undefined members dropped, no whitespace.
- `isAnchored(v)`: an `eth_call` to the registry contract with selector `0x4f0b5801` and `v` as a bytes32. It returns `(bool anchored, uint256 timestamp, address anchorer)`.
- A Merkle anchor (`type: "merkle"`) is checked like agreement check 6 and 7 below: leaf `sha256("<receiptId>:<fingerprint>")`, sorted-pair SHA-256 up the path, the root in the transaction's `RootAnchored` log.
- An event anchor (`type: "event"`) commits `sha256("attest.event.v1|" + eventId + "|" + fingerprint)` in its transaction's log.
- A value anchor (`type: "value"`) commits the value itself in its transaction's log, and `isAnchored(value)` returns it.
- `P` is the BN254 scalar field order, `21888242871839275222246405745257275088548364400416034343698204186575808495617`.

## Values anyone can recompute

Organizations anchor these from their own wallet, so a verifier asks the chain directly, by value, without knowing any transaction:

| What | Value |
| --- | --- |
| An organization's issuer key | `sha256("attest.issuer_key.v1|" + did + "|" + publicKeyMultibase + "|" + canonicalJson(publicKeyJwk))` |
| A certificate's revocation | `sha256("attest.certificate.revoked.v2|" + certificateId)` |
| A Proof Card's n-th status change | `sha256("attest.card.status.v1|" + cardId + "|" + n + "|" + state)`, state `revoked`, `suspended` or `active`, n from 1 |
| A published JSON-LD context | `sha256("attest.context.v1|" + url + "|" + canonicalJson(document))`, from Attest's platform organization |
| A signed copy's visible pages | `sha256("attest.signed_copy.v1|" + agreementId + "|" + variant + "|" + sha256(visible bytes))`, variant `full` or `pages`, from the wallet that anchored the agreement's signed state |

The wallet that anchored an organization's issuer key is that organization's wallet; certificates, revocations and status changes anchored by the same wallet are its own. The issuer key's anchor time shows when the key was public: a key substituted later carries a later time and a different value.

# Signed agreements

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

## Format v3 (`attest.agreement_evidence.v3`)

Signed copies made from 2026-10-10 (after verifier 1.2.0). Format v2 plus:

```
visibleCopy.variant      "full" (with certificate pages) or "pages" (signed pages only)
visibleCopy.byteLength   length of the visible pages: the PDF's first bytes
visibleCopy.sha256       SHA-256 of those bytes
```

The signed copy is the visible pages, saved with a classic cross-reference table, followed by a PDF incremental update (ISO 32000, 7.5.6) that adds the three attachments and a catalog naming them. The visible pages' bytes are never rewritten.

9. **Visible pages.** `SHA-256(first visibleCopy.byteLength bytes of the PDF) == visibleCopy.sha256`, and `isAnchored(sha256("attest.signed_copy.v1|" + agreementId + "|" + variant + "|" + visibleCopy.sha256))` is true, from the wallet that sent `anchor.txHash`. A PDF whose pages were changed, or rebuilt around the same attachments, fails: its first bytes hash differently, and editing the evidence to match leaves a value that was never anchored.

Copies in formats v1 and v2 authenticate the original document inside them, not their visible pages.

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

# Receipts (`attest.receipt_evidence.v1`)

```
receipt.id, kind, sha256, claim, createdAt, supersededBy[]
anchor               a Merkle anchor (see above), or null while pending
zkProof              present for scan proofs (zk_): id, circuit, statement, proof, publicSignals,
                     verificationKey (Groth16, snarkjs JSON), zkverify{status, txHash}
online, verifier
```

1. **Content.** Optionally, `SHA-256(file) == receipt.sha256`.
2. **Anchor.** The Merkle anchor for `receipt.sha256` is in the transaction's log.
3. **Scan proof** (`security_scan_proof_v2`). Groth16 verifies; public signals are `[valid, scanCommitment, proofType, minSecurityScore, maxCriticalAllowed, maxHighAllowed]`; `receipt.sha256 == sha256("attest.scan.v2|" + scanCommitment)`; the predicate holds when `valid == "1"`.

# Certificates (`attest.certificate_evidence.v1`)

```
certificate          id, url, title, subject, issuedAt, validUntil, content, contentSha256, pdfSha256, vcJwt
issuer               name, did, didDocument (verificationMethod: Multikey and JsonWebKey2020 for the same P-256 key)
webauthn             origin, rpId
signers[]            name, role, signedAt, evidence{consentJson, authenticatorData, clientDataJSON, signature, publicKeySpki, alg}
anchor               value anchor of the issued certificate, from the organization's wallet
revocation           revokedAt, reason, anchor, or null
findingsClosure      commitment, proof, publicSignals, verificationKey, zkVerify, or null
chain                chainId, rpc, contract
```

1. **Content.** `sha256(canonicalJson(content)) == contentSha256`.
2. **Signers.** Each `consentJson` names `certificate == id` and `contentSha256`; the passkey assertion over it is valid (as agreement check 4).
3. **Issuer key.** `isAnchored` of the issuer key value (see above) gives its time and the organization's wallet.
4. **Issuer signature.** `vcJwt` is a JWS (ES256) by the key `kid` in the DID document; its payload names `issuer.id == did` and `credentialSubject.contentSha256 == contentSha256`.
5. **PDF.** Optionally, `SHA-256(pdf) == pdfSha256`.
6. **Anchor.** `sha256("attest.certificate.v1|" + id + "|" + pdfSha256 + "|" + sha256(vcJwt))` is in the anchor's transaction, sent by the same wallet that anchored the issuer key.
7. **Status.** `isAnchored(sha256("attest.certificate.revoked.v2|" + id))` from that wallet means revoked, at its time.
8. **Findings closure.** Groth16 verifies; `publicSignals[0] == commitment`; `publicSignals[1] == sha256("attest.certificate.findings|" + id) mod P`; the commitment, as 64 hex digits, equals `content.findingsClosure.commitment`.

# Proof Cards (`attest.card_evidence.v1`)

A shared Proof Card is a W3C Verifiable Credential 2.0 with a selective-disclosure proof (Data Integrity, `ecdsa-sd-2023`, P-256): the holder chose which fields to reveal, and each revealed field is covered by the issuer's signature.

```
shareId
credential           the shared (derived) credential
issuer               name, did, didDocument
issuance             baseSignatureSha256, anchor (Merkle or event)
statusLists[]        purpose, url, version, credential (Bitstring Status List, ecdsa-rdfc-2019), sha256, anchor
status               cardId, changes[] (n, state, value, anchor)
holderApproval       statementJson, publicKeySpki, alg, authenticatorData, clientDataJSON, signature, approvedAt
webauthn             origin, rpId
chain                chainId, rpc, contract
```

1. **Holder approval.** The statement names `credentialId == credential.id` and `disclosedSha256 == sha256(canonicalJson(credential))`; the holder's passkey assertion over it is valid.
2. **Context.** The Attest cards context (`https://attest.datahubz.com/contexts/cards/v1`) is never taken from the evidence: verifiers carry their own copy, and `isAnchored` of its context value confirms it is the published one. A context URL never changes content; changes are published at a new version URL.
3. **Issuer key.** As for certificates.
4. **Issuer signature.** The credential verifies with `ecdsa-sd-2023` using the DID document's Multikey; each status list credential verifies with `ecdsa-rdfc-2019`; the card's bit is clear in each list.
5. **Status list anchors.** `sha256(canonicalJson(list credential))` is in its anchor.
6. **Issuance anchor.** The base signature is the first element of the CBOR array in the proof value (multibase `u`, base64url, after the 3-byte header `d9 5d 01`); its SHA-256 is in the issuance anchor.
7. **Current status.** For n = 1, 2, ...: whichever of the three states has `isAnchored` true from the issuer's wallet is the state after the n-th change; stop at the first n with none. No change means active.

# Agreement proofs (`attest.proof_evidence.v1`)

```
proof                id, circuit, statement, revealed{party, counterparty, dateISO, day}, proof, publicSignals,
                     verificationKey, createdAt, zkverify{status, txHash}
root                 value (0x-hex), anchor (value anchor), or null anchor while pending
chain                chainId, rpc, contract
```

Public signals: `agreement_membership` is `[root, emailField(party), day, identitySalt]`; `agreement_with_party` is `[root, emailField(party), emailField(counterparty), day, identitySalt]`, with `emailField(e) = sha256(lowercase e) mod P`, `identitySalt = sha256("attest.identity.v1") mod P`, and `day` the UTC day number of the completion.

1. **Proof.** Groth16 verifies with the verification key.
2. **What it reveals.** The email fields, the day and the salt match the public signals.
3. **Root.** `isAnchored(root)`: the root commits to every completed agreement on Attest.
4. **zkVerify.** The proof is also verified on zkVerify (`zkverify.txHash`).

## Compatibility

A format's version changes only when fields are added or a check changes. Each verifier release reads every earlier format. A verifier that meets a newer format reports it and points to the latest release; it never reports such a record as failed.
