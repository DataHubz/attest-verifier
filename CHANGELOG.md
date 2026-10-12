# Changelog

## 1.4.1 (2026-10-12)

- Proof Cards verify in Firefox: the issuer's key is a compressed P-256 point, which Firefox's WebCrypto refuses to import (raw or in SPKI). The verifier decompresses it, checking the point is on the curve, before importing it. 1.1.0 to 1.4.0 report a genuine card's issuer signature as invalid in Firefox; Chromium and WebKit were not affected.

## 1.4.0 (2026-10-12)

A pinned trust root, and nothing taken on trust from the file being checked. TRUST.md describes the model and every attack it stops.

- The chain (Horizen, 26514), Attest's registries, the registry authority, the passkey site (attest.datahubz.com) and the circuits' verification keys are pinned in the verifier. Evidence can no longer name its own node, contract, relying party or verification key. Any node can be entered; its chain id is checked.
- An anchor counts only when its wallet is one of Attest's: registered on AttestRegistryV3 by the registry authority, and not revoked before the anchor. The registries are open to any wallet.
- Agreements need Attest's own anchor, `attest.agreement.v1`, which commits to the signed state and to every signer's statement, passkey key and signature: a receipt that any account could record for a forged state no longer suffices, and a swapped passkey key fails. Agreements completed before this release are anchored the same way.
- Signers' statements must name the agreement, the signer, the title and the time the signed state lists; the signed state must list exactly the evidence's signers. Names, titles and dates shown are the signed ones.
- Signed copies are read strictly: after the signed pages there must be exactly Attest's update attaching the evidence, the original and the verifier. A later update, a redefined page, a script, an annotation or any other addition fails, and the verifier offers the signed pages exactly as sealed. Attachments are taken only from that update.
- Zero-knowledge proofs are checked against the pinned keys. Proof statements are built from the checked public inputs.
- Analytics days need Attest's `attest.analytics.v1` anchor; certificates take their title, issuer and validity from the signed content and credential, and each signer's statement and key from the issuer's credential; Proof Cards need the issuer's key committed by an Attest wallet.
- Receipts show their description as the recording account's own text: the anchor covers the receipt and its fingerprint.
- The page runs only its own scripts (a Content Security Policy by hash), links only to the pinned explorer, and accepts one record at a time.
- Reads AttestRegistryV3 (anchors from October 12, 2026) and AttestRegistryV2, and evidence formats agreement v4 and v2 of the others.
- Agreements completed in September 2026, signed before passkeys, show their signers without a passkey signature instead of failing: Attest's anchor commits to that.

Affected versions: 1.0.0 to 1.3.0 take the chain node, the registry contract, the passkey site and the verification keys from the file being checked, and accept anchors from any wallet and bytes appended after a signed copy's evidence. A fabricated record could verify with them. Use 1.4.0.

## 1.3.0 (2026-10-10)

- Attest Analytics evidence: a sealed day's anchored summary, figures and commitments; each figure recounted from the records it committed to and each Merkle root recomputed; each committed anchor transaction read from the chain; inclusion proofs for a party's own records. Method in ANALYTICS.md.

## 1.2.0 (2026-10-10)

- Signed copies (evidence v3) authenticate their visible pages: the verifier hashes the PDF's pages, which come before the evidence (a PDF incremental update), and checks that exact hash is anchored as the agreement's signed copy by the wallet that anchored its signed state. Pages that were changed, or rebuilt around the same attachments, fail.
- Copies in evidence v1 and v2 say plainly that their visible pages are not covered, and how to check them.
- "The original document inside is exactly the one signed" replaces "The document is exactly the one signed", which could be read as covering the visible pages.

Affected versions: 1.0.0 and 1.1.0 report a PDF whose visible pages were altered, with its attachments intact, as verified: they authenticate the attachments only. Use 1.2.0.

## 1.1.0 (2026-10-10)

Reads every Attest record: signed agreements (v1, v2), receipts, certificates, Proof Cards and agreement proofs (v1 each).

- Receipts and scan proofs: file fingerprint, Merkle path, anchor, Groth16 proof and its binding to the receipt.
- Certificates: content, signers' passkeys, issuer signature (vc+jwt), issuer key on chain, PDF, anchor from the issuer's wallet, revocation read from the chain, findings-closure proof.
- Proof Cards: holder's passkey approval, selective-disclosure signature (ecdsa-sd-2023), signed status lists and their anchors, issuance anchor, current status read from the chain.
- Agreement proofs: Groth16, revealed people and completion day, anchored root. Proofs inside signed agreements are now checked in the page too.
- Issuer keys, revocations, card status changes and the cards context are checked by values anyone can recompute (FORMAT.md).
- Built from source with a reproducible build; libraries are bundled from the lockfile.
- The node field overrides the node named by the evidence; it no longer pins the first one used.

## 1.0.0 (2026-10-10)

First release. Reads evidence formats v1 and v2.

- Format v2: document, entries, statements, WebAuthn signatures, signed state, Merkle path and on-chain anchor.
- Format v1: statements and WebAuthn signatures; reports what the format does not carry.
- Reports newer formats and points to the latest release.
- Opt-in check for a newer version.
