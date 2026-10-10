# Changelog

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
