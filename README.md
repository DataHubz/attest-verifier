# Attest verifier

A standalone verifier for [Attest](https://attest.datahubz.com) records: signed agreements, receipts, certificates, Proof Cards and zero-knowledge proofs. It checks a record on your own device, using open standards and a public blockchain, with no Attest service involved.

Every Attest signed copy carries this verifier as an attachment, together with the original document and the evidence. Every other record has an evidence file on its page. This repository is the verifier's source and release history.

## What it checks

- **Signed agreements:** the pages you see, anchored as the agreement's signed copy (copies made from October 10, 2026); the original document inside; each signer's entries and passkey signature (WebAuthn); the signed state covering the document and every signer; its inclusion in the anchored Merkle root; the anchoring transaction; zero-knowledge proofs about the agreement.
- **Receipts:** a file against its recorded fingerprint; the Merkle path to the anchored root; the transaction. For scan proofs, the Groth16 proof and its binding to the receipt.
- **Certificates:** the content; each signer's passkey signature; the issuer's signature (W3C Verifiable Credential, JOSE); the issuer's key as committed on chain by the organization's wallet; the PDF; the anchor from that same wallet; revocation, read from the chain; the findings-closure proof.
- **Proof Cards:** the holder's passkey approval of the exact copy shared; the issuer's selective-disclosure signature (W3C Data Integrity, ecdsa-sd-2023); the issuer's key on chain; the signed status lists and their anchors; the issuance anchor; the current status, read from the chain.
- **Agreement proofs:** the Groth16 proof; the people and completion day it reveals; the anchored root it proves against.
- **Attest Analytics:** each sealed day's figures and summary as anchored; every figure recounted from the records it committed to, every root recomputed, every anchor read from the chain; or, for a party, that their agreement and signature are counted. The method is in [ANALYTICS.md](ANALYTICS.md).

Each format and check is specified in [FORMAT.md](FORMAT.md), so the checks can be reimplemented in any language.

## Use

1. Download `attest-verifier.html` from the latest release, or save the copy attached to a signed PDF (any PDF reader lists its attachments).
2. Open it in a current browser. It works from disk, offline, except the on-chain checks, which read from a public node of the record's chain. A node can be entered on the page.
3. Drop a signed PDF, or an evidence file (`attest-evidence-….json`) downloaded from a record's page. Add the original file or the certificate PDF to check it too.

The page makes no requests besides those on-chain reads, and the opt-in "Check for a newer version" button, which reads the release manifest from attest.datahubz.com or this repository.

## What the verifier carries itself

The libraries it uses are bundled into the file at build time, from the exact versions in `package-lock.json`: W3C Verifiable Credentials and Data Integrity (Digital Bazaar), snarkjs (Groth16), cborg. It also carries the JSON-LD contexts the records use, including the Attest cards context, and never takes a context from an evidence file: a substituted context could change what a credential's fields mean while its signature still verifies. Each Attest context's fingerprint is anchored on chain, and the verifier checks it.

## Build it yourself

```
npm ci
npm run build
shasum -a 256 attest-verifier.html
```

The build is reproducible: the same sources and lockfile produce the same bytes, so the fingerprint matches the release's.

## Versions and compatibility

- Each release has a semantic version, shown on the page.
- Each release reads every earlier evidence format. A signed copy keeps the verifier that was current when it was made; it stays valid for that document because the document's evidence never changes.
- A verifier that meets a newer evidence format says so and points to the latest release.
- `latest.json` describes the current release: version, formats, SHA-256 and download URL.

## Authenticity of releases

Each release lists the SHA-256 of `attest-verifier.html`. That fingerprint is also recorded as an Attest receipt anchored on Horizen: drop the downloaded file on [attest.datahubz.com/verify](https://attest.datahubz.com/verify) to confirm it is the published release, or rebuild it from source.

## Security

Report vulnerabilities to contact@datahubz.com. Fixes are published as new releases with a note in [CHANGELOG.md](CHANGELOG.md) naming the affected versions.

## License

MIT. See [LICENSE](LICENSE). Bundled libraries keep their own licenses, listed at the end of the built file.
