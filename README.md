# Attest verifier

A standalone verifier for documents signed with [Attest](https://attest.datahubz.com). It checks a signed copy on your own device, using open standards and a public blockchain, with no Attest service involved.

Every Attest signed copy carries this verifier as an attachment, together with the original document and the evidence. This repository is its source and release history.

## What it checks

- The original document is exactly the one every signer signed (SHA-256).
- Each signer's entries match what they signed.
- Each signer's passkey signature (WebAuthn): the statement it signed names the document and the entries, it was made on Attest, with the user present and verified.
- The signed state covers the document and every signer, and its fingerprint is a leaf of the Merkle tree whose root was anchored.
- The anchoring transaction on Horizen records that root, read from a public node.
- Zero-knowledge proofs carry their Groth16 verification keys, for any Groth16 verifier.

The exact format and each check are specified in [FORMAT.md](FORMAT.md), so the checks can be reimplemented in any language.

## Use

1. Download `attest-verifier.html` from the latest release, or save the copy attached to a signed PDF (any PDF reader lists its attachments).
2. Open it in a current browser. It works from disk, offline, except the on-chain check, which reads one transaction from a public node of the anchor's chain. The node address can be changed on the page.
3. Drop the signed PDF on it. Alternatively, drop `attest-evidence.json` together with `original-document.pdf`.

The page makes no requests besides that on-chain read, and the opt-in "Check for a newer version" button, which reads the release manifest from attest.datahubz.com or this repository.

## Versions and compatibility

- Each release has a semantic version, shown on the page.
- Each release reads every earlier evidence format. A signed copy keeps the verifier that was current when it was made; it stays valid for that document because the document's evidence never changes.
- A verifier that meets a newer evidence format says so and points to the latest release.
- `latest.json` describes the current release: version, formats, SHA-256 and download URL.

## Authenticity of releases

Each release lists the SHA-256 of `attest-verifier.html`. That fingerprint is also recorded as an Attest receipt anchored on Horizen: drop the downloaded file on [attest.datahubz.com/verify](https://attest.datahubz.com/verify) to confirm it is the published release.

## Security

Report vulnerabilities to security@datahubz.com. Fixes are published as new releases with a note in [CHANGELOG.md](CHANGELOG.md) naming the affected versions.

## License

MIT. See [LICENSE](LICENSE).
