# Attest evidence formats

Every Attest record can be checked without Attest: its evidence holds everything needed, and anchors are read from a public node of Base, where Attest anchors, or, for anchors made on Horizen until it stopped on November 5, 2026, proven from Horizen's state against Base (see "Base and Horizen" below). What a verifier must pin, and why, is in [TRUST.md](TRUST.md).

| Format | Record | Where it comes from |
| --- | --- | --- |
| `attest.agreement_evidence.v1` to `v7` | Signed agreement, its certificate (v5 to v7) | Attached to every signed PDF and agreement certificate |
| `attest.receipt_evidence.v1` to `v3` | Receipt, scan proof | `/api/evidence/<rcpt_ or zk_ id>`, the receipt's page |
| `attest.certificate_evidence.v1` to `v3` | Certificate | `/api/evidence/<cert_ id>`, the certificate's page |
| `attest.card_evidence.v1` to `v3` | Shared Proof Card | `/api/evidence/<shr_ id>`, the shared card's page |
| `attest.proof_evidence.v1` to `v3` | Agreement proof | `/api/evidence/<azk_ id>`, the proof's page |
| `attest.analytics_evidence.v1` to `v3` | Sealed Analytics days | The Analytics dashboard (full), or a completed agreement (inclusion) |

The v2 formats (v4 for agreements), from October 12, 2026, name each anchor's registry (`contract`) and wallet (`from`) where a verifier needs the wallet to ask AttestRegistryV3. The checks are the same for every version, under the trust root below. The v3 formats (v7 for agreements) add anchors on Base and a proof of Horizen's state ("Base and Horizen" below).

Common definitions:

- Fingerprints are SHA-256, lowercase hex. Text is UTF-8. Times are ISO 8601 in UTC.
- `canonicalJson(x)`: JSON with object keys sorted, undefined members dropped, no whitespace.
- **The trust root** (pinned by the verifier, never read from evidence): Base, chain id 8453, with AttestRegistryV3 `0xa4B9c8FaEcF6adAed5bDc6136D3AB55F8791B80e` (anchors from November 2026); Horizen, chain id 26514, with AttestRegistryV3 `0xF44Ed281005c7d506Dc50829a3E24655837FBF75` and AttestRegistryV2 `0x0C6a7918e2f8C28C4bb5Cf8d0f4CE27e9B30fa2A` (anchors until October 12, 2026), and where Horizen settles on Base: OptimismPortal `0x78e794d10a355468A0e7A14AA1a9F9A253D78784`, DisputeGameFactory `0x4e2c464380Fb26b0C5f9B90EDF754c4E2a8d1A90`, game type 1; the registry authority `0x23ACBF52e76EE9502174442c87c3cD47c68f44e7`; the passkey relying party `attest.datahubz.com` and origin `https://attest.datahubz.com`; the Groth16 verification keys of Attest's circuits.
- `anchoredAt(w, v)` on AttestRegistryV3 (selector `0xf8c2919d`) returns when wallet `w` anchored `v`, or 0. `isAnchored(v)` on AttestRegistryV2 (selector `0x4f0b5801`) returns `(bool anchored, uint256 timestamp, address anchorer)`.
- **An Attest anchor** of `v` by wallet `w`: `anchoredAt(w, v) > 0` on V3, or `isAnchored(v)` on V2 with anchorer `w`; and `w` is Attest's: `registeredAt(w) > 0` on V3 of the same chain (selector `0xaaea3d9c`), with `revokedAt(w)` (selector `0x1947aee4`) zero or after the anchor. An anchor whose transaction the evidence names is on the chain its `chainId` names (Horizen when it names none); a value with no transaction (an issuer key, a revocation, a status change, a context, a verifier build, an agreement or its pages) is looked up on Base, then on Horizen. The registries are open to any wallet: an anchor from an unregistered wallet is not Attest's.
- A Merkle anchor (`type: "merkle"`): leaf `sha256("<receiptId>:<fingerprint>")`, sorted-pair SHA-256 up the path to the root, which must be an Attest anchor; its transaction (`txHash`) names the wallet and records the root in its log (V3 `Anchored`, the value in `topics[3]`; V2 `RootAnchored`, the root at the start of `data`).
- An event anchor (`type: "event"`): `sha256("attest.event.v1|" + eventId + "|" + fingerprint)`, an Attest anchor from the wallet in `from`.
- A value anchor (`type: "value"`): the value itself, an Attest anchor from the wallet in `from` (or found on V2).
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
| A completed agreement | `sha256("attest.agreement.v1|" + agreementId + "|" + signedState.sha256 + "|" + S)`, from the creator's wallet, where `S` is the SHA-256 of the JSON array of `[lowercase email, statement, publicKeySpki, alg, authenticatorData, clientDataJSON, signature]` for every signer (missing values as `""`, a missing alg as `null`), sorted by email |
| A completed agreement (protocol v5) | `sha256("attest.agreement.v2|" + agreementId + "|" + signedState.sha256 + "|" + S + "|" + sha256(details))`, from the creator's wallet, where `S` is as above with each signer's commitment in place of their email, sorted by commitment |
| A verifier build Attest served | `sha256("attest.verifier.v1|" + version + "|" + sha256(file))`, version from the build's `const VERIFIER = { version: "x.y.z"` or `unversioned`, from Attest's platform organization (TRUST.md) |
| A sealed Analytics day | `sha256("attest.analytics.v1|" + day + "|" + scope + "|" + sha256)`, with `day` and `scope` from the anchored summary, from the wallet that recorded its receipt |

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
3. **Statement.** Each `statement` parses as JSON with `agreementId`, `documentSha256 == document.sha256`, `signer` (the signer's lowercase email), the signed state's `title`, the `signedAt` the signed state lists for that signer and, when the signer has entries, `fieldsSha256 == entriesSha256`. The names shown are the statements' `name`.
4. **Passkey signature (WebAuthn), on Attest's site.** Decode `clientDataJSON`: `type == "webauthn.get"`, `challenge == base64url(SHA-256(statement))`, `origin == "https://attest.datahubz.com"` (pinned, whatever `webauthn` says), not `crossOrigin`. `authenticatorData` begins with `SHA-256("attest.datahubz.com")`, and its flags byte (offset 32) has user present (0x01) and user verified (0x04). The signature verifies over `authenticatorData || SHA-256(clientDataJSON)` with `passkey.publicKeySpki`. For ES256 the signature is DER-encoded and is converted to raw `r || s` for WebCrypto.
5. **Signed state.** `SHA-256(signedState.message) == signedState.sha256`, and the message (JSON) names `agreementId`, `document.sha256` and exactly the evidence's signers, each with their `signedAt` and entries fingerprint.
6. **Merkle path.** `node = SHA-256("<anchor.receiptId>:<signedState.sha256>")` (equals `anchor.leaf`). For each sibling in `anchor.merkleProof`: `node = SHA-256(min(node, sibling) || max(node, sibling))`, comparing the 32-byte values as lowercase hex strings and concatenating the bytes. The result equals `anchor.merkleRoot`. Batches with a single record have an empty path and `merkleRoot == leaf`.
7. **On chain.** `eth_getTransactionReceipt(anchor.txHash)` from a node of Horizen (chain 26514; `anchor.chainId` must be 26514) has status `0x1`, was sent to one of Attest's registries, and its log records `anchor.merkleRoot`. Its sender `W` must be an Attest wallet, and the root an Attest anchor by `W` (see the definitions above). The anchor's time is when the signed state was recorded.
8. **Zero-knowledge proofs.** `groth16 verify(verificationKey, publicSignals, proof)` with the verification key Attest publishes for the circuit (the verifier carries its own copy and ignores the one in the evidence), for example `npx snarkjs groth16 verify vk.json public.json proof.json`. The root it proves against is an Attest anchor (`proofs[i].root.anchor` names its wallet). Each proof is also verified on zkVerify (`zkverify.txHash`).
9. **Attest's anchor of the agreement.** The agreement value (see "Values anyone can recompute") is an Attest anchor by `W`. A receipt proves only that a fingerprint was recorded, by any account; this value is made only by Attest's completion of this agreement, and it commits to every signer's statement, passkey public key and signature.

## Format v3 (`attest.agreement_evidence.v3`)

Signed copies made from 2026-10-10 (after verifier 1.2.0). Format v2 plus:

```
visibleCopy.variant      "full" (with certificate pages) or "pages" (signed pages only)
visibleCopy.byteLength   length of the visible pages: the PDF's first bytes
visibleCopy.sha256       SHA-256 of those bytes
```

The signed copy is the visible pages, saved with a classic cross-reference table, followed by a PDF incremental update (ISO 32000, 7.5.6) that adds the three attachments and a catalog naming them. The visible pages' bytes are never rewritten.

10. **Visible pages.** `SHA-256(first visibleCopy.byteLength bytes of the PDF) == visibleCopy.sha256`, and the signed copy value is an Attest anchor by `W`. A PDF whose pages were changed, or rebuilt around the same attachments, fails: its first bytes hash differently, and editing the evidence to match leaves a value that was never anchored.
11. **Nothing after the pages but Attest's attachments.** The bytes after the visible pages are exactly one incremental update: its cross-reference section lists exactly the objects between the pages and it, all in use; its trailer has only `/Size`, `/Root` (the pages' catalog), `/Info` and `/ID` (the pages' own) and `/Prev` (the pages' cross-reference table); `startxref` and `%%EOF` end the file. Its objects are the catalog (same number, every entry as before, plus `/Names` with `/EmbeddedFiles`, every earlier name kept, and `/AF` listing the attachments after any earlier entries), one name tree leaf, and for each attachment a file specification (`/Type /Filespec`, `/F` and `/UF` equal, optional `/Desc`, `/AFRelationship /Data`, `/EF`) and an embedded file stream (`/Type /EmbeddedFile`, optional `/Subtype`, optional `/Filter /FlateDecode`, `/Length`, `/Params << /Size >>`). The attachments are `attest-evidence.json`, `original-document.pdf` and `attest-verifier.html`, each at most once. Anything else (another update, a page redefined, a script or open action, an annotation, a comment) means the file was changed after it was sealed: a PDF reader could show it over the signed pages. The signed pages themselves can still be saved exactly as sealed.

## Format v4 (`attest.agreement_evidence.v4`)

Signed copies made from 2026-10-12. Format v3, with each proof's `root` (`value`, `anchor` with `txHash` and `from`) and the check list above. Anchors may be on AttestRegistryV3.

Copies in formats v1 and v2 authenticate the original document inside them, not their visible pages. Copies in formats v3 and v4 authenticate their visible pages as anchored when sealed; copies in formats v5 and v6 also re-make them from what was signed.

## Format v5 (`attest.agreement_evidence.v5`)

Signed copies made from 2026-10-12 with protocol v5. The visible pages are re-made by the verifier from what was signed, and the record names people only by name.

```
format              "attest.agreement_evidence.v5"
agreementId, title, verificationCode, completedAt
document.sha256, document.file
signers[]           in the order of details.signers:
  name              the name the signer's statement carries
  commitment        sha256("attest.signer.v1|" + salt + "|" + lowercase email); the salt is the parties' own
  signedAt
  statement         the exact JSON text the signer's passkey signed (statement v3, below)
  entries, entriesSha256, passkey, webauthnAssertion      as in v2
signedState         message (signed state v3, below) and sha256
anchor              as in v2
details             canonical JSON (below), exactly as Attest's agreement anchor v2 binds it
trail               the audit trail up to completion, canonical JSON of [[type, at, name or null], ...],
                    whose SHA-256 the details name (null in the certificate)
visibleCopy         variant ("full", "pages" or "certificate"), byteLength, sha256 as in v3, and renderer "attest.render.v2"
proofs              [] (zero-knowledge proofs reveal a party's email, so each party shares them from the proof's own page)
checks[], online
```

No email and no salt appears anywhere in the copy, its evidence or its pages.

**Statement v3** (the JSON the passkey signs, keys in this order): `v` (3), `statement`, `agreementId`, `title`, `documentSha256`, `fieldsSha256` (when the signer has entries), `layoutSha256`, `signer` (the commitment), `encryptionKey` (when the signer has an encryption key: `sha256("attest.signer_key.v1|" + salt + "|" + key fingerprint)`), `name`, `signedAt`, `nonce`. `layoutSha256` is the SHA-256 of the JSON array `[[id, type, page, x, y, w, h], ...]` of the signer's fields, sorted by id: where their entries appear.

**Signed state v3:** `{"kind":"attest.agreement_completion.v3","agreementId","title","documentSha256","signers":[{"signer","signedAt","fieldsSha256","statementSha256"}, ...]}`, signers sorted by commitment, `statementSha256` the SHA-256 of that signer's statement.

**Details:** canonical JSON (keys sorted, no spaces) of `{v: 1, renderer: "attest.render.v2", verifyCode, completedAt, signers: [commitment, ...], fields: [[id, type, page, x, y, w, h, commitment], ...] sorted by id, trailSha256}`: everything the pages print beyond the signed state and the signatures. The audit trail it names by `trailSha256` is the parties' own: a signed copy carries it, the certificate anyone can download doesn't.

### Checks

1. **Document.** As v2.
2. **Entries.** As v2.
3. **Statement.** `v == 3`; it names `agreementId`, `document.sha256`, the signed state's `title`, the signer's `commitment`, the `signedAt` and `fieldsSha256` the signed state lists for that commitment (`fieldsSha256 == entriesSha256`), and `layoutSha256` equals the SHA-256 of that signer's fields in `details` (first seven values of each, sorted by id).
4. **Passkey signature.** As v2.
5. **Signed state v3.** `SHA-256(signedState.message) == signedState.sha256`; the message names `agreementId`, `document.sha256` and exactly the evidence's commitments, each with the SHA-256 of their statement.
6. **Merkle path** and 7. **On chain**, as v2.
8. **Details.** `details` is canonical JSON with renderer `attest.render.v2`, its `signers` are exactly the evidence's commitments, and every field belongs to one of them. A signed copy's `trail` hashes to `details.trailSha256`.
9. **Attest's anchor of the agreement (v2).** The protocol v5 agreement value (see "Values anyone can recompute") is an Attest anchor by `W`: it commits to every signer's statement, passkey key and signature, and to `details`.
10. **The visible pages, re-made.** Renderer `attest.render.v2` (`src/renderer/v2.ts`, deterministic: the same input gives the same bytes in every engine) makes the pages from `original-document.pdf`, `visibleCopy.variant`, the origin `https://attest.datahubz.com`, the agreement (`agreementId`, the signed state's `title`, `document.sha256`, `signedState.sha256`, `anchor.txHash`), `details`, `trail` (the full variant prints it), each signer's commitment, the `name` in their statement and the `signedAt` in the signed state, and every signer's entries. The result must be byte for byte the first `visibleCopy.byteLength` bytes of the PDF. Every input is signed by a passkey or anchored by Attest, so pages that show anything else fail, and the verifier offers the pages as signed.
11. **The pages were anchored when sealed** (`attest.signed_copy.v1`, from `W`; required, and reported as not yet anchored until it is), and **nothing follows them but Attest's attachments** (check 11 of v3).
12. **The attached verifier** is a build Attest served: its verifier value is anchored by the platform wallet.

The renderer draws nothing that runs or attaches: it visits every object reachable from the original's trailer; removes the keys `AA`, `OpenAction`, `AF`, `EF`, `Collection`, `XFA`, `JS` and `Base`, the `JavaScript` and `EmbeddedFiles` name trees, every reference (a dictionary entry or an array element) to an action of type JavaScript, Launch, SubmitForm, ImportData, ResetForm, Rendition, Sound, Movie, GoToE, GoToR, Hide, SetOCGState, RichMediaExecute, Trans or GoTo3DView, to a URI action whose address (with control characters and spaces removed) doesn't start with `http:`, `https:` or `mailto:`, to a Named action other than NextPage, PrevPage, FirstPage and LastPage, to any action under `/A`, `/PA` or `/Next` other than GoTo, Thread, such a URI or such a Named action, to an annotation of subtype FileAttachment, RichMedia, Screen, Movie, Sound or 3D, and to an embedded file, reading every name, address and subtype through indirect references; draws; drops every object nothing reachable refers to; and fails if any of these is left. A signature's stamp is at least 120 by 30 points, grown about its field's center within the page.

### The certificate (format v5)

The certificate PDF that Attest serves for a v5 agreement, to anyone allowed to see it, is renderer `attest.render.v2`'s variant `certificate`: the certificate pages alone (each signer's stamp with their name, no document, entries or audit trail), followed by one incremental update attaching `attest-evidence.json` and `attest-verifier.html`. Its evidence is format v5 with `visibleCopy.variant` `certificate`, `trail: null` and no original document. Checks 3 to 10 apply, check 10 re-making the certificate's pages from the same inputs without the document or the entries; the certificate has no sealing anchor of its own.

### Attached files

A reader lists every file a PDF's file specifications attach (`/EF`), whatever its name or first bytes. The verifier finds them the same way and requires: in a strictly read signed copy or certificate, `attest-verifier.html` is a verifier build Attest anchored, and any file the signed pages carry themselves is reported; in any other PDF with Attest evidence, every attached file other than the evidence and one PDF (the document) is a verifier build Attest anchored.

## Format v6 (`attest.agreement_evidence.v6`)

Signed copies and certificates of agreements completed with renderer v3, from its release (verifier 1.6.0) on. Format v5 in every field and check, with renderer `attest.render.v3` in place of `attest.render.v2`: `details.renderer` and `visibleCopy.renderer` are `attest.render.v3`, and check 10 re-makes the pages with `src/renderer/v3.ts`, from the same inputs. A v5 record must name renderer v2 and a v6 record renderer v3. The completion details record the renderer and Attest's agreement anchor binds them, so an agreement keeps the renderer it was completed with: copies of agreements completed with renderer v2 stay format v5, whenever they are sealed.

Renderer v3 is renderer v2 with these changes. First, each page is drawn as it is shown, and its own content can't change how anything after it is drawn:

- **The page as shown.** The fields' `x, y, w, h` in `details.fields` are fractions of the page as a reader shows it (pdf.js, which the sender's and signer's pages draw it with), from its top left: the CropBox within the MediaBox (each taken from the page or the nearest ancestor that has it, as four numbers in either order, with an area; a missing or invalid MediaBox is Letter, a CropBox outside the MediaBox is the MediaBox), turned clockwise by `/Rotate` (a multiple of 90, from the page tree, otherwise 0), at `/UserUnit` points per unit. Everything Attest draws on a page (stamps, entries, the seal line) is drawn upright on that shown page, in points: one `cm` maps it to the page's own coordinates, `[k 0 0 k x0 y0]`, `[0 k -k 0 x1 y0]`, `[-k 0 0 -k x1 y1]` or `[0 -k k 0 x0 y1]` for 0, 90, 180 or 270 degrees, with `k = 1 / UserUnit` and `x0 y0 x1 y1` the shown box.
- **Every document, in two tiers.** Renderer v3 makes a copy of every document and never throws on one. Its check (`documentProblemsV3`) only classifies the document as clean or not, and the verifier runs the same check on the original to say which.
  - Every document: the original, attached to the copy exactly as signed (`original-document.pdf`), with its anchored fingerprint. The verifier offers it as signed.
  - A clean document: its copy shows each page exactly as the signer saw it (pdf.js, which the sender's and signer's pages draw it with, for print, with its own JavaScript image decoders and standard fonts), with Attest's layer on top, in every reader Attest tests (pdf.js, PDFium, MuPDF, Poppler, Ghostscript and Apple PDFKit). Each page's content, its streams decoded and joined as pdf.js joins them, is drawn unchanged as one form XObject, `/AttestPage`, with the page's resources and its MediaBox as its bounding box; the page's content is `q /AttestPage Do Q`, then Attest's drawing, with resources of its own. Readers draw a form with its own graphics state (transform, clip, colours, line and text state, soft mask and every other ExtGState parameter), so nothing the page's content sets can move, hide or stretch what follows.
  - A document that isn't clean: its copy gets the best protection renderer v3 can give (below), and carries the note "Some PDF readers may display parts of this document differently. Attest's verifier shows exactly what was signed." at the foot of every page of the document (5 points, above the seal line) and on the certificate of completion, after its opening paragraph. The verifier says the same when it verifies such a copy, and never says that copy's pages look the same in every reader.
- **Encrypted documents.** A document encrypted with the standard security handler and an empty user password (an owner password only, as government forms are protected) is decrypted first, exactly as pdf.js decrypts it when it opens it for the signer (`src/renderer/decrypt-v3.ts`, following pdf.js's CipherTransformFactory step for step): RC4 of 40 to 128 bits (V 1 and 2), RC4 or AES-128 through crypt filters (V 4: CFM V2 or AESV2, Identity and None), and AES-256 (V 5, revisions 5 and 6). Every string and stream of every indirect object is decrypted with that object's key, except the encryption dictionary and what it refers to, cross-reference streams, and the objects inside an object stream (the object stream itself is decrypted); a stream whose first filter is Crypt is decrypted with the crypt filter it names (Identity by default), and an embedded file with EFF. AES padding is removed as pdf.js removes it, from the last block of a stream fed 512 bytes at a time. The decrypted document then goes through the same check and the same drawing as any other, so it is clean when its content is; the copy carries no encryption, so every reader opens it the same way. MD5, SHA-256/384/512, RC4 and AES are plain JavaScript, so every engine decrypts to the same bytes. A document pdf.js opens only with a user password, or whose encryption pdf.js doesn't open (another security handler, V 3, an unknown crypt method), isn't clean, and its copy shows the page described below.
- **Clean.** A document is clean only when all of these hold:
  - Content: every content stream any reader runs (the pages' content, form XObjects, tiling pattern cells, Type 3 glyph procedures, soft-mask groups) decodes with FlateDecode (Fl), LZWDecode (LZW, with EarlyChange), ASCII85Decode (A85), ASCIIHexDecode (AHx) and RunLengthDecode (RL), in any chain, with a PNG predictor (10 to 15, whole rows) or a TIFF predictor (2, 8-bit samples) on the last Flate or LZW filter, and follows one unambiguous grammar: tokens separated by white space (bytes 9, 10, 12, 13 and 32) or delimiters, well-formed numbers and names, no bytes outside strings but printable ASCII and white space, no operator inside an array or a dictionary, no braces. Only an allowlisted set of operators is used, each with exactly its operands. Each stream balances on its own its saves and restores (`q`/`Q`), text objects (`BT`/`ET`), marked content (`BMC`/`BDC`/`EMC`) and compatibility sections (`BX`/`EX`); a text object holds only what ISO 32000-1 allows in one; every path starts with `m` or `re` and is painted (or used as a clip, then painted) before anything else, and none is left open. Type 3 glyphs start with `d0` or `d1`, and only they use them; an uncoloured glyph sets no colour. Text is filled, invisible or added to the clip, never stroked (rendering modes 1, 2, 5 and 6: readers take a text stroke's width differently). A page's content split across streams is split between tokens, at white space. Inline images only unfiltered, in a device colour space, with exactly their declared number of bytes and no `EI` in their data.
  - Resources: everything content names is there; forms, patterns, soft masks and Type 3 glyphs are checked the same way; no PostScript XObject, no form that draws itself; graphics states without transfer functions, halftones, black generation, undercolour removal or overprint (overprint mode is accepted: it changes nothing while overprint is off), and a smoothness tolerance only in a document that draws no smooth shading.
  - Fonts: carried by the PDF, but for the standard fonts Helvetica, Times and Courier (each style) in a standard encoding, which every reader replaces with a design of the same metrics; composite fonts carry their glyphs and map codes with Identity-H or Identity-V. Images only in filters every reader decodes: the content filters above, DCTDecode, CCITTFaxDecode, JBIG2Decode and JPXDecode, their soft masks and masks too.
  - No optional content anywhere: no `/OCProperties`, no `/OC`, no OCG or OCMD object.
  - Annotations: only links without an appearance of their own, or with one whose every form has a bounding box without area (as macOS writes them), and invisible digital signatures (signature fields whose widgets have a rectangle without area). They show nothing, and are left out of the copy (`/Annots` from every page and page tree node, `/AcroForm` from the catalog). Any other annotation, and any other form field, makes it not clean.
  - Pages: a stated MediaBox, a CropBox (if any) that overlaps it, `/Rotate` in quarter turns, and no `/UserUnit` but 1.
- **Reading the file.** Every document, clean or not, is read exactly as pdf.js 6.4.299 reads it for the signer (`src/renderer/pdfjs-v3.ts`, following pdf.js's code step for step): its header and `startxref`, its cross-reference tables and streams, the `/Prev` chain and a hybrid file's `/XRefStm`, which entry wins, an uncompressed object fetched at its offset and checked against its number and generation, a compressed one read from its object stream, its reconstruction of a file whose cross-reference is damaged or missing (scanning the file for objects, as pdf.js does when it retries in recovery mode), its decryption, its stream decoders with the points where they fail, and its page tree (the pages pdf.js finds, with its caches and cycle checks, inherited Resources merged and MediaBox, CropBox, Rotate and UserUnit as pdf.js takes them). The document the check, the copy and this verifier use is built only from the objects pdf.js read (`src/renderer/open-v3.ts`), so an object defined again elsewhere in the file (appended after the last cross-reference, or placed where the cross-reference doesn't point) never changes what the copy shows. A file pdf.js can't open, or whose first page it can't load, gets the copy described at the end of this section; every other file has its pages drawn as pdf.js draws them, however damaged.
- **Protecting a document that isn't clean.**
  - No content bytes of the document reach the copy as they were. Every content stream a page may run (the page's, form XObjects, Type 3 glyphs, tiling pattern cells, soft-mask groups, annotation appearances) is decoded as pdf.js decodes it (a page's stream that fails to decode is left out whole, as pdf.js leaves it out; a form's is read up to where decoding fails), read as pdf.js reads it (its lexer, its parser and its EvaluatorPreprocessor: its operators and their operand counts, its inline images) and run through the checks pdf.js's evaluator makes (text shown without a font left out, operands it rejects dropped, the operators it ignores left out, reading stopped where pdf.js stops), and written back (FlateDecode) as content every reader reads the same way: numbers as they were written, names and strings re-escaped, inline images as hexadecimal data, and closed off at its end (`ET` for a text object left open, `n` for a path or clip left open, `EMC` for each marked-content sequence, `Q` for each save), with as many saves (`q`) before it as it could restore beyond its own. A page's content is drawn as one form XObject `/AttestPage`. A form run in different contexts (by a page, by an annotation, inside optional content pdf.js hid) gets its own rewritten copy for each. Nesting of arrays and dictionaries is read without recursion, up to the depth Chromium's pdf.js reads (2,900 levels); forms nested deeper than 32 levels make a document not clean (readers stop drawing nested forms at different depths).
  - Annotations are drawn into the page after its content, as pdf.js prints them: one flagged Print and not Hidden (pdf.js ignores Invisible on the types it knows, so does the renderer), a markup annotation of a type that needs QuadPoints only with valid ones, in optional content pdf.js shows, in pdf.js's order (other annotations, then widgets), from its normal appearance (the `/N` stream, or the one its `/AS` names in a state dictionary), as a form XObject `/AttestAnnot<k>` mapped from its BBox through its Matrix onto its Rect (pdf.js's transform, with single-precision bounds) and clipped to its Rect. A form field is drawn as pdf.js draws it (`src/renderer/fields-v3.ts`, following pdf.js's widget code step for step): from its own appearance, except where pdf.js generates one, which is then drawn instead, from `[0 0 width height]` onto its Rect, turned by the field's MK rotation, with the field's resources (its DR, its appearance's resources and the form's DR, merged as pdf.js merges them). pdf.js generates one for a text field or combo box when the form sets NeedAppearances, or when the field has no value (`/V`) and no appearance and the form's XFA dataset gives it one (read as pdf.js reads it with XFA off: the `datasets` packet, searched by the widget's own `/T`); and for a list box under NeedAppearances. The content is pdf.js's: `/Tx BMC q`, the MK background and border, then the value in the DA's font and colour, at the DA's size or, at size 0, the one pdf.js fits to the field (`_computeFontSize`), on one line (aligned by `/Q` at pdf.js's offsets), in comb cells (`/MaxLen`), or over lines split where pdf.js splits them (`_splitLine`), its numbers written as pdf.js writes them and its text widths summed exactly as pdf.js sums them (Math.sumPrecise, computed by the renderer itself so every engine gets the same); a list box shows the options pdf.js shows, the selected ones on its highlight. The font is measured as pdf.js measures it: its encoding (base encoding and Differences, or the one pdf.js picks by its flags and name), its ToUnicode map or the glyph list (`src/renderer/fonts-data-v3.ts`, pdf.js's tables), its widths (or the standard font's metrics), and its ascent and descent (the font descriptor's; a TrueType font file's hhea table over its head unitsPerEm; the metrics of the standard font file pdf.js loads in its place). A font pdf.js can't load draws nothing (only the field's colours are drawn); a combo box flagged as a password keeps its own appearance; an XFA datasets packet pdf.js can't parse gives no dataset, and a packet whose name is an indirect object isn't read, as in pdf.js. A DA font the resources don't have is pdf.js's fallback, Helvetica in WinAnsiEncoding, added to the field's resources under the DA's name. A checkbox or radio button whose value names an appearance state with no stream gets pdf.js's own check (ZapfDingbats `3`) or disc (`l`), sized and centered as pdf.js sizes and centers them. A value the field's font can't encode, which pdf.js draws with a font of the browser's own, is drawn in Noto Sans at the size and alignment pdf.js would use. A pop-up prints its own appearance as pdf.js prints it, with its parent's flags where its own make it unviewable and its parent's don't, and none when its parent (or the annotation a group reply answers) isn't a dictionary. Links, annotations pdf.js doesn't print and ones with no appearance stream are dropped. Every annotation and the form (`/AcroForm`) are then removed from the copy.
  - Optional content: visibility is decided as pdf.js decides it for print (its default configuration's BaseState, ON and OFF, each group's Usage/Print/PrintState, an OCMD's VE expression or its P policy over its OCGs, as pdf.js reads them), and only what pdf.js showed is kept. An XObject pdf.js hid is replaced by an empty form, and an annotation it hid is dropped. In content (the page's, and every form, annotation appearance, Type 3 glyph, tiling pattern cell and soft mask group pdf.js runs), read as pdf.js reads it and with each stream's marked content kept to itself as pdf.js keeps it, everything inside marked content pdf.js hid stays except what it would paint: a path painting operator becomes `n`, text is shown between `3 Tr` and the text rendering mode in force (so it still moves the text position), and an image, shading, inline image or form is left out. Then every `/OC`, every OCG or OCMD in a `/Properties` dictionary (replaced by an empty dictionary), every OCG or OCMD dictionary written into content (emptied) and `/OCProperties` are removed, so the copy has no optional content and no reader can hide anything with it, Attest's layer included.
  - A file whose pages can't be shown (it opens only with a password, is encrypted in a way pdf.js doesn't open, or can't be read) gets a copy whose only page of the document says so plainly, and that the original is attached exactly as signed and verifies (its fingerprint is the one anchored), followed by the certificate pages in the full copy.

Second, everything drawn for an entry stays inside the field the sender placed:

- A signature's stamp (bracket, signature, label, verification code, signing day and QR code) is laid out inside its field, whatever its size; it never grows past it. Its parts keep clear of the field's edges: a tenth of its height (at most 3 points) above and below, and 3% of its width (at most 3 points) at the sides. Everything, the QR code included, sits in a band along the bottom of what is left, which leaves free its top 28% (at most 9 points). The QR code is centered on the band, at most 24 points and 22% of the field's width; one under 18 points (0.22 mm modules, the smallest that scans reliably from a page printed at 300 dpi) is left out. The label, code and day are set side by side with the signature, at up to 5 points within 40% of the room beside the QR code (initials: 60% of the field), or above the signature in a field too tall for that, when that keeps the QR code (if side by side does) and more of the text with the signature at least 80% as large, or the same text with the signature a quarter larger; a field too small for them at 4 points leaves out the label, then the day, then the code, so no line is smaller (the foot of every page carries the code and the link to verify).
- A signature or initials image is fitted by the part of it that carries ink (its pixels at least an eighth opaque, or darker than light gray in an image with no transparency), and clipped to the stamp.
- Initials get an "Attest" stamp with the code, by the same rules, with no day or QR code.
- A date, name or text entry is set at up to 12 points (70% of the field's height), on one line or wrapped onto more when that sets it larger, never wider or taller than its field.

Third, what people typed (entries, a signature set in type, the title, signers' names, the audit trail's names) is printed with a glyph for every character:

- On one line: each run of line breaks (`\n`, `\r`, U+2028, U+2029, U+0085, `\v`, `\f`) is one space.
- Composed (Unicode NFC). A character renderer v3 doesn't print (`src/renderer/charset-v3.ts`: Latin with its extensions and IPA, Greek, Cyrillic with its supplement, Vietnamese, combining marks, punctuation and spaces, superscripts and subscripts, currency, letterlike symbols, number forms, the Latin ligatures) is drawn as its decomposition when that prints, or as U+FFFD.
- A title with a character renderer v3 doesn't print is never printed in part: the certificate shows "Untitled agreement (title not printable), " and the agreement's id instead.
- In Helvetica when its encoding (WinAnsi) has every character, and otherwise in Noto Sans 2.015 (`src/fonts/noto-sans-400.ttf` and `noto-sans-700.ttf`, cut to `charset-v3.ts`, embedded as subsets); on the certificate, in Instrument Sans when it has every glyph, and otherwise in Noto Sans.

Fourth, the certificate pages say that each party can prove they signed "and the date it was completed" (what a Share proof shows; renderer v2 says "and when"), and that a PDF reader's attachments panel lists the attached files (renderer v2 says any PDF reader lists them).

Everything else is drawn as by renderer v2: the document without anything that runs or attaches, the seal line at the foot of every page, and the certificate, audit trail and verification pages (each signer's stamp on the certificate drawn by the rules above).

### The certificate (format v6)

As format v5's, made by renderer `attest.render.v3`: its evidence is format v6.


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

Checks 3, 4 and 9 apply (with `consentJson` as the statement); the sender of `anchor.txHash`, which must be a transaction to one of Attest's registries, is `W`. The original document can be checked against `documentSha256` by whoever holds it.

Agreements completed in September 2026 have signers with no passkey evidence (no statement, key or assertion): they were signed before Attest's signers used passkeys. Check 9 commits to that, so a verifier reports such a signer as having no passkey signature, with Attest's anchored record as the evidence, rather than as a failure.

# Receipts (`attest.receipt_evidence.v1`)

```
receipt.id, kind, sha256, claim, createdAt, supersededBy[]
anchor               a Merkle anchor (see above), or null while pending
zkProof              present for scan proofs (zk_): id, circuit, statement, proof, publicSignals,
                     verificationKey (Groth16, snarkjs JSON), zkverify{status, txHash}
online, verifier
```

1. **Content.** Optionally, `SHA-256(file) == receipt.sha256`.
2. **Anchor.** The Merkle anchor for `receipt.sha256` is an Attest anchor. `claim`, `kind` and `createdAt` are the account's own description, not covered by the anchor: a verifier shows the anchor's time and labels the description as the account's.
3. **Scan proof** (`security_scan_proof_v2`). Groth16 verifies with the circuit's published key; public signals are `[valid, scanCommitment, proofType, minSecurityScore, maxCriticalAllowed, maxHighAllowed]`; `receipt.sha256 == sha256("attest.scan.v2|" + scanCommitment)`; the predicate holds when `valid == "1"`.

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
3. **Issuer key.** The issuer key value (see above) is an Attest anchor, from the wallet named in `issuer.keyAnchor.from`: that is the organization's wallet. The DID must be one Attest issues (`did:web:attest.datahubz.com:orgs:<slug>`), and every verification method in its document must be that one committed key (as a Multikey or as a JWK, with an id under the DID): a signature is checked only against it.
4. **Issuer signature.** `vcJwt` is a JWS (ES256) by the key `kid` in the DID document; its payload names `issuer.id == did` and `credentialSubject.contentSha256 == contentSha256`.
5. **PDF.** Optionally, `SHA-256(pdf) == pdfSha256`.
6. **Anchor.** `sha256("attest.certificate.v1|" + id + "|" + pdfSha256 + "|" + sha256(vcJwt))` is an Attest anchor by the wallet that anchored the issuer key.
7. **Status.** `sha256("attest.certificate.revoked.v2|" + id)` anchored by that wallet means revoked, at its time.
The title, issuer name and validity shown are the signed content's and credential's. Each signer's statement and passkey key are named in the credential's `credentialSubject.signatures` (`statementSha256`, `publicKeySha256`).
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
7. **Current status.** For n = 1, 2, ...: whichever of the three states is anchored by the issuer's wallet is the state after the n-th change; stop at the first n with none. No change means active.
All anchors (issuer key, context, status lists, issuance, status changes) must be Attest anchors.

# Agreement proofs (`attest.proof_evidence.v1`)

```
proof                id, circuit, statement, revealed{party, counterparty, dateISO, day}, proof, publicSignals,
                     verificationKey, createdAt, zkverify{status, txHash}
root                 value (0x-hex), anchor (value anchor), or null anchor while pending
chain                chainId, rpc, contract
```

Public signals: `agreement_membership` is `[root, emailField(party), day, identitySalt]`; `agreement_with_party` is `[root, emailField(party), emailField(counterparty), day, identitySalt]`, with `emailField(e) = sha256(lowercase e) mod P`, `identitySalt = sha256("attest.identity.v1") mod P`, and `day` the UTC day number of the completion.

1. **Proof.** Groth16 verifies with the circuit's published verification key (never the one in the evidence).
2. **What it reveals.** The email fields, the day and the salt match the public signals. The statement shown is built from these checked values.
3. **Root.** The root is an Attest anchor (from the wallet in `root.anchor.from`): it commits to every completed agreement on Attest.
4. **zkVerify.** The proof is also verified on zkVerify (`zkverify.txHash`).

# Analytics (`attest.analytics_evidence.v1`)

The method and each figure's definition are in [ANALYTICS.md](ANALYTICS.md).

```
snapshots[]          id, day, scope ("platform" or "organization"), canonical (the summary), sha256
  figures            the figures document (full evidence only)
  commitments        the commitments document
  leaves             { figure: [leaf hashes] } (full evidence only)
  inclusion[]        figure, record{kind, id}, salt, leaf, path (inclusion evidence only)
  anchor             Merkle anchor of the summary's SHA-256
chain                chainId, rpc, contract
```

1. `sha256(canonical) == sha256`; its receipt is an Attest anchor by wallet `W`; and the Analytics day value (`attest.analytics.v1`, with the summary's own `day` and `scope`) is an Attest anchor by `W`, so a receipt someone else recorded for the same fingerprint doesn't count.
2. `sha256(commitments) == summary.commitmentsSha256`; `sha256(figures) == summary.figuresSha256`.
3. Full: for each figure, the root of its leaves equals its commitment, and their number equals `figures.activity[figure]`; each anchor leaf is a transaction to one of Attest's registries, mined that day.
4. Inclusion: `sha256("attest.analytics.leaf.v1|" + figure + "|" + record.id + "|" + salt) == leaf`, and folding `path` (sorted pairs) reaches `commitments[figure]`.

## Compatibility

A format's version changes only when fields are added or a check changes. Each verifier release reads every earlier format. A verifier that meets a newer format reports it and points to the latest release; it never reports such a record as failed.

# Base and Horizen

Attest anchors on Base (chain 8453). Until Horizen stopped, on November 5, 2026 at 18:00 UTC, it anchored on Horizen (chain 26514), an OP Stack chain that settles on Base. Records anchored there stay verifiable: every value in Horizen's state at a block is provable from that block's header, and Horizen posted each block's output root to Base as a dispute game.

The v3 formats (`attest.receipt_evidence.v3`, `attest.certificate_evidence.v3`, `attest.card_evidence.v3`, `attest.proof_evidence.v3`, `attest.analytics_evidence.v3`) and `attest.agreement_evidence.v7` are the earlier formats (v2, and v5 or v6 for agreements) with:

- anchors that may name `chainId` 8453, checked on Base exactly as anchors on Horizen were checked there;
- an optional member `horizen`, a proof of Attest's registries on Horizen, below.

An agreement v7 record names no renderer of its own: its pages are re-made with the renderer its anchored completion details name (`attest.render.v2` or `attest.render.v3`). Its `visibleCopy.chainId` is the chain the pages name (the signed state's anchor chain, or the chain Attest anchored on when the copy was made before that anchor existed): it must be 8453 or 26514 and, when `anchor` is present, equal `anchor.chainId` (26514 when it names none). The renderer is given it as `agreement.anchorChainId`, and the pages name Base for 8453 and Horizen for 26514 (the seal's ring, the "Anchored on" fact, and the anchor step of "How to verify"). For v5 and v6 records the renderer is given no chain: their pages name Horizen, as they always have. Verifiers from 1.7.0 accept an anchor on 8453 or 26514 in any format version.

## The Horizen proof (`attest.horizen_proof.v1`)

```
horizen.format          "attest.horizen_proof.v1"
horizen.chainId         26514
horizen.block           number, hash, headerRlp: the proven Horizen block and its RLP header
horizen.game            chainId (8453), factory, index, address: the dispute game on Base whose root claim is that block's output root
horizen.accounts[]      address (AttestRegistryV3 or AttestRegistryV2 on Horizen), accountProof (RLP nodes, root first),
  storage[]             slot, value (hex quantity, "0x0" when empty), proof (RLP nodes), meaning, txHash (the anchoring
                        transaction, on anchoredAt and rootTimestamp entries)
```

`meaning` names what a slot holds, and the slot is recomputed from it (Solidity's layout, `mappingSlot(key, slot) = keccak256(key . slot)`, 32-byte words):

| Meaning | Registry | Slot |
| --- | --- | --- |
| `anchoredAt[w][v]` | AttestRegistryV3 | `mappingSlot(v, mappingSlot(w, 1))` |
| `registeredAt[w]` | AttestRegistryV3 | `mappingSlot(w, 2)` |
| `revokedAt[w]` | AttestRegistryV3 | `mappingSlot(w, 3)` |
| `rootTimestamp[v]` | AttestRegistryV2 | `mappingSlot(v, 2)` |
| `rootAnchorer[v]` | AttestRegistryV2 | `mappingSlot(v, 3)` |

Checks (`src/horizen-proof.mts` implements the proofs; it needs only Keccak-256):

1. `keccak256(headerRlp) == block.hash`, and the header's number is `block.number`.
2. The output root: `keccak256(0^32 || stateRoot || withdrawalsRoot || block.hash)` (OP Stack version 0; since Isthmus the header's `withdrawalsRoot` is the message passer's storage root).
3. On Base: the pinned portal's `disputeGameFactory()` is the pinned factory, which is `game.factory`; the factory's `gameAtIndex(game.index)` returns game type 1 and `game.address`; the game's `rootClaim()` is the output root, `l2BlockNumber()` is `block.number`, `l2ChainId()` is 26514, and the portal's `disputeGameBlacklist(game)` is false. `status()` 2 (defender wins) settles the block; 0 (in progress) leaves it pending until the game resolves, 3.5 days after it was created (`createdAt + 302400` seconds); 1 (challenger wins) means the output root is invalid.
4. Each account is one of the pinned Horizen registries, and its account proof verifies against the header's `stateRoot`.
5. Each storage entry's slot is the one its meaning names, and its proof verifies against the account's `storageRoot` to `value` (an exclusion proof for 0).

A slot the proof doesn't carry is unknown, never empty. The anchor checks above then read `anchoredAt`, `isAnchored`, `registeredAt` and `revokedAt` from the proven values. A transaction hash in the proof is the archive's record of where the anchor came from: the anchor itself is proven from state, the transaction is not.

## Where a Horizen anchor is read

In order: the proof the record carries; a node of Horizen, if one still answers (the verifier's page takes one); Attest's archive of Horizen proofs, for records sealed before they carried one:

```
GET https://attest.datahubz.com/api/horizen/proofs?q=<wallet>:<value>,...&t=<txHash>,...
```

`q` asks for `anchoredAt[wallet][value]` (or, with an empty wallet, `:<value>`, the V2 anchor of `value`), with `value` as 64 hex digits without `0x`; `t` asks for the anchor a transaction made; at most 32 of each. The answer is an `attest.horizen_proof.v1` object holding the proofs the archive has for them, each hit with its wallet's `registeredAt` and `revokedAt` (and `rootAnchorer` for V2), or 404 when it has none. It is checked exactly as a carried proof, so the archive is trusted only for the absence of a proof, which the verifier reports as Attest's statement.
