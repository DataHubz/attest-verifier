# Trust model

What the verifier relies on, what it checks, and which attacks each check stops. Everything here holds with no Attest
service involved: the verifier reads only the file it is given and a public node of Horizen.

## The trust root

The verifier pins these values in `src/main.js` (`TRUST`) and never reads them from a file it checks:

| What | Value |
| --- | --- |
| Chain | Horizen, chain id 26514. Any node can be used; the verifier checks its chain id. |
| Registry | AttestRegistryV3, `0xF44Ed281005c7d506Dc50829a3E24655837FBF75` (anchors from October 12, 2026) |
| Earlier registry | AttestRegistryV2, `0x0C6a7918e2f8C28C4bb5Cf8d0f4CE27e9B30fa2A` (anchors until October 12, 2026) |
| Registry authority | `0x23ACBF52e76EE9502174442c87c3cD47c68f44e7`, fixed in AttestRegistryV3 |
| Platform wallet | `0xdEa7B859DcBd34deB8dc910b5b36d6ACdBeC6F3a`, Attest's platform organization: anchors every verifier build Attest has served |
| Passkey site | relying party `attest.datahubz.com`, origin `https://attest.datahubz.com` |
| Circuits | the Groth16 verification keys in `src/circuits/` |
| Vocabulary | the JSON-LD contexts in `src/contexts/` |
| Renderers | `attest.render.v2` and `attest.render.v3` in `src/renderer/`, with their fonts in `src/fonts/`; an agreement's anchored completion details name its renderer |

The registries are open: any wallet can anchor any value. An anchor counts as Attest's only when the wallet that made
it is registered on AttestRegistryV3 by the registry authority and was not revoked before the anchor. The authority is
an Attest wallet whose key only Attest's signer service holds; the signer lets it register wallets it derives itself,
and nothing else. AttestRegistryV3 records each value per wallet, so nobody can block or take over Attest's anchor of a
value by anchoring it first.

Every value an Attest wallet anchors is built by Attest under a fixed prefix (`attest.agreement.v1|...`,
`attest.signed_copy.v1|...`, `attest.issuer_key.v1|...`, and so on, in FORMAT.md) or is the Merkle root of receipt
leaves, `sha256(receiptId + ":" + fingerprint)`. No account can make an Attest wallet anchor a value of another kind.

## Attacks and the checks that stop them

| Attack | What stops it |
| --- | --- |
| A file names its own chain, node, registry contract or passkey site | All pinned; the file's values are ignored. An anchor on another chain fails. |
| A record anchored on Attest's open registry from someone else's wallet | The wallet isn't registered by the authority: fails. |
| An account holder records a receipt for a forged agreement's signed state | A receipt proves only that a fingerprint was recorded. An agreement also needs Attest's own anchor, `attest.agreement.v1`, which only Attest's completion of that agreement makes. |
| A signer's passkey key and signature swapped for an attacker's own | Attest's agreement anchor commits to every signer's statement, passkey key and signature: a swapped one changes the value, which was never anchored. |
| A signer's name, title, date or entries edited | Each is in the signed statement (the passkey signature fails) and in Attest's anchors. |
| The pages of one agreement shown with the evidence of another | Every statement and the signed state name the agreement, and the pages' anchor names it too. |
| Content added to a signed copy after its evidence (a second PDF update that overlays a page, a script, an annotation) | The verifier reads the file strictly: after the signed pages there must be exactly Attest's update, attaching the evidence, the original and the verifier, with a catalog that is otherwise the pages' own. Anything else fails, and the verifier offers the signed pages exactly as sealed. |
| The signed pages edited | Their SHA-256 no longer matches the anchored value. |
| Pages drawn by whoever sealed the copy with an entry, a name, a date or a field moved (protocol v5) | The verifier re-makes the pages from what the passkeys signed and Attest anchored, with the same deterministic renderer, and compares every byte: pages that show anything else fail. |
| Pages made by another renderer than the agreement's (renderer v3's pages under evidence v5, or v2's under v6) | The completion details name the renderer and Attest's agreement anchor binds them, and the evidence format must match it (v5 for renderer v2, v6 for v3): the pages are re-made only with the renderer the anchored details name. |
| A signer's entries drawn in another place | Each statement signs where its signer's entries appear (`layoutSha256`); Attest's anchor binds every field's place and owner. |
| A zero-knowledge proof checked against a key that accepts anything | Proofs are checked only against the pinned verification keys. |
| A certificate or Proof Card signed by a key the forger adds to the issuer's DID document | The DID document may hold only the key Attest committed on chain from the issuer's wallet; every proof must name it, and no other DID resolves. |
| A proof's root, or an issuer key, status change or Analytics day, anchored by an outsider | Same as any anchor: it must be from a registered Attest wallet, under its own domain-separated value. |
| A predictable value anchored first to block Attest | AttestRegistryV3 keeps values per wallet: Attest's anchor still lands. |
| A signed copy whose attached verifier was replaced, so that opening it shows a forged result | The verifier checks every attached verifier: its SHA-256 and version must be anchored as `attest.verifier.v1` by the pinned platform wallet. A changed or unknown verifier fails, and the page says not to open it. |
| A document whose links, outline, form or annotations carry a script, a launch, media or an attached file, chained or hung from any key | The renderer visits every object, removes anything that runs or attaches, drops what nothing refers to, and refuses to finish if anything is left; the verifier re-makes the pages with the same code, so pages carrying anything else fail. |
| A certificate PDF whose pages were redrawn | A v5 certificate's pages are re-made from what was signed and anchored and compared byte for byte. Earlier certificates' pages aren't checked: the verifier says so, and shows the signed and anchored names, dates and fingerprints to compare with. |
| A link that runs a script (`javascript:`), opens data or a local file, or a viewer command (print, save), written directly or behind an indirect reference | A link, an outline item or a chained action keeps only a jump within the document, an article thread, a web or email address, or a page turn; the renderer removes every other action, reading names through references as readers do. |
| An attachment that hides from the check (another name, a byte order mark, a comment, an SVG, a missing type) | The verifier finds attachments the way a reader does, through file specifications, and every file other than the evidence and the document must be a verifier build Attest anchored. |
| A file that tries to run a script in the page | The page runs only its own scripts, by hash (Content Security Policy); links go only to the pinned explorer. Served from attest.datahubz.com it is also sandboxed away from the app's cookies and storage. |
| A display that shows more than was checked | Titles, names, dates and descriptions shown are the signed or anchored ones. A receipt's description, which no anchor covers, is labeled as the account's own text. |

## What a result covers

- **Signed copies from evidence v5 and v6** (protocol v5, October 12, 2026 on): the verifier re-makes the visible pages
  from the original document, each signer's signed statement and entries, the signed state and Attest's anchored
  completion details, with the renderer those details name (v2 for evidence v5, v3 for v6), and checks them byte for
  byte against the copy and against the value anchored when it was sealed. The record names people only by name: each
  signer's email is behind a salted commitment that only the parties can open.
- **Signed copies from evidence v3 and v4** (October 10, 2026 on): the visible pages are the copy anchored when the
  agreement completed, made in the browser of a party to the agreement. The verifier checks them byte for byte and
  checks the original document inside against what every signer signed.
- **Signed copies in evidence v1 and v2** carry no anchor of their visible pages: the verifier checks the original
  document inside and says the pages aren't covered.
- **Agreements completed in September 2026** were signed before signers used passkeys: the verifier shows each such
  signer without a passkey signature, and Attest's anchored record of the agreement, which commits to that, as the
  evidence.
- **Receipts** prove that a fingerprint was recorded by an Attest account at the anchor's time. They do not identify
  the account or vouch for its description.
- **Proof Cards** shared before holder approvals existed show no approval.

## Reporting

Report a vulnerability to contact@datahubz.com. Fixes ship as new releases, with the affected versions named in
CHANGELOG.md.
