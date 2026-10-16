# Changelog

## 1.6.0 (unreleased)

Signed copies whose stamps and entries stay inside their fields, on the page as it is shown, whatever the document's own content does: renderer v3, and evidence v6 for the copies it makes.

- Renderer v3 (`attest.render.v3`, `src/renderer/v3.ts`, byte for byte the one Attest's app seals with): everything drawn for an entry stays inside the field the sender placed. A signature's stamp no longer grows past a small field (renderer v2 grew it to 120 by 30 points about the field's center, over the document around it); its bracket, signature, label, code and day sit in a band along the bottom of the field, clear of its edges, with the QR code at the right, 18 to 24 points and never above the band; the stamp's text is at least 4 points, and small fields leave out the label, the day and the code, in that order, rather than set them smaller. Signature images are fitted by their ink. Text entries wrap or shrink to fit their field.
- The page as shown: fields land on the CropBox within the MediaBox, turned by `/Rotate`, at `/UserUnit`, as pdf.js shows the page to the sender and signer, and stamps, entries and the seal line are drawn upright on it. Renderer v2 placed fields on the MediaBox from its origin, unturned.
- Every document is signed, in two tiers. Every document gets the original attached exactly as signed, which this verifier checks against its anchored fingerprint and offers as signed. A clean document (one renderer v3 can prove every reader shows the same way: one unambiguous grammar, an allowlisted set of operators, each stream balanced on its own, no path left open and no text stroked, content in the five filters v3 decodes, no optional content, its own fonts or the standard ones, images in filters every reader decodes, no annotation but links and invisible signatures, plainly sized and turned pages; FORMAT.md lists every rule) gets a copy whose pages show exactly what pdf.js showed the signer, with Attest's layer on top, drawn as one form XObject so nothing in it can move, hide, stretch or cover what Attest draws; tested in pdf.js, PDFium, MuPDF, Poppler, Ghostscript and Apple PDFKit against what pdf.js showed the signer, on the reviews' attacks and on a corpus of everyday PDFs (Adobe Acrobat wasn't tested). Any other document gets the best protection v3 can give (its content closed off in its own form where v3 can read it and kept exactly as it was where it can't, annotations and form fields drawn as pdf.js prints them, optional content as pdf.js decided it, given to every reader) and a note at the foot of its pages and on the certificate: "Some PDF readers may display parts of this document differently. Attest's verifier shows exactly what was signed." This verifier says the same for such a copy, verifies the document as signed, and offers it. Renderer v2 drew after the page's content, so a page ending in an extra restore and a transform, text mode, clip or scaling changed every stamp after it.
- What people typed is printed with a glyph for every character: on one line (line breaks become spaces), composed, in Helvetica, Instrument Sans or Noto Sans (embedded, cut to Latin, Greek, Cyrillic and Vietnamese: `src/renderer/charset-v3.ts`), and any other character as U+FFFD; a title with such a character is shown as "Untitled agreement (title not printable)" with the agreement's id. Renderer v2 could draw missing glyphs and start new lines below a field.
- The certificate pages say a party can prove they signed "and the date it was completed", what a Share proof shows, and that a PDF reader's attachments panel lists the attached files. Everything else is drawn as by renderer v2.
- Evidence v6: the evidence of copies and certificates whose pages renderer v3 made, the same as v5 with renderer v3 named in the completion details and the visible copy. The verifier re-makes their pages with renderer v3 and compares them byte for byte. A v5 record must name renderer v2, a v6 record renderer v3: Attest's agreement anchor binds the details, so pages can't be moved to another renderer. An agreement keeps the renderer it was completed with, so copies of agreements completed with renderer v2 stay v5 and verify as before.
- Earlier releases report a v6 record as a newer format and point to this release, as they do for any format they don't read; they never report it as failed.
- `npm test` also renders renderer v3's fixtures (`test/renderer/v3/`) to the exact bytes Attest's app makes: renderer v2's cases, a tester's agreement whose fields reach into the labels above them and sit on their lines, a field of every size Attest's field placer makes and smaller, turned, cropped and offset pages, the reviews' attacks, content in every filter and predictor renderer v3 decodes, annotations of every kind, and entries in every script v3 prints and some it doesn't; including the reviews' attacks and files that can't be read or decrypted, every one of which gets a copy. The same cases render to the same bytes in Chromium, WebKit and Firefox. Renderer v2's fixtures are unchanged, and `npm test` fails unless pdf-lib, @pdf-lib/fontkit and qrcode are pinned and resolved at exactly 1.17.1, 1.1.1 and 1.5.4, whose output the renderers' bytes depend on.
- The page is about 0.36 MB larger: it carries Noto Sans for renderer v3.

Attest serves this release, and completes agreements with renderer v3, only once its build is anchored by Attest's platform organization: until then it serves 1.5.0 and completes with renderer v2.

## 1.5.0 (2026-10-12)

Signed copies from protocol v5: the verifier re-makes the pages you see from what was signed, and the record names people only by name.

- Evidence v5: the verifier re-makes a signed copy's visible pages with Attest's deterministic renderer (`attest.render.v2`, carried in the page with its fonts) from the original document, every signer's signed statement and entries, the signed state and Attest's anchored completion details, and compares them byte for byte with the copy. Pages drawn with anything else fail, and the verifier offers the pages as signed. The same pages render to the same bytes in Chromium, WebKit and Firefox.
- Statements v3 name each signer by a salted commitment, sign where their entries appear (`layoutSha256`) and commit to the signer's own encryption key. Signed state v3 lists signers by commitment with the SHA-256 of each statement. Attest's agreement anchor v2 also binds the completion details the pages print.
- Names only: a v5 copy, its evidence and its pages carry no email and no salt, and no zero-knowledge proof (a proof reveals its party's email; each party shares it from the proof's page).
- The renderer draws the document without anything that runs or attaches: it visits every object of the original and removes scripts (including those chained after a link), launches, form submissions, media, open and additional actions, XFA, attached files and portfolios, keeps links within the document and to web pages, drops every object nothing refers to any more, and refuses to finish if anything active is left. The original document is attached to the signed copy as it was signed.
- A signature's stamp always carries its label, the verification code and day, and the QR code: a smaller field's stamp grows about its center to 120 by 30 points. The certificate pages list every signer and every step of the audit trail, on as many pages as they need.
- A v5 copy whose evidence lacks what re-making its pages needs (the document, an entry or the audit trail) fails: a genuine copy always carries them.
- A v5 signed copy's pages must also be anchored as sealed (`attest.signed_copy.v1`): until that anchor is there, the result is "not verified yet".
- The verifier attached to a signed copy or a certificate must be one Attest published: every build Attest has served is anchored by its platform organization (`attest.verifier.v1`, TRUST.md), and the verifier checks the attached one against those anchors. A changed or unknown verifier fails; an earlier release is accepted and noted as updated since.
- The certificate PDF of a v5 agreement is made by the same renderer (variant `certificate`: no document, entries or audit trail) and its pages are re-made and compared byte for byte, like a signed copy's. The completion details name the audit trail by its SHA-256, so the certificate carries the details and the trail stays with the parties; a signed copy's trail must hash to that value. Earlier certificates say plainly that their own pages aren't checked.
- A link, an outline item or a chained action keeps only a jump within the document, an article thread, a web or email address, or a page turn: any other action is removed, whatever its type, including `javascript:`, `data:` and relative addresses and commands such as print. Every name, address and subtype is read through indirect references, as readers read them.
- Attachments are found the way a reader finds them, through file specifications, whatever their name or first bytes, and every file other than the evidence and the document must be a verifier build Attest anchored. Files the signed pages carry themselves are reported.
- `npm test` also renders fixtures to the exact bytes Attest's app makes, with no active content left: a document with every kind of active content, and twenty signers with tiny fields and sixty steps.

Before release, three independent reviews of this version found that a script chained after a link survived the renderer, that the attached verifier wasn't checked, that an attachment starting with a byte order mark, a comment or an SVG escaped that check, that `javascript:` links and print commands survived, that an action whose type was an indirect reference escaped the cleaning, and that a certificate's pages could be redrawn around genuine evidence. All are fixed above.

Affected versions: 1.0.0 to 1.4.2 don't check the verifier attached to a signed copy, so a copy whose attached verifier was replaced still verifies there. Check signed copies with 1.5.0, and open an attached verifier only after this page confirms it. Earlier formats otherwise verify as in 1.4.2.

## 1.4.2 (2026-10-12)

- Certificates and Proof Cards: an issuer's signature counts only against the key Attest committed on chain. The issuer's DID document in the evidence may carry only that key (as a Multikey and as a JWK, under the issuer's DID), and every proof, on the card and on its status lists, must name it. Found by an independent review: 1.0.0 to 1.4.1 checked a certificate's or card's signature against whichever key its DID document listed, so a fabricated certificate or card whose DID document added a key of the forger's own could verify.
- A certificate whose evidence lacks the issued PDF's fingerprint or the issuer's credential fails, instead of skipping its anchor.
- Keys resolve only from the issuer's DID document: no other DID (did:key included) can sign.

Affected versions: 1.0.0 to 1.4.1, for certificates and Proof Cards. Signed agreements, receipts, agreement proofs and Analytics are not affected. Use 1.4.2.

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
