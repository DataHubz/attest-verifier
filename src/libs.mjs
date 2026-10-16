// Libraries bundled into attest-verifier.html at build time (see build.mjs). Nothing is loaded at run time.
import * as vc from "@digitalbazaar/vc";
import { DataIntegrityProof } from "@digitalbazaar/data-integrity";
import { createVerifyCryptosuite } from "@digitalbazaar/ecdsa-sd-2023-cryptosuite";
import { cryptosuite as ecdsaRdfc2019 } from "@digitalbazaar/ecdsa-rdfc-2019-cryptosuite";
import { securityLoader } from "@digitalbazaar/security-document-loader";
import { checkStatus } from "@digitalbazaar/vc-bitstring-status-list";
import * as cborg from "cborg";
import { verifyGroth16 } from "./groth16.mjs";
import { p256 } from "@noble/curves/p256";
// Renderers v2 and v3 re-make a v5 or v6 signed copy's visible pages; the certificate fonts they embed travel with them.
import { renderV2, RENDERER_V2 } from "./renderer/v2.ts";
import { renderV3, RENDERER_V3, documentProblemsV3, NOT_CLEAN_NOTE } from "./renderer/v3.ts";
import { PDFArray, PDFDict, PDFDocument, PDFName, PDFRawStream, PDFRef, decodePDFRawStream } from "pdf-lib";
import instrumentSans400 from "./fonts/instrument-sans-400.ttf";
import instrumentSans600 from "./fonts/instrument-sans-600.ttf";
import jetbrainsMono400 from "./fonts/jetbrains-mono-400.ttf";
// Renderer v3 also prints what people typed in Noto Sans when Helvetica and Instrument Sans have no glyph for it.
import notoSans400 from "./fonts/noto-sans-400.ttf";
import notoSans700 from "./fonts/noto-sans-700.ttf";

// Issuer keys (Multikey) are compressed P-256 points, which some browsers' WebCrypto won't import, raw or wrapped in
// SPKI (Firefox). The point is decompressed, and checked to be on the curve, before WebCrypto imports it.
const SPKI_P256_COMPRESSED = "3039301306072a8648ce3d020106082a8648ce3d030107032200";
const SPKI_P256 = "3059301306072a8648ce3d020106082a8648ce3d030107034200";
const hexOf = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (h) => Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16));
const subtle = globalThis.crypto && globalThis.crypto.subtle;
if (subtle) {
  const importKey = subtle.importKey.bind(subtle);
  subtle.importKey = (format, keyData, algorithm, extractable, usages) => {
    const curve = algorithm && typeof algorithm === "object" ? algorithm.namedCurve : null;
    if ((format === "raw" || format === "spki") && curve === "P-256" && keyData && typeof keyData === "object" && "byteLength" in keyData) {
      const bytes = ArrayBuffer.isView(keyData) ? new Uint8Array(keyData.buffer, keyData.byteOffset, keyData.byteLength) : new Uint8Array(keyData);
      const point = format === "raw" ? bytes : bytes.length === 59 && hexOf(bytes.subarray(0, 26)) === SPKI_P256_COMPRESSED ? bytes.subarray(26) : null;
      if (point && point.length === 33 && (point[0] === 2 || point[0] === 3)) {
        const full = p256.ProjectivePoint.fromHex(point).toRawBytes(false);
        keyData = format === "raw" ? full : new Uint8Array([...fromHex(SPKI_P256), ...full]);
      }
    }
    return importKey(format, keyData, algorithm, extractable, usages);
  };
}
import cardsContext from "./contexts/attest-cards-v1.json";
import ob3Context from "./contexts/ob3-context-3.0.3.json";
// The circuits' verification keys, pinned: a proof is checked against these, never against a key its file carries.
import agreementMembership from "./circuits/agreement_membership_vk.json";
import agreementWithParty from "./circuits/agreement_with_party_vk.json";
import securityScanProofV2 from "./circuits/security_scan_proof_v2_vk.json";
import findingsClosure from "./circuits/findings_closure_vk.json";

/**
 * Every file a PDF reader would list as attached: the streams named by any file specification's /EF, anywhere in the
 * document (the attachments name tree, a file attachment annotation, media), decoded. A stream that can't be decoded
 * is returned as stored, so it can't pass for anything Attest published.
 */
async function attachedFiles(bytes) {
  const pdf = await PDFDocument.load(bytes, { ignoreEncryption: true, updateMetadata: false, throwOnInvalidObject: false });
  const ctx = pdf.context;
  const look = (v) => (v instanceof PDFRef ? ctx.lookup(v) : v);
  const out = [], seen = new Set();
  const take = (v) => {
    const st = look(v);
    if (!(st instanceof PDFRawStream) || seen.has(st)) return;
    seen.add(st);
    try { out.push(decodePDFRawStream(st).decode()); } catch { out.push(st.contents); }
  };
  const walk = (v, depth) => {
    if (depth > 32) return;
    const d = v instanceof PDFDict ? v : v && v.dict instanceof PDFDict ? v.dict : null;
    if (d) {
      const ef = look(d.get(PDFName.of("EF")));
      if (ef instanceof PDFDict) for (const [, f] of ef.entries()) take(f);
      if (v instanceof PDFRawStream && d.get(PDFName.of("Type")) === PDFName.of("EmbeddedFile")) take(v);
      for (const [, x] of d.entries()) if (!(x instanceof PDFRef)) walk(x, depth + 1);
    } else if (v instanceof PDFArray) for (const x of v.asArray()) if (!(x instanceof PDFRef)) walk(x, depth + 1);
  };
  for (const [, obj] of ctx.enumerateIndirectObjects()) walk(obj, 0);
  return out;
}

window.AttestLibs = {
  attachedFiles,
  vc,
  DataIntegrityProof,
  createVerifyCryptosuite,
  ecdsaRdfc2019,
  securityLoader,
  checkStatus,
  cborg,
  verifyGroth16,
  renderers: {
    [RENDERER_V2]: (input) => renderV2({ ...input, fonts: { sans: instrumentSans400, bold: instrumentSans600, mono: jetbrainsMono400 } }),
    [RENDERER_V3]: (input) => renderV3({ ...input, fonts: { sans: instrumentSans400, bold: instrumentSans600, mono: jetbrainsMono400, noto: notoSans400, notoBold: notoSans700 } }),
  },
  // Whether a document is clean for renderer v3 (its copy shows exactly what pdf.js showed the signer, in every reader
  // Attest tests), and the sentence a copy of one that isn't carries.
  cleanCheck: { [RENDERER_V3]: async (original) => (await documentProblemsV3(original)).length === 0 },
  notCleanNote: NOT_CLEAN_NOTE,
  circuits: {
    agreement_membership: agreementMembership,
    agreement_with_party: agreementWithParty,
    security_scan_proof_v2: securityScanProofV2,
    findings_closure: findingsClosure,
  },
  contexts: {
    "https://attest.datahubz.com/contexts/cards/v1": cardsContext,
    "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json": ob3Context,
  },
};
