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

window.AttestLibs = {
  vc,
  DataIntegrityProof,
  createVerifyCryptosuite,
  ecdsaRdfc2019,
  securityLoader,
  checkStatus,
  cborg,
  verifyGroth16,
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
