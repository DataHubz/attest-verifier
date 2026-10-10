// Libraries bundled into attest-verifier.html at build time (see build.mjs). Nothing is loaded at run time.
import * as vc from "@digitalbazaar/vc";
import { DataIntegrityProof } from "@digitalbazaar/data-integrity";
import { createVerifyCryptosuite } from "@digitalbazaar/ecdsa-sd-2023-cryptosuite";
import { cryptosuite as ecdsaRdfc2019 } from "@digitalbazaar/ecdsa-rdfc-2019-cryptosuite";
import { securityLoader } from "@digitalbazaar/security-document-loader";
import { checkStatus } from "@digitalbazaar/vc-bitstring-status-list";
import * as cborg from "cborg";
import { verifyGroth16 } from "./groth16.mjs";
import cardsContext from "./contexts/attest-cards-v1.json";
import ob3Context from "./contexts/ob3-context-3.0.3.json";

window.AttestLibs = {
  vc,
  DataIntegrityProof,
  createVerifyCryptosuite,
  ecdsaRdfc2019,
  securityLoader,
  checkStatus,
  cborg,
  verifyGroth16,
  contexts: {
    "https://attest.datahubz.com/contexts/cards/v1": cardsContext,
    "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json": ob3Context,
  },
};
