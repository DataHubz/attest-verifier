"use strict";
// This file's version, and the evidence formats it reads. Every release reads every earlier format, so an
// older record verifies with any newer verifier; a record in a newer format is reported as such.
const VERIFIER = {
  version: "1.1.0",
  formats: { agreement: [1, 2], receipt: [1], certificate: [1], card: [1], proof: [1] },
  repo: "https://github.com/DataHubz/attest-verifier",
  latest: ["https://attest.datahubz.com/attest-verifier/latest.json", "https://raw.githubusercontent.com/DataHubz/attest-verifier/main/latest.json"],
};
const KINDS = { agreement: "Signed agreement", receipt: "Receipt", certificate: "Certificate", card: "Proof Card", proof: "Zero-knowledge proof" };
const L = window.AttestLibs;
const $ = (id) => document.getElementById(id);
const enc = new TextEncoder(), dec = new TextDecoder();
const hex = (b) => Array.from(new Uint8Array(b)).map((x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (h) => new Uint8Array((h.replace(/^0x/, "").match(/../g) || []).map((x) => parseInt(x, 16)));
const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest("SHA-256", typeof bytes === "string" ? enc.encode(bytes) : bytes));
const sha256hex = async (x) => hex(await sha256(x));
const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64url = (s) => b64(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
const toB64url = (b) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
const mono = (s) => `<span class="mono">${esc(s)}</span>`;
const link = (url, text) => (url ? ` · <a href="${esc(url)}" target="_blank" rel="noopener">${esc(text || "explorer")}</a>` : "");
const when = (iso) => (iso ? new Date(iso).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC") : "");

/** Canonical JSON (sorted keys, no whitespace): the exact text Attest fingerprints and anchors. */
function canonicalJson(v) {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v).sort().filter((k) => v[k] !== undefined).map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(",")}}`;
  return JSON.stringify(v);
}

// BN254 scalar field: values the zero-knowledge circuits take as public inputs.
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const fieldOf = async (s) => (BigInt("0x" + (await sha256hex(s))) % P).toString();

// ---- Files attached to a PDF: the streams marked /Type /EmbeddedFile (deflated or not) ----------------
async function inflate(bytes) {
  const s = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate"));
  return new Uint8Array(await new Response(s).arrayBuffer());
}
// Byte offsets must line up with the text view: decode as latin1, never UTF-8.
const latin1 = new TextDecoder("latin1");
async function attachmentsOf(buf) {
  const raw = new Uint8Array(buf), text = latin1.decode(raw), found = [];
  const re = /\/Type\s*\/EmbeddedFile\b/g;
  let m;
  while ((m = re.exec(text))) {
    const dictStart = text.lastIndexOf("<<", m.index);
    const streamAt = text.indexOf("stream", m.index);
    if (streamAt < 0) continue;
    const dict = text.slice(dictStart, streamAt);
    let start = streamAt + 6;
    if (raw[start] === 13) start++;
    if (raw[start] === 10) start++;
    const lenM = /\/Length\s+(\d+)(?!\s+\d+\s+R)/.exec(dict);
    const end = lenM ? start + Number(lenM[1]) : text.indexOf("endstream", start);
    let body = raw.slice(start, end);
    if (/\/Filter\s*\/FlateDecode/.test(dict)) {
      if (typeof DecompressionStream === "undefined") { found.noInflate = true; continue; }
      try { body = await inflate(body); } catch { continue; }
    }
    found.push(body);
  }
  return found;
}

// ---- WebAuthn (passkey) signatures ------------------------------------------------------------------
function derToRaw(der) {
  let i = 2; if (der[1] & 0x80) i += der[1] & 0x7f;
  const read = () => { i++; let len = der[i++]; let v = der.slice(i, i + len); i += len; while (v.length > 32 && v[0] === 0) v = v.slice(1); const out = new Uint8Array(32); out.set(v, 32 - v.length); return out; };
  const r = read(), s = read(); const raw = new Uint8Array(64); raw.set(r); raw.set(s, 32); return raw;
}
/** One passkey assertion over sha256(statement): { statement, authenticatorData, clientDataJSON, signature, publicKeySpki, alg }. */
async function passkeyCheck(e, rp) {
  const clientBytes = b64url(e.clientDataJSON), client = JSON.parse(dec.decode(clientBytes));
  const challengeOk = client.type === "webauthn.get" && client.challenge === toB64url(await sha256(e.statement));
  const originOk = !rp || client.origin === rp.origin;
  const auth = b64url(e.authenticatorData);
  const rpHash = rp ? await sha256(rp.rpId) : null;
  const rpOk = !rp || (auth.length >= 37 && rpHash.every((b, i) => auth[i] === b));
  const flags = auth[32] || 0, present = (flags & 1) !== 0, verified = (flags & 4) !== 0;
  const data = new Uint8Array(auth.length + 32); data.set(auth); data.set(await sha256(clientBytes), auth.length);
  const spki = b64(e.publicKeySpki), sig = b64url(e.signature);
  let sigOk = false;
  if (e.alg === -7) sigOk = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]), derToRaw(sig), data);
  else if (e.alg === -257) sigOk = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", await crypto.subtle.importKey("spki", spki, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]), sig, data);
  else if (e.alg === -8) sigOk = await crypto.subtle.verify({ name: "Ed25519" }, await crypto.subtle.importKey("spki", spki, { name: "Ed25519" }, false, ["verify"]), sig, data);
  return { ok: challengeOk && originOk && rpOk && present && verified && sigOk, parts: { challengeOk, originOk, rpOk, present, verified, sigOk }, origin: client.origin };
}
const webauthnValid = (s, rp) =>
  passkeyCheck({ statement: s.statement, ...s.webauthnAssertion, publicKeySpki: s.passkey.publicKeySpki, alg: s.passkey.alg }, rp);

// ---- The public blockchain --------------------------------------------------------------------------
async function rpc(url, method, params) {
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  const j = await r.json();
  if (j.error) throw new Error(j.error.message);
  return j.result;
}
// The node field is an override: when empty, each check uses the node its evidence names for its own chain.
const nodeUrl = (fallback) => $("rpc").value.trim() || fallback || null;
function rememberNode(url) { if (url && !$("rpc").value) $("rpc").placeholder = `${url} (from the evidence)`; }

/** Fold a Merkle path (sorted pairs, SHA-256) from a leaf; the result should be the anchored root. */
async function foldPath(leaf, path) {
  let node = leaf.replace(/^0x/, "").toLowerCase();
  for (const sib0 of path || []) {
    const sib = sib0.replace(/^0x/, "").toLowerCase();
    const [lo, hi] = node <= sib ? [node, sib] : [sib, node];
    const both = new Uint8Array(64); both.set(unhex(lo)); both.set(unhex(hi), 32);
    node = await sha256hex(both);
  }
  return node;
}

/** The transaction's log from the registry recording `root`, and when it was mined. */
async function rootInTx(url, txHash, contract, root) {
  const rc = await rpc(url, "eth_getTransactionReceipt", [txHash]);
  const r = root.replace(/^0x/, "").toLowerCase();
  if (!rc) return { missing: true };
  const log = rc.logs.find((l) => (!contract || l.address.toLowerCase() === contract.toLowerCase()) && l.data.toLowerCase().startsWith("0x" + r));
  if (rc.status !== "0x1" || !log) return null;
  const block = await rpc(url, "eth_getBlockByNumber", [rc.blockNumber, false]);
  return { block: parseInt(rc.blockNumber, 16), at: new Date(parseInt(block.timestamp, 16) * 1000).toISOString(), from: rc.from };
}

/** isAnchored(bytes32) on the registry: whether a value is on chain, when, and from which wallet. */
async function isAnchored(url, contract, value) {
  const v = value.replace(/^0x/, "").toLowerCase().padStart(64, "0");
  const r = await rpc(url, "eth_call", [{ to: contract, data: `0x4f0b5801${v}` }, "latest"]);
  const anchored = BigInt(`0x${r.slice(2, 66) || "0"}`) === 1n;
  return anchored ? { anchored, at: new Date(Number(BigInt(`0x${r.slice(66, 130)}`)) * 1000).toISOString(), from: `0x${r.slice(154, 194)}`.toLowerCase() } : { anchored: false };
}

/**
 * Check an anchor from an evidence file: a receipt in a Merkle batch ({type:"merkle"}), an organization event
 * ({type:"event"}), or a single value ({type:"value"}). `expect` is the fingerprint the anchor must commit to.
 */
async function checkAnchor(label, a, expect, chain) {
  if (!a) { add("warn", `${label}: not anchored yet`, "Anchoring follows within minutes. Download the evidence again later to check it on chain."); return null; }
  const url = nodeUrl(a.rpc || (chain && chain.rpc));
  rememberNode(url);
  const contract = a.contract || (chain && chain.contract);
  let root;
  if (a.type === "merkle") {
    const leaf = await sha256hex(`${a.receiptId}:${expect.toLowerCase()}`);
    if (leaf !== String(a.leaf).replace(/^0x/, "")) { add("bad", `${label}: the anchored record is for a different fingerprint`, `Leaf ${mono(leaf)}`); return null; }
    root = await foldPath(leaf, a.merkleProof);
    if (root !== String(a.merkleRoot).replace(/^0x/, "").toLowerCase()) { add("bad", `${label}: the Merkle path doesn't reach the anchored root`, `Computed ${mono(root)}`); return null; }
  } else if (a.type === "event") {
    root = await sha256hex(`attest.event.v1|${a.eventId}|${expect.toLowerCase()}`);
    if (a.digest && a.digest !== expect) { add("bad", `${label}: the anchored event is for a different fingerprint`, ""); return null; }
  } else root = expect.replace(/^0x/, "").toLowerCase();
  if (!url) { add("warn", `${label}: the on-chain check needs a public node`, "Enter one above, then drop the file again."); return null; }
  try {
    const t = await rootInTx(url, a.txHash, contract, root);
    if (t && t.missing) { add("bad", `${label}: the anchoring transaction doesn't exist on chain ${esc(a.chainId)}`, `Transaction ${mono(a.txHash)}, looked up on ${esc(url)}`); return null; }
    if (!t) { add("bad", `${label}: the transaction does not record this value`, `Transaction ${mono(a.txHash)}`); return null; }
    add("ok", `${label}: anchored on the public blockchain`, `Chain ${esc(a.chainId)}, block ${t.block}, ${when(t.at)}. Transaction ${mono(a.txHash)}${link(a.explorer)}`);
    return t;
  } catch (e) {
    add("warn", `${label}: the on-chain check couldn't run here`, `${esc(e.message)}. Check your connection, or enter another public node of chain ${esc(a.chainId)} above, then drop the file again.`);
    return null;
  }
}

/**
 * The issuer's key, as committed on chain by the organization's wallet:
 * isAnchored(sha256("attest.issuer_key.v1|" + did + "|" + publicKeyMultibase + "|" + canonicalJson(publicKeyJwk))).
 */
async function checkIssuerKey(issuer, chain, issuedAt) {
  const doc = issuer.didDocument || {};
  if (doc.id !== issuer.did) { add("bad", "The issuer's DID document is for a different issuer", ""); return null; }
  const vms = doc.verificationMethod || [];
  const multi = vms.find((m) => m.publicKeyMultibase), jwkVm = vms.find((m) => m.publicKeyJwk);
  if (!multi || !jwkVm) { add("bad", "The issuer's DID document has no signing key", ""); return null; }
  const value = await sha256hex(`attest.issuer_key.v1|${issuer.did}|${multi.publicKeyMultibase}|${canonicalJson(jwkVm.publicKeyJwk)}`);
  const url = nodeUrl(chain && chain.rpc);
  rememberNode(url);
  if (!url || !chain || !chain.contract) { add("warn", "The issuer's key commitment couldn't be looked up", "Enter a public node above."); return { doc, wallet: null }; }
  try {
    const r = await isAnchored(url, chain.contract, value);
    if (!r.anchored) {
      add("warn", `The issuer's key isn't committed on chain yet`, `Attest commits every issuer's key on chain from the organization's own wallet, before its first use. ${esc(issuer.name || issuer.did)}'s isn't yet, so it comes only from this evidence file. Download the evidence again later.`);
      return { doc, wallet: null };
    }
    const before = !issuedAt || new Date(r.at) <= new Date(issuedAt);
    add(
      "ok",
      `The issuer's key was committed on chain by ${esc(issuer.name || "the issuer")}`,
      `On ${when(r.at)}, by wallet ${mono(r.from)}${before ? ", before this record was issued" : `, after this record was issued (${when(issuedAt)})`}. A key swapped in later would carry a later date and a different value.`,
    );
    return { doc, wallet: r.from, at: r.at };
  } catch (e) {
    add("warn", "The issuer's key commitment couldn't be looked up", esc(e.message));
    return { doc, wallet: null };
  }
}

/** ES256 JWS (vc+jwt) against a P-256 JWK. */
async function jwsValid(jws, jwk) {
  const [h, p, s] = jws.split(".");
  const key = await crypto.subtle.importKey("jwk", { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, b64url(s), enc.encode(`${h}.${p}`));
  return { ok, header: JSON.parse(dec.decode(b64url(h))), payload: JSON.parse(dec.decode(b64url(p))) };
}

/** Groth16 over BN254, in this page (src/groth16.mjs). */
async function groth16(vk, signals, proof) {
  return L.verifyGroth16(vk, signals, proof);
}

// ---- Results ----------------------------------------------------------------------------------------
let results = [];
const add = (state, title, detail) => results.push({ state, title, detail });
const headline = {
  agreement: "Verified: the document, every signature and entry, the signed state and its anchor on the public blockchain.",
  receipt: "Verified: this fingerprint was recorded and anchored on the public blockchain, and has not changed since.",
  certificate: "Verified: the content, every signature, the issuer's signature and key, and the anchor on the public blockchain.",
  card: "Verified: the issuer's signature and key, the holder's approval, the anchors and the current status on the public blockchain.",
  proof: "Verified: the zero-knowledge proof, what it reveals, and the anchored record it proves against.",
};
function render(kind, title, sub) {
  const failed = results.some((r) => r.state === "bad");
  if (results.length === 1 && /newer evidence format/.test(results[0].title)) {
    $("out").innerHTML = `<div class="verdict bad">Not checked: this record is newer than this verifier. Get the latest verifier to check it.</div><div class="card"><div class="row"><span class="icon warn">!</span><div><div class="title">${esc(results[0].title)}</div><div class="detail">${results[0].detail}</div></div></div></div>`;
    return;
  }
  const unknown = results.some((r) => r.state === "warn");
  const icon = { ok: "✓", bad: "✕", warn: "!", info: "i" };
  $("out").innerHTML =
    `<div class="verdict ${failed ? "bad" : "ok"}">${failed ? "This record does not verify: see the failed checks below." : unknown ? "Every check that could run passed. Some could not run here (see below)." : headline[kind] || "Verified."}</div>` +
    `<h2>${esc(title || KINDS[kind] || "Record")}</h2>${sub ? `<p class="small">${sub}</p>` : ""}` +
    `<div class="card">${results.map((r) => `<div class="row"><span class="icon ${r.state}">${icon[r.state]}</span><div><div class="title">${esc(r.title)}</div>${r.detail ? `<div class="detail">${r.detail}</div>` : ""}</div></div>`).join("")}</div>`;
}

/** The evidence's kind and format version, or null if it isn't Attest evidence. */
function formatOf(ev) {
  const m = ev && typeof ev.format === "string" && /^attest\.(agreement|receipt|certificate|card|proof)_evidence\.v(\d+)$/.exec(ev.format);
  if (m) return { kind: m[1], v: Number(m[2]) };
  const other = ev && typeof ev.format === "string" && /^attest\.([a-z_]+)\.v(\d+)$/.exec(ev.format);
  return other ? { kind: other[1], v: Number(other[2]), unknown: true } : null;
}

// ============================================================================================ agreements
/** Agreement evidence v1 (signed copies before October 10, 2026), mapped onto v2's shape. It carries the
 *  signatures and the fingerprints, but not the signed state's text or the anchor's Merkle path. */
function fromV1(e) {
  const origin = (() => { try { return new URL(e.verify).origin; } catch { return null; } })();
  return {
    format: e.format,
    legacy: true,
    agreementId: e.agreementId,
    title: e.title,
    completedAt: e.completedAt,
    verificationCode: null,
    document: { sha256: e.documentSha256, file: null },
    webauthn: origin ? { origin, rpId: new URL(origin).hostname } : null,
    signers: (e.signers || []).map((s) => ({
      email: s.email,
      name: s.name,
      signedAt: s.signedAt,
      statement: s.consentJson || null,
      entries: null,
      entriesSha256: s.entriesSha256 || null,
      passkey: s.passkeyPublicKey ? { publicKeySpki: s.passkeyPublicKey, alg: s.passkeyAlg } : null,
      webauthnAssertion: s.signature ? { authenticatorData: s.authenticatorData, clientDataJSON: s.clientDataJSON, signature: s.signature } : null,
    })),
    signedState: e.signedStateSha256 ? { message: null, sha256: e.signedStateSha256 } : null,
    anchor: e.anchor ? { chainId: e.anchor.chainId, txHash: e.anchor.txHash, explorer: e.anchor.explorer, receiptId: e.anchor.receiptId, rpc: null, merkleRoot: null, merkleProof: [] } : null,
    proofs: (e.proofs || []).map((p) => ({ id: p.id, statement: null, proof: null, zkverify: { status: p.zkverifyStatus, txHash: p.zkverifyTxHash } })),
  };
}

async function verifyAgreement(ev, files) {
  if (ev.legacy !== true && /\.v1$/.test(ev.format)) ev = fromV1(ev);
  const original = files.pdf;
  // 1. The document
  if (original) {
    const h = await sha256hex(original);
    add(h === ev.document.sha256 ? "ok" : "bad", h === ev.document.sha256 ? "The document is exactly the one signed" : "The document does not match what was signed", `SHA-256 ${mono(h)}`);
  } else add("warn", "The original document wasn't found", "It's attached to the signed copy as original-document.pdf.");
  // 2-4. Each signer
  for (const s of ev.signers) {
    let st = null;
    try { st = JSON.parse(s.statement); } catch {}
    if (!st || !s.webauthnAssertion || !s.passkey) { add("bad", `${s.name || s.email}: no signature evidence`, ""); continue; }
    if (s.entries != null) {
      const eh = await sha256hex(s.entries);
      add(eh === s.entriesSha256 ? "ok" : "bad", `${s.name || s.email}: entries match what they signed`, `Entries SHA-256 ${mono(eh)}`);
    }
    const namesDoc = st.documentSha256 === ev.document.sha256;
    const namesEntries = !s.entriesSha256 || st.fieldsSha256 === s.entriesSha256;
    add(namesDoc && namesEntries ? "ok" : "bad", `${s.name || s.email}: the statement names this document${s.entriesSha256 ? " and these entries" : ""}`, esc(st.statement || ""));
    try {
      const w = await webauthnValid(s, ev.webauthn);
      add(w.ok ? "ok" : "bad", `${s.name || s.email}: passkey signature valid`, w.ok ? `Signed ${esc(s.signedAt || st.signedAt || "")} on ${esc(w.origin)}, with the user present and verified` : esc(JSON.stringify(w.parts)));
    } catch (e) { add("bad", `${s.name || s.email}: passkey signature could not be checked`, esc(e.message)); }
  }
  // 5. The signed state
  const ss = ev.signedState;
  let stateOk = false;
  if (ss && ss.message) {
    const h = await sha256hex(ss.message);
    let m = null; try { m = JSON.parse(ss.message); } catch {}
    const covers = m && m.documentSha256 === ev.document.sha256 && ev.signers.every((s) => m.signers.some((x) => x.email === s.email.toLowerCase() && (!s.entriesSha256 || x.fieldsSha256 === s.entriesSha256)));
    stateOk = h === ss.sha256 && covers;
    add(stateOk ? "ok" : "bad", "The signed state covers the document and every signer", `SHA-256 ${mono(h)}`);
  } else if (ev.legacy && ss) {
    add("warn", "This older format doesn't carry the signed state's text", `Its fingerprint is ${mono(ss.sha256)}; signed copies made from October 10, 2026 carry the text, so it can be recomputed.`);
  } else add("bad", "The signed state is missing", "");
  // 6-7. The Merkle path, and the transaction that anchors its root
  const an = ev.anchor;
  if (ev.legacy) {
    add("warn", "This older format doesn't carry the anchor's Merkle path", an && an.txHash ? `The anchoring transaction is ${mono(an.txHash)}${link(an.explorer)}. Signed copies made from October 10, 2026 carry the full path.` : "");
  } else if (an && ss && an.merkleRoot) {
    await checkAnchor("The signed state", { ...an, type: "merkle" }, ss.sha256, null);
  } else add("bad", "The anchor's Merkle path is missing", "");
  // 8. Zero-knowledge proofs about this agreement
  for (const p of ev.proofs || []) {
    if (!p.proof || !p.verificationKey) continue;
    await checkAgreementProof({ ...p, revealed: p.revealed || {} }, null, `Proof ${p.id}`, an ? { rpc: an.rpc, contract: an.contract } : null);
  }
  render("agreement", ev.title || "Signed agreement", `${ev.verificationCode ? `Verification code ATT-${esc(ev.verificationCode.slice(0, 4))}-${esc(ev.verificationCode.slice(4))} · ` : ""}completed ${esc(ev.completedAt || "")}`);
}

// ============================================================================================== receipts
async function verifyReceipt(ev, files) {
  const r = ev.receipt;
  if (files.other) {
    const h = await sha256hex(files.other);
    add(h === r.sha256 ? "ok" : "bad", h === r.sha256 ? `${files.otherName} is exactly the recorded content` : `${files.otherName} is not the recorded content`, `SHA-256 ${mono(h)}`);
  } else if (!ev.zkProof) add("info", "Drop the file too, to check it is the recorded content", `Recorded fingerprint ${mono(r.sha256)}. Nothing is uploaded.`);
  if (ev.zkProof) {
    const z = ev.zkProof;
    if (z.verificationKey && z.proof) {
      let ok = false;
      try { ok = await groth16(z.verificationKey, z.publicSignals, z.proof); } catch {}
      add(ok ? "ok" : "bad", ok ? `The zero-knowledge proof is valid: ${z.statement}` : "The zero-knowledge proof is not valid", `Circuit ${esc(z.circuit)}, checked here with Groth16 (BN254).`);
      if (z.circuit === "security_scan_proof_v2") {
        const bound = (await sha256hex(`attest.scan.v2|${z.publicSignals[1]}`)) === r.sha256;
        add(bound ? "ok" : "bad", "The proof is about this receipt's commitment", `Commitment ${mono(z.publicSignals[1])}; the receipt records sha256("attest.scan.v2|" + commitment).`);
        add(z.publicSignals[0] === "1" ? "ok" : "bad", z.publicSignals[0] === "1" ? "The predicate holds" : "The predicate does NOT hold", "Proven without revealing the underlying scan.");
      }
    } else add("warn", "This proof's verification key isn't public", "It's an earlier circuit; Attest verified it when it was made.");
    if (z.zkverify && z.zkverify.txHash) add("info", "Also verified on zkVerify", mono(z.zkverify.txHash));
  }
  await checkAnchor("The receipt", ev.anchor, r.sha256, null);
  if (r.supersededBy && r.supersededBy.length) add("warn", "A correcting receipt supersedes this one", esc(r.supersededBy.join(", ")));
  render("receipt", r.claim || "Receipt", `${esc(r.id)} · ${esc(r.kind)} · created ${when(r.createdAt)}`);
}

// ========================================================================================== certificates
async function verifyCertificate(ev, files) {
  const c = ev.certificate;
  // Content
  const ch = await sha256hex(canonicalJson(c.content));
  add(ch === c.contentSha256 ? "ok" : "bad", "The certificate's content is exactly what was signed", `SHA-256 of its canonical JSON ${mono(ch)}`);
  // Signers
  for (const s of ev.signers) {
    if (!s.evidence) { add("bad", `${s.name}: no signature evidence`, ""); continue; }
    let st = null; try { st = JSON.parse(s.evidence.consentJson); } catch {}
    const names = st && st.certificate === c.id && st.contentSha256 === c.contentSha256;
    add(names ? "ok" : "bad", `${s.name}${s.role ? ` (${s.role})` : ""}: the statement names this certificate and content`, "");
    try {
      const w = await passkeyCheck({ statement: s.evidence.consentJson, authenticatorData: s.evidence.authenticatorData, clientDataJSON: s.evidence.clientDataJSON, signature: s.evidence.signature, publicKeySpki: s.evidence.publicKeySpki, alg: s.evidence.alg }, ev.webauthn);
      add(w.ok ? "ok" : "bad", `${s.name}: passkey signature valid`, w.ok ? `Signed ${when(s.signedAt)} on ${esc(w.origin)}, with the user present and verified` : esc(JSON.stringify(w.parts)));
    } catch (e) { add("bad", `${s.name}: passkey signature could not be checked`, esc(e.message)); }
  }
  // Issuer key and signature
  const key = await checkIssuerKey(ev.issuer, ev.chain, c.issuedAt);
  if (c.vcJwt && key) {
    try {
      const kid = JSON.parse(dec.decode(b64url(c.vcJwt.split(".")[0]))).kid;
      const vm = (key.doc.verificationMethod || []).find((m) => m.id === kid && m.publicKeyJwk);
      const j = vm ? await jwsValid(c.vcJwt, vm.publicKeyJwk) : { ok: false };
      const p = j.payload || {};
      const ok = j.ok && p.issuer && p.issuer.id === ev.issuer.did && p.credentialSubject && p.credentialSubject.contentSha256 === c.contentSha256;
      add(ok ? "ok" : "bad", `Signed by the issuer, ${ev.issuer.name}`, `W3C Verifiable Credential (vc+jwt, ES256), key ${mono(kid || "")}`);
    } catch (e) { add("bad", "The issuer's signature could not be checked", esc(e.message)); }
  }
  // The PDF
  if (files.pdf) {
    const h = await sha256hex(files.pdf);
    add(h === c.pdfSha256 ? "ok" : "bad", h === c.pdfSha256 ? "The PDF is exactly the issued certificate" : "The PDF is not the issued certificate", `SHA-256 ${mono(h)}`);
  } else add("info", "Drop the certificate PDF too, to check it is the issued one", `Its fingerprint is ${mono(c.pdfSha256 || "")}.`);
  // Issuance anchor, from the organization's wallet
  let issuanceWallet = null;
  if (c.pdfSha256 && c.vcJwt && ev.anchor) {
    const value = await sha256hex(`attest.certificate.v1|${c.id}|${c.pdfSha256}|${await sha256hex(c.vcJwt)}`);
    const t = await checkAnchor("The issued certificate", { ...ev.anchor, type: "value" }, value, ev.chain);
    issuanceWallet = t && t.from ? t.from.toLowerCase() : null;
    if (issuanceWallet && key && key.wallet) add(issuanceWallet === key.wallet ? "ok" : "bad", issuanceWallet === key.wallet ? "Anchored by the same wallet that committed the issuer's key" : "Anchored by a different wallet than the one that committed the issuer's key", mono(issuanceWallet));
  } else if (!ev.anchor) add("warn", "The certificate isn't anchored yet", "");
  // Current status, read from the chain
  const url = nodeUrl(ev.chain && ev.chain.rpc);
  if (url && ev.chain && ev.chain.contract) {
    try {
      const r = await isAnchored(url, ev.chain.contract, await sha256hex(`attest.certificate.revoked.v2|${c.id}`));
      const byIssuer = r.anchored && (!key || !key.wallet || r.from === key.wallet);
      if (byIssuer) add("bad", "Revoked", `Revoked on ${when(r.at)} by the issuer's wallet ${mono(r.from)}, read from the chain just now.${ev.revocation && ev.revocation.reason ? ` Reason given: ${esc(ev.revocation.reason)}` : ""}`);
      else if (ev.revocation) add("bad", "Revoked", `On ${when(ev.revocation.revokedAt)}, per the evidence. Reason: ${esc(ev.revocation.reason || "")}`);
      else add("ok", "Not revoked", "Read from the chain just now: no revocation has been anchored for this certificate.");
    } catch (e) {
      if (ev.revocation) add("bad", "Revoked", `On ${when(ev.revocation.revokedAt)}, per the evidence. Reason: ${esc(ev.revocation.reason || "")}`);
      add("warn", "The current status couldn't be read from the chain", esc(e.message));
    }
  } else if (ev.revocation) add("bad", "Revoked", `On ${when(ev.revocation.revokedAt)}. Reason: ${esc(ev.revocation.reason || "")}`);
  if (c.validUntil && new Date(c.validUntil) < new Date()) add("warn", "Expired", `Valid until ${when(c.validUntil)}.`);
  // Findings closure proof
  const z = ev.findingsClosure;
  if (z && z.verificationKey) {
    const context = (BigInt("0x" + (await sha256hex(`attest.certificate.findings|${c.id}`))) % P).toString();
    const inContent = c.content && c.content.findingsClosure && c.content.findingsClosure.commitment;
    let ok = false;
    try { ok = z.publicSignals[1] === context && z.publicSignals[0] === z.commitment && inContent === BigInt(z.commitment).toString(16).padStart(64, "0") && (await groth16(z.verificationKey, z.publicSignals, z.proof)); } catch {}
    add(ok ? "ok" : "bad", "Zero-knowledge proof: every finding in the assessed set is closed", "Bound to this certificate and to the commitment in its signed content; checked here with Groth16.");
  }
  render("certificate", c.title, `${esc(c.id)} · issued by ${esc(ev.issuer.name)} · ${when(c.issuedAt)}`);
}

// ============================================================================================ Proof Cards
/** Documents the credential and its status lists refer to: standard contexts (bundled), the cards context
 *  (bundled), and the issuer's DID document and status lists (from the evidence, checked against the chain). */
function loaderFor(ev) {
  const base = L.securityLoader().build();
  const doc = (url, document) => ({ contextUrl: null, documentUrl: url, document });
  const did = ev.issuer.didDocument;
  const lists = Object.fromEntries((ev.statusLists || []).map((l) => [l.url, l.credential]));
  return async (url) => {
    if (L.contexts[url]) return doc(url, L.contexts[url]);
    if (url === did.id) return doc(url, did);
    if (url.startsWith(did.id + "#")) {
      const vm = (did.verificationMethod || []).find((m) => m.id === url);
      if (!vm) throw new Error(`Unknown key: ${url}`);
      return doc(url, vm.publicKeyMultibase ? { "@context": "https://w3id.org/security/multikey/v1", ...vm } : { "@context": "https://w3id.org/security/suites/jws-2020/v1", ...vm });
    }
    if (lists[url]) return doc(url, lists[url]);
    return base(url);
  };
}

/** sha256 of the issuer's base signature inside an ecdsa-sd-2023 proof (what issuance anchors commit to). */
async function baseSignatureSha256(cred) {
  const proofs = Array.isArray(cred.proof) ? cred.proof : [cred.proof];
  const p = proofs.find((x) => x && x.cryptosuite === "ecdsa-sd-2023");
  if (!p || typeof p.proofValue !== "string" || !p.proofValue.startsWith("u")) return null;
  const bytes = b64url(p.proofValue.slice(1));
  if (bytes[0] !== 0xd9 || bytes[1] !== 0x5d) return null;
  const tags = []; tags[64] = (x) => new Uint8Array(x);
  const [sig] = L.cborg.decode(bytes.subarray(3), { useMaps: true, tags });
  return sig instanceof Uint8Array ? sha256hex(sig) : null;
}

async function verifyCard(ev) {
  const cred = ev.credential;
  const subject = cred.credentialSubject || {};
  // Holder's approval of this exact disclosure
  const h = ev.holderApproval;
  if (h) {
    let st = null; try { st = JSON.parse(h.statementJson); } catch {}
    const disclosed = await sha256hex(canonicalJson(cred));
    const names = st && st.disclosedSha256 === disclosed && st.credentialId === cred.id;
    add(names ? "ok" : "bad", "The holder approved sharing exactly this copy", `${esc(st ? st.statement || "" : "")} Disclosed copy SHA-256 ${mono(disclosed)}`);
    try {
      const w = await passkeyCheck({ statement: h.statementJson, authenticatorData: h.authenticatorData, clientDataJSON: h.clientDataJSON, signature: h.signature, publicKeySpki: h.publicKeySpki, alg: h.alg }, ev.webauthn);
      add(w.ok ? "ok" : "bad", "The holder's passkey signature is valid", w.ok ? `Approved ${when(h.approvedAt)} on ${esc(w.origin)}, with the user present and verified` : esc(JSON.stringify(w.parts)));
    } catch (e) { add("bad", "The holder's passkey signature could not be checked", esc(e.message)); }
  } else add("warn", "This share has no passkey approval", "It was shared before approvals existed.");
  // The vocabulary this verifier carries for the card's fields: the version Attest committed on chain.
  const ctxUrls = (Array.isArray(cred["@context"]) ? cred["@context"] : [cred["@context"]]).filter((u) => typeof u === "string" && L.contexts[u] && u.startsWith("https://attest.datahubz.com/"));
  for (const u of ctxUrls) {
    const url = nodeUrl(ev.chain && ev.chain.rpc);
    rememberNode(url);
    if (!url || !ev.chain || !ev.chain.contract) break;
    try {
      const r = await isAnchored(url, ev.chain.contract, await sha256hex(`attest.context.v1|${u}|${canonicalJson(L.contexts[u])}`));
      add(r.anchored ? "ok" : "warn", r.anchored ? "The card's vocabulary is the version Attest committed on chain" : "The card's vocabulary isn't committed on chain yet", `${mono(u)}${r.anchored ? `, committed ${when(r.at)}. This verifier carries its own copy, so a file can't redefine what the fields mean.` : ". This verifier carries its own copy, so a file can't redefine what the fields mean."}`);
    } catch (e) { add("warn", "The card's vocabulary commitment couldn't be looked up", esc(e.message)); }
  }
  // Issuer key, then the issuer's signature and the signed status lists (W3C Data Integrity, checked here)
  const key = await checkIssuerKey(ev.issuer, ev.chain, cred.validFrom);
  const loader = loaderFor(ev);
  const suite = [new L.DataIntegrityProof({ cryptosuite: L.createVerifyCryptosuite() }), new L.DataIntegrityProof({ cryptosuite: L.ecdsaRdfc2019 })];
  const validUntil = cred.validUntil ? new Date(cred.validUntil) : null;
  const at = validUntil && validUntil < new Date() ? new Date(validUntil.getTime() - 1000) : new Date();
  try {
    const r = await L.vc.verifyCredential({ credential: cred, suite, documentLoader: loader, checkStatus: L.checkStatus, now: at });
    const sigOk = Boolean(r.results && r.results.some((x) => x.verified));
    const why = sigOk ? "" : (() => { const e = (r.results || []).map((x) => x.error).find(Boolean) || r.error; const m = e && [e.message || (e.errors && e.errors[0] && e.errors[0].message), e.cause && e.cause.message].filter(Boolean).join(": "); return m ? ` (${esc(m)})` : ""; })();
    add(sigOk ? "ok" : "bad", `Signed by the issuer, ${ev.issuer.name}`, `W3C Verifiable Credential with selective disclosure (ecdsa-sd-2023): only the fields shown were revealed, and each is covered by the issuer's signature.${why}`);
    const sts = (r.statusResult && r.statusResult.results) || [];
    for (const s of sts) {
      const purpose = s.credentialStatus && s.credentialStatus.statusPurpose;
      add(s.verified ? (s.status ? "bad" : "ok") : "bad", `${purpose === "suspension" ? "Suspension" : "Revocation"} list: ${s.status ? (purpose === "suspension" ? "suspended" : "revoked") : "clear"}`, "The issuer's signed status list in this evidence file.");
    }
  } catch (e) { add("bad", "The issuer's signature could not be checked", esc(e.message)); }
  // Each status list version is anchored
  for (const l of ev.statusLists || []) {
    const lh = await sha256hex(canonicalJson(l.credential));
    if (l.sha256 && lh !== l.sha256) { add("bad", `The ${l.purpose} list is not the anchored version`, ""); continue; }
    await checkAnchor(`The ${l.purpose} list (version ${l.version})`, l.anchor, lh, ev.chain);
  }
  // Issuance anchor: sha256 of the issuer's base signature, which this copy carries
  const bs = await baseSignatureSha256(cred);
  if (bs && ev.issuance) {
    if (ev.issuance.baseSignatureSha256 && bs !== ev.issuance.baseSignatureSha256) add("bad", "The issuance anchor is for a different card", "");
    else await checkAnchor("The card's issuance", ev.issuance.anchor, bs, ev.chain);
  }
  // Current status, read from the chain: the latest of sha256("attest.card.status.v1|" + cardId + "|" + n + "|" + state)
  const url = nodeUrl(ev.chain && ev.chain.rpc);
  if (url && ev.chain && ev.chain.contract && ev.status) {
    try {
      let state = "active", at = null;
      for (let n = 1; n < 200; n++) {
        let hit = null;
        for (const s of ["revoked", "suspended", "active"]) {
          const r = await isAnchored(url, ev.chain.contract, await sha256hex(`attest.card.status.v1|${ev.status.cardId}|${n}|${s}`));
          if (r.anchored && (!key || !key.wallet || r.from === key.wallet)) { hit = { s, at: r.at }; break; }
        }
        if (!hit) break;
        state = hit.s; at = hit.at;
      }
      add(state === "active" ? "ok" : "bad", state === "active" ? "Active now" : state === "revoked" ? "Revoked" : "Suspended", `Read from the chain just now${at ? `: last change on ${when(at)}, by the issuer's wallet` : ": no status change has been anchored"}.`);
    } catch (e) { add("warn", "The current status couldn't be read from the chain", esc(e.message)); }
  }
  if (validUntil && validUntil < new Date()) add("warn", "Expired", `Valid until ${when(cred.validUntil)}.`);
  const shown = Object.entries(subject).filter(([k]) => k !== "id" && k !== "type").map(([k, v]) => `${esc(k)}: ${esc(typeof v === "object" ? JSON.stringify(v) : v)}`).join(" · ");
  render("card", cred.name || "Proof Card", `Issued by ${esc(ev.issuer.name)}${shown ? ` · ${shown}` : ""}`);
}

// ======================================================================================= agreement proofs
/** An agreement proof: Groth16, its public inputs recomputed from what it reveals, and its anchored root. */
async function checkAgreementProof(p, root, label, chain) {
  const withParty = p.circuit === "agreement_with_party";
  const sig = p.publicSignals || [];
  let ok = false;
  try { ok = await groth16(p.verificationKey, sig, p.proof); } catch {}
  add(ok ? "ok" : "bad", ok ? `${label}: the zero-knowledge proof is valid` : `${label}: the zero-knowledge proof is not valid`, `${esc(p.statement || "")} Circuit ${esc(p.circuit)}, checked here with Groth16 (BN254).`);
  const r = p.revealed || {};
  if (r.party) {
    const party = (await fieldOf(r.party.trim().toLowerCase())) === sig[1];
    const counter = !withParty || (r.counterparty && (await fieldOf(r.counterparty.trim().toLowerCase())) === sig[2]);
    add(party && counter ? "ok" : "bad", `${label}: it is about ${withParty ? `${r.party} and ${r.counterparty}` : r.party}`, "Each email's field element, sha256(email) mod p, matches the proof's public input.");
  }
  const daySig = sig[withParty ? 3 : 2];
  if (daySig != null) {
    const date = new Date(Number(daySig) * 86400000).toISOString().slice(0, 10);
    add(!r.dateISO || r.dateISO === date ? "ok" : "bad", `${label}: completed on ${date}`, "The completion day is a public input of the proof.");
  }
  const salt = await fieldOf("attest.identity.v1");
  if (sig[withParty ? 4 : 3] !== salt) add("bad", `${label}: unexpected identity salt`, "");
  const rootHex = BigInt(sig[0] || "0").toString(16).padStart(64, "0");
  if (root && root.value && root.value.replace(/^0x/, "").toLowerCase() !== rootHex) add("bad", `${label}: proven against a different root than the evidence names`, "");
  // The root commits to every completed agreement on Attest; it is anchored as a single value: isAnchored(root).
  const ra = root && root.anchor;
  const url = nodeUrl((ra && ra.rpc) || (chain && chain.rpc));
  rememberNode(url);
  const contract = (ra && ra.contract) || (chain && chain.contract);
  if (url && contract) {
    try {
      const a = await isAnchored(url, contract, rootHex);
      add(a.anchored ? "ok" : "warn", a.anchored ? `${label}: the record it proves against is anchored` : `${label}: the record it proves against isn't anchored yet`, a.anchored ? `Root ${mono("0x" + rootHex)}, anchored ${when(a.at)}${ra ? link(ra.explorer) : ""}` : `Root ${mono("0x" + rootHex)}. Anchoring follows within minutes.`);
    } catch (e) { add("warn", `${label}: the on-chain check couldn't run here`, esc(e.message)); }
  } else add("warn", `${label}: the anchored record couldn't be looked up`, `Root ${mono("0x" + rootHex)}. Enter a public node above.`);
  if (p.zkverify && p.zkverify.txHash) add("info", `${label}: also verified on zkVerify`, mono(p.zkverify.txHash));
}

async function verifyProof(ev) {
  const p = ev.proof;
  if (!p.verificationKey) add("bad", "The proof's verification key is missing", "");
  else await checkAgreementProof(p, ev.root, "The proof", ev.chain);
  render("proof", p.statement, `${esc(p.id)} · ${esc(p.circuit)} · reveals only the names shown and the completion day`);
}

// =================================================================================================== input
async function verify(ev, files) {
  results = [];
  const f = formatOf(ev);
  if (!f) {
    add("bad", "No Attest evidence found", "Drop an Attest signed copy (PDF), or an evidence file (attest-evidence-….json) from a receipt, certificate, Proof Card or proof page.");
    return render(null, "Nothing to check");
  }
  const known = VERIFIER.formats[f.kind];
  if (f.unknown || !known || f.v > Math.max(...known)) {
    add("warn", `This record uses a newer evidence format (${esc(ev.format)})`, `This verifier (version ${VERIFIER.version}) reads ${Object.entries(VERIFIER.formats).map(([k, v]) => `${k} v${v.join(", v")}`).join("; ")}. Get the latest verifier: <a href="${VERIFIER.repo}/releases" target="_blank" rel="noopener">${VERIFIER.repo}</a>, or attest.datahubz.com/attest-verifier.html. The record's evidence is unchanged and stays verifiable.`);
    return render(null);
  }
  if (!L) {
    add("bad", "This copy of the verifier is incomplete", "Its libraries are missing. Download it again from the releases page.");
    return render(f.kind);
  }
  try {
    if (f.kind === "agreement") return await verifyAgreement(f.v === 1 ? fromV1(ev) : ev, files);
    if (f.kind === "receipt") return await verifyReceipt(ev, files);
    if (f.kind === "certificate") return await verifyCertificate(ev, files);
    if (f.kind === "card") return await verifyCard(ev);
    if (f.kind === "proof") return await verifyProof(ev);
  } catch (e) {
    add("bad", "The check stopped with an error", esc(e.message));
    render(f.kind);
  }
}

async function handle(list) {
  if (!window.crypto || !crypto.subtle) {
    $("out").innerHTML = '<div class="verdict bad">This browser can\'t run the checks on this page. Open the file in a current browser, from your disk (file://) or over https.</div>';
    return;
  }
  let ev = null;
  const files = { pdf: null, other: null, otherName: null };
  for (const f of list) {
    const buf = new Uint8Array(await f.arrayBuffer());
    if (/\.json$/i.test(f.name) || buf[0] === 123) {
      try { const j = JSON.parse(dec.decode(buf)); if (j && typeof j.format === "string") { ev = j; continue; } } catch {}
    }
    const isPdf = latin1.decode(buf.slice(0, 5)) === "%PDF-";
    const att = isPdf ? await attachmentsOf(buf) : [];
    let usedAttachment = false;
    for (const b of att) {
      const head = latin1.decode(b.slice(0, 64));
      if (head.startsWith("%PDF")) { files.pdf = b; usedAttachment = true; }
      else if (head.trimStart().startsWith("{")) { try { const j = JSON.parse(dec.decode(b)); if (j.format) { ev = j; usedAttachment = true; } } catch {} }
    }
    if (!usedAttachment) {
      if (isPdf) files.pdf = files.pdf || buf;
      // Any other file: the content a receipt records.
      files.other = buf; files.otherName = f.name;
    }
  }
  if (!ev && list.some((f) => /\.pdf$/i.test(f.name)) && typeof DecompressionStream === "undefined") {
    $("out").innerHTML = '<div class="verdict bad">This browser can\'t open the PDF\'s attachments. Save attest-evidence.json and original-document.pdf from the PDF (any PDF reader lists its attachments) and drop both here.</div>';
    return;
  }
  $("out").innerHTML = '<p class="small">Checking…</p>';
  await verify(ev, files);
}

$("ver").textContent = `Version ${VERIFIER.version} · reads ${Object.keys(VERIFIER.formats).join(", ")} evidence · source and releases: github.com/DataHubz/attest-verifier ·`;
// Opt-in only: nothing is fetched unless this button is clicked.
const newer = (a, b) => { const x = a.split(".").map(Number), y = b.split(".").map(Number); for (let i = 0; i < 3; i++) { if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) > (y[i] || 0); } return false; };
$("update").addEventListener("click", async () => {
  $("updateOut").textContent = "Checking…";
  for (const url of VERIFIER.latest) {
    try {
      const r = await fetch(url, { cache: "no-store" });
      if (!r.ok) continue;
      const l = await r.json();
      $("updateOut").innerHTML = newer(l.version, VERIFIER.version)
        ? `Version ${esc(l.version)} is available: <a href="${esc(l.url)}" target="_blank" rel="noopener">download</a> (SHA-256 ${mono(String(l.sha256).slice(0, 16) + "…")}, anchored on Horizen: check it at attest.datahubz.com/verify).`
        : "This is the latest version.";
      return;
    } catch {}
  }
  $("updateOut").textContent = "Couldn't reach a release list. See github.com/DataHubz/attest-verifier/releases.";
});
const drop = $("drop");
drop.addEventListener("click", () => $("file").click());
drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") $("file").click(); });
$("file").addEventListener("change", (e) => handle([...e.target.files]));
drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); handle([...e.dataTransfer.files]); });
