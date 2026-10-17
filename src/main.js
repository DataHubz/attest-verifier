"use strict";
// This file's version, and the evidence formats it reads. Every release reads every earlier format, so an
// older record verifies with any newer verifier; a record in a newer format is reported as such.
const VERIFIER = {
  version: "1.6.0",
  formats: { agreement: [1, 2, 3, 4, 5, 6], receipt: [1, 2], certificate: [1, 2], card: [1, 2], proof: [1, 2], analytics: [1, 2] },
  repo: "https://github.com/DataHubz/attest-verifier",
  latest: ["https://attest.datahubz.com/attest-verifier/latest.json", "https://raw.githubusercontent.com/DataHubz/attest-verifier/main/latest.json"],
};

/**
 * The trust root, pinned in this file and never read from a file being checked: the chain Attest anchors on, its
 * registries, the registry authority that lists Attest's wallets, and the site where passkeys sign.
 *
 * The registries are open: anyone can anchor any value from any wallet. An anchor counts as Attest's only when its
 * wallet is registered on AttestRegistryV3 by the authority below (and wasn't revoked before the anchor). The
 * authority is fixed in that contract and only ever registers wallets whose keys Attest's signer derives.
 */
const TRUST = {
  chainId: 26514,
  chain: "Horizen",
  rpcs: ["https://horizen.calderachain.xyz/http"],
  explorer: "https://horizen.calderaexplorer.xyz",
  registry: "0xf44ed281005c7d506dc50829a3e24655837fbf75", // AttestRegistryV3: values per wallet, and Attest's wallets
  registryV2: "0x0c6a7918e2f8c28c4bb5cf8d0f4ce27e9b30fa2a", // AttestRegistryV2: anchors made until October 12, 2026
  authority: "0x23acbf52e76ee9502174442c87c3cd47c68f44e7",
  // Attest's platform organization: anchors every verifier build Attest has served, and the JSON-LD contexts.
  platform: "0xdea7b859dcbd34deb8dc910b5b36d6acdbec6f3a",
  webauthn: { rpId: "attest.datahubz.com", origin: "https://attest.datahubz.com" },
};
const REGISTRIES = [TRUST.registry, TRUST.registryV2];
const SEL = { anchoredAt: "0xf8c2919d", registeredAt: "0xaaea3d9c", revokedAt: "0x1947aee4", isAnchored: "0x4f0b5801" };
const TOPIC = {
  anchored: "0x57fefa523db76cd62f789aa4b83143b4f3851eb48941a7d42cc380126342f404", // Anchored(uint256,address,bytes32,uint256,uint256), V3
  rootAnchored: "0x65d7864cc203711bbe6234f2bedef9f3923db5d198919a8f604fcb92aa12f7ca", // RootAnchored(uint256,address,bytes32,uint256,uint256), V2
};

const KINDS = { agreement: "Signed agreement", receipt: "Receipt", certificate: "Certificate", card: "Proof Card", proof: "Zero-knowledge proof", analytics: "Attest Analytics" };
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
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const mono = (s) => `<span class="mono">${esc(s)}</span>`;
const isHex64 = (s) => typeof s === "string" && /^[0-9a-f]{64}$/.test(s);
const isTx = (s) => typeof s === "string" && /^0x[0-9a-fA-F]{64}$/.test(s);
// Links only ever point at the pinned explorer, built from a checked transaction hash: never a URL from a file.
const txLink = (tx) => (isTx(tx) ? `<a href="${TRUST.explorer}/tx/${tx}" target="_blank" rel="noopener noreferrer">${mono(tx.slice(0, 10) + "…")}</a>` : "");
const when = (iso) => (iso ? new Date(iso).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC") : "");
const fromSeconds = (s) => new Date(Number(s) * 1000).toISOString();
const str = (v) => (typeof v === "string" ? v : "");

/** Canonical JSON (sorted keys, no whitespace): the exact text Attest fingerprints and anchors. */
function canonicalJson(v) {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v).sort().filter((k) => v[k] !== undefined).map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(",")}}`;
  return JSON.stringify(v);
}

// BN254 scalar field: values the zero-knowledge circuits take as public inputs.
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const fieldOf = async (s) => (BigInt("0x" + (await sha256hex(s))) % P).toString();

// ---- Files attached to a PDF -----------------------------------------------------------------------
async function inflate(bytes) {
  const s = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate"));
  return new Uint8Array(await new Response(s).arrayBuffer());
}
// Byte offsets must line up with the text view: decode as latin1, never UTF-8.
const latin1 = new TextDecoder("latin1");

/** Every embedded file in a PDF, found by scanning (for PDFs that aren't signed copies, and for reporting). */
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

// ---- A signed copy's structure ------------------------------------------------------------------------
// A signed copy is its visible pages (a complete PDF, whose SHA-256 is anchored) followed by exactly one incremental
// update (ISO 32000, 7.5.6) that attaches the evidence, the original document and this verifier, and names them in
// a new catalog that is otherwise the old one. Anything else after the pages (another update, a page or annotation
// redefined, a script, an open action) is refused: a PDF reader could show it on top of the signed pages.
const ATTACHMENT_NAMES = new Set(["attest-evidence.json", "original-document.pdf", "attest-verifier.html"]);
const isWs = (c) => c === 0 || c === 9 || c === 10 || c === 12 || c === 13 || c === 32;
const isDelim = (c) => c === 40 || c === 41 || c === 60 || c === 62 || c === 91 || c === 93 || c === 123 || c === 125 || c === 47 || c === 37;
class PdfError extends Error {}

/** A strict reader of PDF objects: no comments, no repeated keys, references only as "n g R". */
function pdfReader(b) {
  let p = 0;
  const fail = (why) => { throw new PdfError(why); };
  const ws = () => { while (p < b.length && isWs(b[p])) p++; };
  const token = () => { const s = p; while (p < b.length && !isWs(b[p]) && !isDelim(b[p])) p++; return latin1.decode(b.subarray(s, p)); };
  function literal() {
    p++;
    let depth = 1;
    const out = [];
    const escapes = { 110: 10, 114: 13, 116: 9, 98: 8, 102: 12, 40: 40, 41: 41, 92: 92 };
    while (p < b.length) {
      const c = b[p++];
      if (c === 92) {
        const e = b[p++];
        if (e in escapes) out.push(escapes[e]);
        else if (e >= 48 && e <= 55) { let o = e - 48; for (let k = 0; k < 2 && b[p] >= 48 && b[p] <= 55; k++) o = o * 8 + (b[p++] - 48); out.push(o & 255); }
        else if (e === 13) { if (b[p] === 10) p++; }
        else if (e !== 10) out.push(e);
        continue;
      }
      if (c === 40) depth++;
      if (c === 41 && --depth === 0) return new Uint8Array(out);
      out.push(c);
    }
    fail("an unterminated string");
  }
  function dict() {
    p += 2;
    const v = new Map();
    for (;;) {
      ws();
      if (b[p] === 62 && b[p + 1] === 62) { p += 2; return { t: "dict", v }; }
      if (p >= b.length) fail("an unterminated dictionary");
      const k = value();
      if (k.t !== "name") fail("a dictionary key that isn't a name");
      if (v.has(k.v)) fail(`a repeated key /${k.v}`);
      v.set(k.v, value());
    }
  }
  function value() {
    ws();
    const c = b[p];
    if (p >= b.length) fail("an unexpected end");
    if (c === 37) fail("a comment");
    if (c === 47) { p++; return { t: "name", v: token().replace(/#([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16))) }; }
    if (c === 40) return { t: "str", v: literal() };
    if (c === 60 && b[p + 1] === 60) return dict();
    if (c === 60) {
      const s = ++p;
      while (p < b.length && b[p] !== 62) p++;
      const h = latin1.decode(b.subarray(s, p++)).replace(/[\0\t\n\f\r ]/g, "");
      if (!/^[0-9a-fA-F]*$/.test(h)) fail("a malformed hex string");
      return { t: "hex", v: h.toLowerCase() };
    }
    if (c === 91) {
      p++;
      const v = [];
      for (;;) { ws(); if (b[p] === 93) { p++; return { t: "arr", v }; } if (p >= b.length) fail("an unterminated array"); v.push(value()); }
    }
    const tok = token();
    if (tok === "true" || tok === "false" || tok === "null") return { t: "kw", v: tok };
    if (/^\d+$/.test(tok)) {
      const save = p;
      ws();
      const g = token();
      if (/^\d+$/.test(g)) { ws(); if (b[p] === 82 && (p + 1 >= b.length || isWs(b[p + 1]) || isDelim(b[p + 1]))) { p++; return { t: "ref", n: Number(tok), g: Number(g) }; } }
      p = save;
      return { t: "num", v: tok };
    }
    if (/^[+-]?(\d+\.?\d*|\.\d+)$/.test(tok)) return { t: "num", v: tok };
    fail(`an unexpected token ${JSON.stringify(tok.slice(0, 16))}`);
  }
  /** Match `re` (anchored with ^) at the current position and move past it. */
  function expect(re) {
    const m = re.exec(latin1.decode(b.subarray(p, Math.min(b.length, p + 80))));
    if (!m) return null;
    p += m[0].length;
    return m;
  }
  return { at: (q) => { p = q; }, pos: () => p, ws, value, expect, fail };
}

/** A value's canonical text, to compare two values (dictionaries compared key by key, in any order). */
function ser(x) {
  if (x.t === "dict") return `<<${[...x.v.keys()].sort().map((k) => `${JSON.stringify(k)}:${ser(x.v.get(k))}`).join(",")}>>`;
  if (x.t === "arr") return `[${x.v.map(ser).join(",")}]`;
  if (x.t === "str") return `(${hex(x.v)})`;
  if (x.t === "hex") return `(${x.v})`;
  if (x.t === "name") return `/${JSON.stringify(x.v)}`;
  if (x.t === "ref") return `${x.n} ${x.g} R`;
  return x.v;
}

/** One indirect object at `off`: its number, generation, value and (for a stream) its raw data. */
function objectAt(R, raw, off) {
  R.at(off);
  const h = R.expect(/^(\d{1,10}) (\d{1,5}) obj(?=[\0\t\n\f\r <\[(\/])/);
  if (!h) R.fail(`no object where its cross-reference entry points (byte ${off})`);
  const value = R.value();
  R.ws();
  let data = null;
  if (R.expect(/^stream(\r\n|\n)/)) {
    if (value.t !== "dict") R.fail("a stream without a dictionary");
    const len = value.v.get("Length");
    if (!len || len.t !== "num" || !/^\d+$/.test(len.v)) R.fail("a stream whose length isn't a number");
    const start = R.pos(), end = start + Number(len.v);
    if (end > raw.length) R.fail("a stream longer than the file");
    data = raw.subarray(start, end);
    R.at(end);
    if (!R.expect(/^(\r\n|\n|\r)?endstream/)) R.fail("a stream that doesn't end where its length says");
    R.ws();
  }
  if (!R.expect(/^endobj/)) R.fail("an object without endobj");
  return { n: Number(h[1]), g: Number(h[2]), value, data, end: R.pos() };
}

/** A classic cross-reference section and its trailer, at `at`. */
function xrefSection(R, at, onlyInUse) {
  R.at(at);
  if (!R.expect(/^xref(\r\n|\n|\r)/)) R.fail("no cross-reference table where the file says");
  const entries = new Map();
  for (let m; (m = R.expect(/^(\d{1,10}) (\d{1,7})(\r\n|\n|\r)/)); ) {
    let n = Number(m[1]);
    for (let i = 0; i < Number(m[2]); i++, n++) {
      const e = R.expect(/^(\d{10}) (\d{5}) ([nf])(\r\n| \n| \r)/);
      if (!e) R.fail("a malformed cross-reference entry");
      if (entries.has(n)) R.fail("an object listed twice");
      if (onlyInUse && e[3] !== "n") R.fail("a freed object after the signed pages");
      entries.set(n, { off: Number(e[1]), g: Number(e[2]), used: e[3] === "n" });
    }
  }
  R.ws();
  if (!R.expect(/^trailer/)) R.fail("no trailer after the cross-reference table");
  const trailer = R.value();
  if (trailer.t !== "dict") R.fail("a trailer that isn't a dictionary");
  R.ws();
  return { entries, trailer: trailer.v, end: R.pos() };
}

/**
 * Read a signed copy: its visible pages are the first `length` bytes; what follows must be exactly Attest's
 * update attaching the evidence. Returns the attachments it names, or why the file isn't a sealed copy.
 */
function readSealedCopy(raw, length) {
  const R = pdfReader(raw);
  const fail = R.fail;
  if (!(Number.isInteger(length) && length > 0 && length < raw.length)) fail("the evidence names no valid length for the pages");
  const ending = (from, to) => /startxref(?:\r\n|\n|\r)(\d{1,12})(?:\r\n|\n|\r)%%EOF(?:\r\n|\n|\r)?$/.exec(latin1.decode(raw.subarray(Math.max(from, to - 64), to)));
  const pe = ending(0, length);
  if (!pe) fail("the signed pages don't end where the evidence says");
  const fe = ending(length, raw.length);
  if (!fe) fail("the file doesn't end with a cross-reference section");
  const pagesXref = Number(pe[1]), xrefAt = Number(fe[1]);
  if (!(pagesXref < length)) fail("the signed pages' cross-reference table is outside them");
  if (!(xrefAt > length)) fail("the last cross-reference table isn't after the signed pages");

  // The pages' own objects, found through their cross-reference sections (the latest entry for each number).
  const pagesTrailer = xrefSection(R, pagesXref, false).trailer;
  const pageEntries = new Map();
  for (let at = pagesXref, hops = 0; at != null && hops < 32; hops++) {
    const sec = xrefSection(R, at, false);
    for (const [n, e] of sec.entries) if (!pageEntries.has(n)) pageEntries.set(n, e);
    const prev = sec.trailer.get("Prev");
    at = prev && prev.t === "num" && Number(prev.v) < at ? Number(prev.v) : null;
  }
  const pageObject = (ref, what) => {
    const e = pageEntries.get(ref.n);
    if (!e || !e.used || e.g !== ref.g || e.off >= length) fail(`${what} wasn't found in the signed pages`);
    const o = objectAt(R, raw, e.off);
    if (o.n !== ref.n || o.g !== ref.g) fail(`${what} isn't where the signed pages' table says`);
    return o.value;
  };
  const resolve = (v, what) => (v && v.t === "ref" ? pageObject(v, what) : v);
  const root = pagesTrailer.get("Root");
  if (!root || root.t !== "ref") fail("the signed pages have no catalog");
  const oldCatalog = { value: pageObject(root, "the signed pages' catalog") };
  if (oldCatalog.value.t !== "dict") fail("the signed pages' catalog isn't a dictionary");
  const pagesSize = pagesTrailer.get("Size");
  if (!pagesSize || pagesSize.t !== "num" || !/^\d+$/.test(pagesSize.v)) fail("the signed pages' trailer has no size");

  // The update: one cross-reference section of objects in use, its trailer, then startxref and %%EOF end the file.
  const last = xrefSection(R, xrefAt, true);
  if (last.end !== raw.length - fe[0].length) fail("there is something between the last trailer and the end of the file");
  const t = last.trailer;
  for (const k of t.keys()) if (!["Size", "Root", "Info", "ID", "Prev"].includes(k)) fail(`the last trailer adds /${k}`);
  const prev = t.get("Prev");
  if (!prev || prev.t !== "num" || Number(prev.v) !== pagesXref) fail("the update doesn't follow the signed pages directly");
  if (!t.get("Root") || ser(t.get("Root")) !== ser(root)) fail("the update changes which catalog the file opens");
  for (const k of ["Info", "ID"]) if ((t.get(k) ? ser(t.get(k)) : null) !== (pagesTrailer.get(k) ? ser(pagesTrailer.get(k)) : null)) fail(`the update changes the file's /${k}`);

  // Every byte between the pages and the table is one of the update's objects, in order.
  const objects = new Map();
  R.at(length);
  R.ws();
  while (R.pos() < xrefAt) {
    const off = R.pos();
    const o = objectAt(R, raw, off);
    if (objects.has(o.n)) fail("an object defined twice");
    objects.set(o.n, { ...o, off });
    R.ws();
  }
  if (R.pos() !== xrefAt) fail("the update's objects overrun its table");
  if (objects.size !== last.entries.size) fail("the update's table and its objects differ");
  for (const [n, e] of last.entries) {
    const o = objects.get(n);
    if (!o || o.off !== e.off || o.g !== e.g) fail("the update's table and its objects differ");
  }
  const size = Number(pagesSize.v);
  const newSize = t.get("Size");
  if (!newSize || newSize.t !== "num" || Number(newSize.v) !== Math.max(...objects.keys()) + 1) fail("the update's trailer has the wrong size");
  for (const [n, o] of objects) if (n !== root.n && (n < size || o.g !== 0)) fail("the update redefines an object of the signed pages");

  // The new catalog is the old one, with the attachments added to its /Names (as /EmbeddedFiles, every other
  // name kept as it was) and to its /AF (after the files it already listed).
  const cat = objects.get(root.n);
  if (!cat || cat.g !== root.g || cat.value.t !== "dict" || cat.data) fail("the update doesn't name its attachments in the catalog");
  const oldKeys = oldCatalog.value.v, newKeys = cat.value.v;
  for (const [k, v] of oldKeys) if (k !== "Names" && k !== "AF" && (!newKeys.has(k) || ser(newKeys.get(k)) !== ser(v))) fail(`the update changes the catalog's /${k}`);
  for (const k of newKeys.keys()) if (!oldKeys.has(k) && k !== "Names" && k !== "AF") fail(`the update adds /${k} to the catalog`);
  const oldNames = resolve(oldKeys.get("Names"), "the signed pages' names");
  if (oldNames && oldNames.t !== "dict") fail("the signed pages' names aren't a dictionary");
  const oldAf = resolve(oldKeys.get("AF"), "the signed pages' associated files");
  if (oldAf && oldAf.t !== "arr") fail("the signed pages' associated files aren't a list");
  const used = new Set([root.n]);
  const take = (ref, what) => {
    if (!ref || ref.t !== "ref" || ref.g !== 0) fail(`${what} isn't a reference`);
    const o = objects.get(ref.n);
    if (!o || ref.n === root.n) fail(`${what} isn't one of the update's objects`);
    return o;
  };
  const names = newKeys.get("Names");
  if (!names || names.t !== "dict" || !names.v.has("EmbeddedFiles")) fail("the catalog doesn't name the attachments");
  for (const [k, v] of names.v) if (k !== "EmbeddedFiles" && (!oldNames || !oldNames.v.has(k) || ser(oldNames.v.get(k)) !== ser(v))) fail(`the update adds or changes /${k} in the catalog's names`);
  if (oldNames) for (const k of oldNames.v.keys()) if (k !== "EmbeddedFiles" && !names.v.has(k)) fail(`the update drops /${k} from the catalog's names`);
  const tree = take(names.v.get("EmbeddedFiles"), "the attachments' name tree");
  used.add(tree.n);
  if (tree.value.t !== "dict" || tree.data || tree.value.v.size !== 1 || !tree.value.v.has("Names")) fail("the attachments' name tree isn't a single list");
  const list = tree.value.v.get("Names");
  if (list.t !== "arr" || list.v.length % 2) fail("the attachments' list is malformed");
  const af = newKeys.get("AF");
  if (!af || af.t !== "arr") fail("the catalog's /AF isn't a list");
  const files = [], specs = new Set();
  for (let i = 0; i < list.v.length; i += 2) {
    const key = list.v[i];
    if (key.t !== "str") fail("an attachment without a name");
    const spec = take(list.v[i + 1], "an attachment");
    if (specs.has(spec.n)) fail("an attachment listed twice");
    specs.add(spec.n);
    used.add(spec.n);
    const s = spec.value;
    if (s.t !== "dict" || spec.data) fail("an attachment that isn't a file specification");
    for (const k of s.v.keys()) if (!["Type", "F", "UF", "Desc", "AFRelationship", "EF"].includes(k)) fail(`an attachment with /${k}`);
    if (ser(s.v.get("Type") || { t: "kw", v: "" }) !== ser({ t: "name", v: "Filespec" })) fail("an attachment that isn't a file specification");
    const fname = s.v.get("F"), uf = s.v.get("UF");
    if (!fname || fname.t !== "str" || !uf || ser(uf) !== ser(fname) || ser(key) !== ser(fname)) fail("an attachment whose names disagree");
    const name = latin1.decode(fname.v);
    if (!ATTACHMENT_NAMES.has(name)) fail(`an attachment Attest doesn't make (${name.slice(0, 60)})`);
    if (files.some((f) => f.name === name)) fail(`two attachments named ${name}`);
    const rel = s.v.get("AFRelationship");
    if (rel && ser(rel) !== ser({ t: "name", v: "Data" })) fail("an attachment with an unexpected relationship");
    const desc = s.v.get("Desc");
    if (desc && desc.t !== "str") fail("an attachment with an unexpected description");
    const ef = s.v.get("EF");
    if (!ef || ef.t !== "dict" || ![...ef.v.keys()].every((k) => k === "F" || k === "UF") || !ef.v.has("F")) fail("an attachment without its file");
    if (ef.v.has("UF") && ser(ef.v.get("UF")) !== ser(ef.v.get("F"))) fail("an attachment with two files");
    const file = take(ef.v.get("F"), "an attachment's file");
    if (used.has(file.n)) fail("a file used twice");
    used.add(file.n);
    const d = file.value;
    if (d.t !== "dict" || !file.data) fail("an attachment's file that isn't a stream");
    for (const k of d.v.keys()) if (!["Type", "Subtype", "Filter", "Length", "Params"].includes(k)) fail(`an attachment's file with /${k}`);
    if (ser(d.v.get("Type") || { t: "kw", v: "" }) !== ser({ t: "name", v: "EmbeddedFile" })) fail("an attachment's file that isn't an embedded file");
    const filter = d.v.get("Filter");
    if (filter && ser(filter) !== ser({ t: "name", v: "FlateDecode" })) fail("an attachment's file with an unexpected filter");
    const params = d.v.get("Params");
    if (params && (params.t !== "dict" || ![...params.v.keys()].every((k) => k === "Size"))) fail("an attachment's file with unexpected parameters");
    const declared = params && params.v.get("Size");
    files.push({ name, data: file.data, deflated: Boolean(filter), size: declared && declared.t === "num" ? Number(declared.v) : null });
  }
  const kept = oldAf ? oldAf.v.length : 0;
  if (oldAf && oldAf.v.some((v, i) => ser(v) !== ser(af.v[i]))) fail("the update changes the files the signed pages listed in /AF");
  const added = af.v.slice(kept);
  if (added.length !== specs.size || !added.every((r) => r.t === "ref" && r.g === 0 && specs.has(r.n))) fail("the catalog's /AF and its attachments differ");
  if (new Set(added.map((r) => r.n)).size !== added.length) fail("an attachment listed twice in /AF");
  for (const n of objects.keys()) if (!used.has(n)) fail("the update adds an object that isn't an attachment");
  if (!files.some((f) => f.name === "attest-evidence.json")) fail("the update carries no evidence");
  return files;
}

/** The signed copy's attachments, or why it isn't exactly a sealed copy. */
async function sealedCopy(raw, length) {
  let files;
  try {
    files = readSealedCopy(raw, length);
  } catch (e) {
    return { ok: false, why: e instanceof PdfError ? e.message : `it couldn't be read (${e.message})` };
  }
  const out = {};
  for (const f of files) {
    let bytes = f.data;
    if (f.deflated) {
      if (typeof DecompressionStream === "undefined") return { ok: false, why: "this browser can't open the attachments", noInflate: true };
      try { bytes = await inflate(bytes); } catch { return { ok: false, why: `${f.name} can't be decompressed` }; }
    }
    if (f.size != null && f.size !== bytes.length) return { ok: false, why: `${f.name} isn't the size its file says` };
    out[f.name] = bytes;
  }
  return { ok: true, files: out };
}

// ---- WebAuthn (passkey) signatures ------------------------------------------------------------------
function derToRaw(der) {
  let i = 2; if (der[1] & 0x80) i += der[1] & 0x7f;
  const read = () => { i++; let len = der[i++]; let v = der.slice(i, i + len); i += len; while (v.length > 32 && v[0] === 0) v = v.slice(1); const out = new Uint8Array(32); out.set(v, 32 - v.length); return out; };
  const r = read(), s = read(); const raw = new Uint8Array(64); raw.set(r); raw.set(s, 32); return raw;
}
/**
 * One passkey assertion over sha256(statement), made on Attest's site: the site and origin are pinned here, never
 * taken from the evidence. { statement, authenticatorData, clientDataJSON, signature, publicKeySpki, alg }.
 */
async function passkeyCheck(e) {
  const rp = TRUST.webauthn;
  const clientBytes = b64url(e.clientDataJSON), client = JSON.parse(dec.decode(clientBytes));
  const challengeOk = client.type === "webauthn.get" && client.challenge === toB64url(await sha256(e.statement));
  const originOk = client.origin === rp.origin && client.crossOrigin !== true;
  const auth = b64url(e.authenticatorData);
  const rpHash = await sha256(rp.rpId);
  const rpOk = auth.length >= 37 && rpHash.every((b, i) => auth[i] === b);
  const flags = auth[32] || 0, present = (flags & 1) !== 0, verified = (flags & 4) !== 0;
  const data = new Uint8Array(auth.length + 32); data.set(auth); data.set(await sha256(clientBytes), auth.length);
  const spki = b64(e.publicKeySpki), sig = b64url(e.signature);
  let sigOk = false;
  if (e.alg === -7) sigOk = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]), derToRaw(sig), data);
  else if (e.alg === -257) sigOk = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", await crypto.subtle.importKey("spki", spki, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]), sig, data);
  else if (e.alg === -8) sigOk = await crypto.subtle.verify({ name: "Ed25519" }, await crypto.subtle.importKey("spki", spki, { name: "Ed25519" }, false, ["verify"]), sig, data);
  return { ok: challengeOk && originOk && rpOk && present && verified && sigOk, parts: { challengeOk, originOk, rpOk, present, verified, sigOk } };
}
const signerPasskeyCheck = (s) => passkeyCheck({ statement: s.statement, ...s.webauthnAssertion, publicKeySpki: s.passkey.publicKeySpki, alg: s.passkey.alg });

// ---- The public blockchain --------------------------------------------------------------------------
async function rpc(url, method, params) {
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  const j = await r.json();
  if (j.error) throw new Error(j.error.message);
  return j.result;
}

// The node: Horizen's public node unless one is entered above. Either way it must be a node of Horizen; it is
// only a source of data, every answer is checked against the pinned registries and authority.
const nodes = new Map();
function node() {
  const url = $("rpc").value.trim() || TRUST.rpcs[0];
  if (!/^https?:\/\/\S+$/i.test(url)) return Promise.reject(new Error("A node's address starts with https://"));
  if (!nodes.has(url)) {
    const p = rpc(url, "eth_chainId", []).then((id) => {
      if (parseInt(id, 16) !== TRUST.chainId) throw new Error(`${url} is a node of chain ${parseInt(id, 16)}, not of ${TRUST.chain} (chain ${TRUST.chainId})`);
      return url;
    });
    p.catch(() => nodes.delete(url));
    nodes.set(url, p);
  }
  return nodes.get(url);
}
const word = (r, i) => BigInt("0x" + ((r || "0x").slice(2 + 64 * i, 2 + 64 * (i + 1)) || "0"));
const arg = (x) => x.replace(/^0x/, "").toLowerCase().padStart(64, "0");
const callView = (url, to, data) => rpc(url, "eth_call", [{ to, data }, "latest"]);

/** An anchor of `value` on AttestRegistryV2, which records one wallet per value. */
async function v2Anchor(url, value) {
  const r = await callView(url, TRUST.registryV2, SEL.isAnchored + arg(value));
  if (word(r, 0) !== 1n) return null;
  return { at: Number(word(r, 1)), wallet: `0x${r.slice(2 + 128 + 24, 2 + 192)}`.toLowerCase(), registry: TRUST.registryV2 };
}

/** Whether a wallet is Attest's: registered by the authority on AttestRegistryV3, and when it was revoked, if ever. */
const walletCache = new Map();
function walletStatus(url, wallet) {
  if (!walletCache.has(wallet)) {
    const p = Promise.all([callView(url, TRUST.registry, SEL.registeredAt + arg(wallet)), callView(url, TRUST.registry, SEL.revokedAt + arg(wallet))]).then(([r, x]) => ({ registered: Number(word(r, 0)), revoked: Number(word(x, 0)) }));
    p.catch(() => walletCache.delete(wallet));
    walletCache.set(wallet, p);
  }
  return walletCache.get(wallet);
}

/**
 * Whether `value` is anchored by an Attest wallet. `wallet` is the wallet expected to have anchored it (named by the
 * evidence or by an earlier anchor); without one, only an anchor on V2, which records its wallet, can be found.
 */
async function attested(url, value, wallet) {
  const v = String(value).replace(/^0x/, "").toLowerCase();
  let w = wallet ? String(wallet).toLowerCase() : null;
  if (w && !/^0x[0-9a-f]{40}$/.test(w)) return { anchored: false, ok: false };
  let hit = null;
  if (w) {
    const at = Number(word(await callView(url, TRUST.registry, SEL.anchoredAt + arg(w) + arg(v)), 0));
    if (at) hit = { at, registry: TRUST.registry };
    else {
      const old = await v2Anchor(url, v);
      if (old && old.wallet === w) hit = old;
    }
  } else {
    hit = await v2Anchor(url, v);
    if (hit) w = hit.wallet;
  }
  if (!hit) return { anchored: false, ok: false, wallet: w };
  const st = await walletStatus(url, w);
  const ok = st.registered > 0 && (!st.revoked || hit.at < st.revoked);
  return { anchored: true, ok, at: fromSeconds(hit.at), wallet: w, registry: hit.registry, why: ok ? "" : st.registered ? "Attest revoked that wallet before this anchor" : "that wallet isn't one of Attest's" };
}

/** The wallet that sent a transaction to one of the pinned registries, and the value its log records. */
async function anchorTx(url, txHash, value) {
  if (!isTx(txHash)) return null;
  const rc = await rpc(url, "eth_getTransactionReceipt", [txHash]);
  if (!rc || rc.status !== "0x1" || !rc.to || !REGISTRIES.includes(rc.to.toLowerCase())) return null;
  const reg = rc.to.toLowerCase(), v = "0x" + arg(value);
  const log = rc.logs.find((l) =>
    l.address.toLowerCase() === reg &&
    (reg === TRUST.registry
      ? (l.topics[0] || "").toLowerCase() === TOPIC.anchored && (l.topics[3] || "").toLowerCase() === v
      : (l.topics[0] || "").toLowerCase() === TOPIC.rootAnchored && l.data.toLowerCase().startsWith(v)));
  return log ? { wallet: rc.from.toLowerCase() } : null;
}

/** The wallet that sent a transaction to one of the pinned registries (for records that don't carry the value's path). */
async function anchorTxSender(url, txHash) {
  if (!isTx(txHash)) return null;
  const rc = await rpc(url, "eth_getTransactionReceipt", [txHash]);
  return rc && rc.status === "0x1" && rc.to && REGISTRIES.includes(rc.to.toLowerCase()) ? rc.from.toLowerCase() : null;
}

/**
 * Check that `value` is anchored by an Attest wallet, and report it. `hint.txHash` (a transaction that must record
 * it) or `hint.wallet` name the wallet; `hint.missing` is how to report an anchor that isn't there.
 * Returns { at, wallet } or null.
 */
async function onChain(label, value, hint = {}) {
  let url;
  try { url = await node(); } catch (e) {
    add("warn", `${label}: the on-chain check couldn't run here`, `${esc(e.message)}. Check your connection, or enter another public node of ${TRUST.chain} above, then drop the file again.`);
    return null;
  }
  try {
    let wallet = hint.wallet ? String(hint.wallet).toLowerCase() : null;
    if (hint.txHash != null) {
      const tx = await anchorTx(url, hint.txHash, value);
      if (!tx) { add("bad", `${label}: the transaction its evidence names doesn't anchor it on Attest's registry`, `Transaction ${mono(String(hint.txHash))}`); return null; }
      if (wallet && wallet !== tx.wallet) { add("bad", `${label}: its evidence names a different wallet than the transaction's`, ""); return null; }
      wallet = tx.wallet;
    }
    const r = await attested(url, value, wallet);
    if (!r.anchored) {
      add(hint.missing || "bad", `${label}: not anchored ${hint.missing === "wait" ? "yet" : "by Attest"}`, hint.missingDetail || `Value ${mono(String(value))} isn't on Attest's registries${wallet ? ` from wallet ${mono(wallet)}` : ""}.`);
      return null;
    }
    if (!r.ok) {
      add("bad", `${label}: anchored by a wallet that isn't Attest's`, `Wallet ${mono(r.wallet)}: ${esc(r.why)}. Attest's wallets are registered on chain by its registry authority, ${mono(TRUST.authority)}, which this verifier pins.`);
      return null;
    }
    add("ok", `${label}: anchored on ${TRUST.chain} by an Attest wallet`, `${when(r.at)}, by wallet ${mono(r.wallet)}${isTx(hint.txHash) ? `, transaction ${txLink(hint.txHash)}` : ""}.`);
    return r;
  } catch (e) {
    add("warn", `${label}: the on-chain check couldn't run here`, `${esc(e.message)}. Check your connection, or enter another public node of ${TRUST.chain} above, then drop the file again.`);
    return null;
  }
}

/** Fold a Merkle path (sorted pairs, SHA-256) from a leaf; the result should be the anchored root. */
async function foldPath(leaf, path) {
  let node = leaf.replace(/^0x/, "").toLowerCase();
  for (const sib0 of path || []) {
    const sib = String(sib0).replace(/^0x/, "").toLowerCase();
    if (!isHex64(sib)) return null;
    const [lo, hi] = node <= sib ? [node, sib] : [sib, node];
    const both = new Uint8Array(64); both.set(unhex(lo)); both.set(unhex(hi), 32);
    node = await sha256hex(both);
  }
  return node;
}

/** The chain an anchor names, if any, must be Attest's. */
function onAttestChain(label, a) {
  if (a && a.chainId != null && Number(a.chainId) !== TRUST.chainId) {
    add("bad", `${label}: anchored on chain ${esc(a.chainId)}, not on ${TRUST.chain}`, "Attest anchors its records on Horizen. A record on another chain, such as a test network, isn't proof.");
    return false;
  }
  return true;
}

/**
 * An anchor from an evidence file: a receipt in a Merkle batch ({type:"merkle"}), an organization event
 * ({type:"event"}), or a single value ({type:"value"}). `expect` is the fingerprint it must commit to.
 */
async function checkAnchor(label, a, expect) {
  if (!a) { add("wait", `${label}: not anchored yet`, "Anchoring follows within minutes. Download the evidence again later to check it on chain."); return null; }
  if (!onAttestChain(label, a)) return null;
  const e = String(expect || "").replace(/^0x/, "").toLowerCase();
  if (!isHex64(e)) { add("bad", `${label}: no valid fingerprint`, ""); return null; }
  let value;
  if (a.type === "merkle" || (!a.type && a.receiptId)) {
    if (typeof a.receiptId !== "string" || !Array.isArray(a.merkleProof)) { add("bad", `${label}: the anchor's Merkle path is missing`, ""); return null; }
    const leaf = await sha256hex(`${a.receiptId}:${e}`);
    value = await foldPath(leaf, a.merkleProof);
    if (!value || (a.merkleRoot && value !== String(a.merkleRoot).replace(/^0x/, "").toLowerCase())) { add("bad", `${label}: the Merkle path doesn't reach the anchored root`, `Computed ${mono(value || "nothing")}`); return null; }
  } else if (a.type === "event") {
    if (a.digest && a.digest !== e) { add("bad", `${label}: the anchored event is for a different fingerprint`, ""); return null; }
    value = await sha256hex(`attest.event.v1|${a.eventId}|${e}`);
  } else value = e;
  return onChain(label, value, { txHash: a.txHash, wallet: a.from });
}

/** Groth16 over BN254 against the circuit's pinned verification key (src/circuits), never a key from a file. */
async function groth16(circuit, signals, proof) {
  const vk = L.circuits[circuit];
  if (!vk) throw new Error(`no pinned verification key for circuit ${circuit}`);
  if (!Array.isArray(signals) || !signals.every((s) => typeof s === "string" && /^\d{1,78}$/.test(s) && BigInt(s) < P)) throw new Error("malformed public inputs");
  return L.verifyGroth16(vk, signals, proof);
}

/** ES256 JWS (vc+jwt) against a P-256 JWK. */
async function jwsValid(jws, jwk) {
  const [h, p, s] = jws.split(".");
  const key = await crypto.subtle.importKey("jwk", { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, b64url(s), enc.encode(`${h}.${p}`));
  return { ok, header: JSON.parse(dec.decode(b64url(h))), payload: JSON.parse(dec.decode(b64url(p))) };
}

/**
 * The issuer's key, committed on chain by the organization's wallet:
 * sha256("attest.issuer_key.v1|" + did + "|" + publicKeyMultibase + "|" + canonicalJson(publicKeyJwk)).
 * Only Attest builds this value, for an organization's own DID, from that organization's wallet: a commitment from an
 * Attest wallet binds the DID to the wallet. Returns { doc, wallet, at } or null.
 */
async function checkIssuerKey(issuer, issuedAt) {
  const doc = (issuer && issuer.didDocument) || {};
  if (!issuer || typeof issuer.did !== "string" || doc.id !== issuer.did) { add("bad", "The issuer's DID document is for a different issuer", ""); return null; }
  if (!/^did:web:attest\.datahubz\.com:orgs:[a-z0-9-]+$/.test(issuer.did)) { add("bad", "The issuer isn't an Attest organization", `${mono(issuer.did)} isn't a DID Attest issues.`); return null; }
  const vms = Array.isArray(doc.verificationMethod) ? doc.verificationMethod : [];
  const multi = vms.find((m) => m && m.publicKeyMultibase), jwkVm = vms.find((m) => m && m.publicKeyJwk);
  if (!multi || !jwkVm) { add("bad", "The issuer's DID document has no signing key", ""); return null; }
  const value = await sha256hex(`attest.issuer_key.v1|${issuer.did}|${multi.publicKeyMultibase}|${canonicalJson(jwkVm.publicKeyJwk)}`);
  // The anchor commits to one key (as a Multikey and as a JWK). Every verification method in the document must be that
  // key, under this DID, so a signature can only ever be checked against the key Attest committed.
  const committedJwk = canonicalJson(jwkVm.publicKeyJwk);
  for (const m of vms) {
    const fields = m && typeof m === "object" ? Object.keys(m).filter((k) => !["id", "type", "controller"].includes(k)) : [];
    const sameKey = fields.length === 1 && ((fields[0] === "publicKeyMultibase" && m.publicKeyMultibase === multi.publicKeyMultibase) || (fields[0] === "publicKeyJwk" && canonicalJson(m.publicKeyJwk) === committedJwk));
    const ours = Boolean(m) && typeof m.id === "string" && m.id.startsWith(`${issuer.did}#`) && (m.controller === undefined || m.controller === issuer.did);
    if (!sameKey || !ours) { add("bad", "The issuer's DID document carries a key Attest didn't commit", `${mono(str(m && m.id))} isn't the key committed on chain for ${mono(issuer.did)}.`); return null; }
  }
  const k = issuer.keyAnchor || {};
  const r = await onChain(`The issuer's key, ${issuer.did}`, value, { wallet: k.from, missing: "bad", missingDetail: "Attest commits every issuer's key on chain from the organization's own wallet before its first use. This key isn't committed, so nothing ties it to the issuer." });
  if (!r) return null;
  if (issuedAt && new Date(r.at) > new Date(issuedAt)) add("info", "The issuer's key was committed after this was issued", `Committed ${when(r.at)}, issued ${when(issuedAt)}.`);
  return { doc, wallet: r.wallet, at: r.at };
}

// ---- Results ----------------------------------------------------------------------------------------
let results = [];
let downloads = [];
const add = (state, title, detail) => results.push({ state, title, detail });
const headline = {
  agreement: "Verified: the document, every signer's passkey signature and entries, and Attest's record of the agreement, anchored on the public blockchain.",
  receipt: "Verified: this fingerprint was recorded by Attest and anchored on the public blockchain, and has not changed since.",
  certificate: "Verified: the content, every signature, the issuer's signature and key, and the anchor on the public blockchain.",
  card: "Verified: the issuer's signature and key, the holder's approval, the anchors and the current status on the public blockchain.",
  proof: "Verified: the zero-knowledge proof, what it reveals, and the anchored record it proves against.",
  analytics: "Verified: the sealed figures, the records behind them, and their anchors on the public blockchain.",
};
function render(kind, title, sub, verified) {
  if (results.length === 1 && /newer evidence format/.test(results[0].title)) {
    $("out").innerHTML = `<div class="verdict bad">Not checked: this record is newer than this verifier. Get the latest verifier to check it.</div><div class="card"><div class="row"><span class="icon warn">!</span><div><div class="title">${esc(results[0].title)}</div><div class="detail">${results[0].detail}</div></div></div></div>`;
    return;
  }
  const failed = results.some((r) => r.state === "bad");
  const waiting = results.some((r) => r.state === "wait");
  const partial = results.some((r) => r.state === "warn");
  const icon = { ok: "✓", bad: "✕", warn: "!", wait: "…", info: "i" };
  const verdict = failed
    ? ["bad", "This record does not verify: see the failed checks below."]
    : waiting
      ? ["partial", "Not verified yet: part of this record isn't anchored yet. Check again in a few minutes."]
      : partial
        ? ["partial", "Not fully verified: see the checks marked ! below. Every other check passed."]
        : ["ok", verified || headline[kind] || "Verified."];
  $("out").innerHTML =
    `<div class="verdict ${verdict[0]}">${esc(verdict[1])}</div>` +
    `<h2>${esc(title || KINDS[kind] || "Record")}</h2>${sub ? `<p class="small">${sub}</p>` : ""}` +
    `<div class="card">${results.map((r) => `<div class="row"><span class="icon ${r.state}">${icon[r.state]}</span><div><div class="title">${esc(r.title)}</div>${r.detail ? `<div class="detail">${r.detail}</div>` : ""}</div></div>`).join("")}</div>` +
    downloads.map((d, i) => `<p><button type="button" class="link" data-download="${i}">${esc(d.label)}</button></p>`).join("");
  for (const b of $("out").querySelectorAll("button[data-download]")) {
    const d = downloads[Number(b.getAttribute("data-download"))];
    b.addEventListener("click", () => {
      const url = URL.createObjectURL(new Blob([d.bytes], { type: d.type }));
      const a = document.createElement("a");
      a.href = url; a.download = d.name; a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
  }
}

/**
 * A file that carries a verifier tells its reader to open it, so the verifier must be one Attest published: every
 * build Attest has served is anchored by its platform organization as
 * sha256("attest.verifier.v1|" + version + "|" + sha256(file)), the version read from the build's own declaration.
 */
const SAFE_VERIFIER = "1.4.2"; // earlier releases have weaknesses fixed since (CHANGELOG.md)
async function checkAttachedVerifiers(list) {
  let url;
  try { url = await node(); } catch (e) {
    add("warn", "The verifier attached to this file couldn't be checked here", `${esc(e.message)}. Check your connection, or enter another public node of ${TRUST.chain} above, then drop the file again.`);
    return;
  }
  const older = (a, b) => { const x = a.split(".").map(Number), y = b.split(".").map(Number); for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] < y[i]; return false; };
  for (const bytes of list) {
    const sha = await sha256hex(bytes);
    const m = /const VERIFIER = \{\s*version: "(\d+\.\d+\.\d+)"/.exec(latin1.decode(bytes));
    const version = m ? m[1] : "unversioned";
    let r;
    try { r = await attested(url, await sha256hex(`attest.verifier.v1|${version}|${sha}`), TRUST.platform); } catch (e) {
      add("warn", "The verifier attached to this file couldn't be checked here", esc(e.message));
      continue;
    }
    if (!r.anchored || !r.ok) {
      add("bad", "A file attached to this PDF isn't one Attest published", `Its SHA-256 ${mono(sha)} isn't anchored by Attest's platform wallet ${mono(TRUST.platform)}${r.anchored ? `: ${esc(r.why)}` : ""}. Don't open it: a changed verifier, or any file a reader can open, can show any result. Check files here, or with a release from ${esc(VERIFIER.repo.replace(/^https:\/\//, ""))}.`);
      continue;
    }
    add("ok", `The verifier attached to this file is Attest's ${version === "unversioned" ? "first build" : `release ${version}`}`, `Its SHA-256 ${mono(sha)} was anchored by Attest's platform wallet ${when(r.at)}.`);
    if (version === "unversioned" || older(version, SAFE_VERIFIER)) add("info", "That verifier has been updated since", `Later releases fix weaknesses found in it (CHANGELOG.md at ${esc(VERIFIER.repo.replace(/^https:\/\//, ""))}). Check this file here, or with the latest release, rather than with the attached copy.`);
  }
}

/** The evidence's kind and format version, or null if it isn't Attest evidence. */
function formatOf(ev) {
  const m = ev && typeof ev.format === "string" && /^attest\.(agreement|receipt|certificate|card|proof|analytics)_evidence\.v(\d+)$/.exec(ev.format);
  if (m) return { kind: m[1], v: Number(m[2]) };
  const other = ev && typeof ev.format === "string" && /^attest\.([a-z_]+)\.v(\d+)$/.exec(ev.format);
  return other ? { kind: other[1], v: Number(other[2]), unknown: true } : null;
}

// ============================================================================================ agreements
/** Agreement evidence v1 (signed copies before October 10, 2026), mapped onto v2's shape. It carries the
 *  signatures and the fingerprints, but not the signed state's text or the anchor's Merkle path. */
function fromV1(e) {
  return {
    format: e.format,
    legacy: true,
    agreementId: e.agreementId,
    document: { sha256: e.documentSha256, file: null },
    signers: (e.signers || []).map((s) => ({
      email: s.email,
      signedAt: s.signedAt,
      statement: s.consentJson || null,
      entries: null,
      entriesSha256: s.entriesSha256 || null,
      passkey: s.passkeyPublicKey ? { publicKeySpki: s.passkeyPublicKey, alg: s.passkeyAlg } : null,
      webauthnAssertion: s.signature ? { authenticatorData: s.authenticatorData, clientDataJSON: s.clientDataJSON, signature: s.signature } : null,
    })),
    signedState: e.signedStateSha256 ? { message: null, sha256: e.signedStateSha256 } : null,
    anchor: e.anchor ? { chainId: e.anchor.chainId, txHash: e.anchor.txHash, receiptId: e.anchor.receiptId, merkleRoot: null, merkleProof: null } : null,
    proofs: [],
  };
}

/**
 * Every signer's statement, passkey public key and signature, as Attest commits them in the agreement's anchor:
 * SHA-256 of the JSON array of [lowercase email, statement, public key, alg, authenticatorData, clientDataJSON,
 * signature] per signer, sorted by email.
 */
async function signaturesSha256(signers) {
  const rows = signers
    .map((s) => [String(s.email).toLowerCase(), s.statement ?? "", (s.passkey && s.passkey.publicKeySpki) ?? "", (s.passkey && s.passkey.alg) ?? null, (s.webauthnAssertion && s.webauthnAssertion.authenticatorData) ?? "", (s.webauthnAssertion && s.webauthnAssertion.clientDataJSON) ?? "", (s.webauthnAssertion && s.webauthnAssertion.signature) ?? ""])
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  return sha256hex(JSON.stringify(rows));
}

async function verifyAgreement(ev, files) {
  if (ev.legacy !== true && /\.v1$/.test(ev.format)) ev = fromV1(ev);
  const id = str(ev.agreementId);
  const docSha = str(ev.document && ev.document.sha256);
  const signers = Array.isArray(ev.signers) ? ev.signers : [];
  if (!/^agr_[0-9A-Za-z_-]+$/.test(id) || !isHex64(docSha) || !signers.length) {
    add("bad", "This isn't a complete agreement record", "It names no agreement, document or signers.");
    return render("agreement", "Signed agreement");
  }
  // 1. The signed state: Attest's record of the agreement, its document and every signer, whose fingerprint is anchored.
  const ss = ev.signedState || {};
  const stateSha = isHex64(ss.sha256) ? ss.sha256 : null;
  let state = null;
  if (typeof ss.message === "string") {
    let m = null;
    try { m = JSON.parse(ss.message); } catch {}
    const h = await sha256hex(ss.message);
    const shape = m && (m.kind === "attest.agreement_completion.v1" || m.kind === "attest.agreement_completion.v2") && m.agreementId === id && m.documentSha256 === docSha && Array.isArray(m.signers);
    const sameSigners = shape && m.signers.map((x) => x.email).sort().join("\n") === signers.map((s) => String(s.email).toLowerCase()).sort().join("\n");
    if (h === stateSha && shape && sameSigners) { state = m; add("ok", "The signed state names this agreement, its document and every signer", `SHA-256 ${mono(h)}`); }
    else add("bad", "The signed state doesn't match this agreement", h !== stateSha ? `It hashes to ${mono(h)}, not to the anchored ${mono(stateSha || "")}.` : "It names a different agreement, document or set of signers.");
  } else if (ev.legacy && stateSha) {
    add("info", "This older format doesn't carry the signed state's text", "Each signer is checked by their own signed statement instead, and Attest's anchor of the agreement covers every one of them.");
  } else add("bad", "The signed state is missing", "");

  // 2. The original document inside
  const original = files.pdf;
  if (original) {
    const h = await sha256hex(original);
    add(h === docSha ? "ok" : "bad", h === docSha ? `The original document${files.outer ? " inside" : ""} is exactly the one signed` : `The original document${files.outer ? " inside" : ""} is not the one signed`, `SHA-256 ${mono(h)}`);
  } else if (files.outer && ev.document && ev.document.file === null && !ev.visibleCopy) add("info", "The document isn't in this certificate", `It stays with the parties, whose signed copy carries it. Its fingerprint is ${mono(docSha)}.`);
  else if (files.outer) add("warn", "The original document isn't in this file", "A signed copy carries it as original-document.pdf.");
  else add("info", "Drop the original document too, to check it is the one signed", `Its fingerprint is ${mono(docSha)}.`);

  // 3. Each signer: the statement their passkey signed, their entries, and the signature.
  let title = state ? str(state.title) : null;
  const names = [];
  for (const s of signers) {
    const email = String(s.email || "").toLowerCase();
    let st = null;
    try { st = JSON.parse(s.statement); } catch {}
    const who = st && typeof st.name === "string" && st.name ? st.name : email;
    names.push(who);
    if (s.statement == null && !s.webauthnAssertion && !s.passkey) {
      // Agreements signed before signers signed with passkeys (September 2026): Attest's anchor of the agreement,
      // checked below, commits to this signer having no passkey signature, so this can't be a stripped one.
      add("warn", `${who}: no passkey signature`, "Signed in September 2026, before Attest's signers signed with passkeys. Attest's anchored record of the agreement, checked below, is the evidence of this signature.");
      continue;
    }
    if (!st || !s.webauthnAssertion || !s.passkey) { add("bad", `${who}: no signature evidence`, ""); continue; }
    if (title == null && typeof st.title === "string") title = st.title;
    const inState = state ? state.signers.find((x) => x.email === email) : null;
    if (s.entries != null) {
      const eh = await sha256hex(s.entries);
      add(eh === s.entriesSha256 ? "ok" : "bad", `${who}: the entries are the ones they signed`, `Entries SHA-256 ${mono(eh)}`);
    }
    const fields = (st.fieldsSha256 ?? null) === (s.entriesSha256 ?? null) && (!state || (inState && (inState.fieldsSha256 ?? null) === (st.fieldsSha256 ?? null)));
    const named = st.agreementId === id && st.documentSha256 === docSha && st.signer === email && st.title === title && fields && (!state || (inState && st.signedAt === inState.signedAt));
    add(named ? "ok" : "bad", `${who}: the signed statement names this agreement, its document${s.entriesSha256 ? ", their entries" : ""} and this signer`, esc(str(st.statement)));
    try {
      const w = await signerPasskeyCheck(s);
      add(w.ok ? "ok" : "bad", `${who}: passkey signature valid`, w.ok ? `Signed ${when(st.signedAt)} on ${esc(TRUST.webauthn.origin)}, with the signer present and verified on their device` : esc(JSON.stringify(w.parts)));
    } catch (e) { add("bad", `${who}: passkey signature could not be checked`, esc(e.message)); }
  }

  // 4. The anchors: the signed state's receipt (when it was recorded, and by which Attest wallet), then Attest's
  // anchor of the agreement itself, which commits to the signed state and to every signature and passkey key: a
  // receipt alone could be anyone's record of the same fingerprint.
  const an = ev.anchor;
  let wallet = null, stateAt = null;
  if (!stateSha) add("bad", "The signed state's fingerprint is missing", "");
  else if (ev.legacy) {
    if (an && onAttestChain("The signed state", an) && isTx(an.txHash)) {
      try { wallet = await anchorTxSender(await node(), an.txHash); } catch (e) { add("warn", "The anchoring transaction couldn't be read here", esc(e.message)); }
      if (!wallet) add("bad", "The anchoring transaction isn't an anchor on Attest's registry", `Transaction ${mono(an.txHash)}`);
    } else if (!an) add("wait", "The signed state isn't anchored yet", "Anchoring follows within minutes.");
  } else if (an && an.merkleRoot) {
    const r = await checkAnchor("The signed state", { ...an, type: "merkle" }, stateSha);
    if (r) { wallet = r.wallet; stateAt = r.at; }
  } else add(an ? "bad" : "wait", an ? "The anchor's Merkle path is missing" : "The signed state isn't anchored yet", an ? "" : "Anchoring follows within minutes.");
  let agreementAt = null;
  if (stateSha && wallet) {
    const value = await sha256hex(`attest.agreement.v1|${id}|${stateSha}|${await signaturesSha256(signers)}`);
    const r = await onChain("Attest's record of this agreement and its signatures", value, {
      wallet,
      missing: "bad",
      missingDetail: "Attest anchors every completed agreement, with every signer's statement, passkey key and signature, from the wallet that anchored its signed state. This one isn't anchored: either the evidence was changed, or the agreement was completed in the last few minutes and its anchor is on its way (check again shortly).",
    });
    if (r) agreementAt = r.at;
  }

  // 5. The visible pages: the bytes before the appended evidence, anchored as this agreement's sealed copy.
  await checkVisiblePages(ev, files, id, wallet);

  // 6. Zero-knowledge proofs about this agreement
  for (const p of ev.proofs || []) {
    if (!p || !p.proof) continue;
    await checkAgreementProof({ ...p, revealed: p.revealed || {} }, p.root || null, `Proof ${str(p.id)}`);
  }
  const done = state ? state.signers.map((x) => x.signedAt).filter(Boolean).sort().pop() : null;
  render(
    "agreement",
    title || "Signed agreement",
    [names.length ? `Signed by ${esc(names.join(", "))}` : "", done ? `completed ${when(done)}` : "", stateAt || agreementAt ? `anchored ${when(stateAt || agreementAt)}` : ""].filter(Boolean).join(" · "),
    original ? null : "Verified: every signer's passkey signature and entries, and Attest's record of the agreement, anchored on the public blockchain. Drop the original document too, to check it is the one signed.",
  );
}

/**
 * A signed copy's visible pages are its first visibleCopy.byteLength bytes, and exactly Attest's update attaching
 * the evidence follows them. Their SHA-256 is anchored by the wallet that anchored the agreement:
 * sha256("attest.signed_copy.v1|" + agreementId + "|" + variant + "|" + sha256(visible bytes)).
 */
async function checkVisiblePages(ev, files, id, wallet) {
  const v = ev.visibleCopy;
  if (!files.outer) {
    if (v && isHex64(v.sha256)) add("info", "Drop the signed PDF itself to check the pages you see", `Its visible pages have SHA-256 ${mono(v.sha256)}.`);
    return;
  }
  if (!v) {
    if (!files.pdf) add("warn", "This PDF's own pages aren't checked", "It's the agreement's certificate, made when it was downloaded: the record below is verified, not the pages of this PDF. Compare the names, dates and fingerprints on its pages with the ones shown here. The signed pages are in the parties' signed copy.");
    else add("warn", "The pages you see aren't covered by this copy's evidence", "This copy was made before October 10, 2026: its evidence authenticates the original document inside it, not the visible pages. Compare the pages with the original inside, or drop the file on attest.datahubz.com/verify, which checks the whole file against its recorded fingerprint.");
    return;
  }
  const len = Number(v.byteLength);
  if (!(Number.isInteger(len) && len > 0 && len < files.outer.length) || (v.variant !== "full" && v.variant !== "pages")) { add("bad", "The pages you see are not the signed copy", "The file's structure doesn't match its evidence."); return; }
  const pages = files.outer.subarray(0, len);
  const h = await sha256hex(pages);
  if (h !== v.sha256) { add("bad", "The pages you see have been changed", `The visible pages hash to ${mono(h)}, not to the signed copy's ${mono(String(v.sha256))}.`); return; }
  let anchored = null;
  if (wallet) {
    anchored = await onChain("The pages you see", await sha256hex(`attest.signed_copy.v1|${id}|${v.variant}|${h}`), {
      wallet,
      missing: "bad",
      missingDetail: "They aren't anchored as this agreement's signed copy by the wallet that anchored it. Either they were altered, with the evidence edited to match, or the copy was made in the last few minutes and its anchor is on its way: check again shortly.",
    });
  } else add("bad", "The pages' anchor couldn't be checked", "The agreement's own anchor didn't check out, so there is no Attest wallet to check the pages against.");
  if (files.structure && !files.structure.ok) {
    add("bad", "Something was added to this file after Attest sealed it", `${esc(files.structure.why[0].toUpperCase() + files.structure.why.slice(1))}. A PDF reader shows additions like this on top of the signed pages.${anchored ? " The signed pages themselves are intact: you can save them exactly as they were sealed." : ""}`);
    if (anchored) downloads.push({ label: "Save the signed pages exactly as sealed", name: `${id}-signed-pages.pdf`, type: "application/pdf", bytes: pages });
    return;
  }
  if (anchored) add("ok", "The pages you see are the copy sealed when the agreement completed", `${v.variant === "pages" ? "The signed pages, without certificate pages" : "The signed pages with their certificate pages"}: SHA-256 ${mono(h)}. Nothing follows them but the evidence, the original document and this verifier, attached as files.`);
}

// ===================================================================================== agreements, v5
/**
 * The renderer each evidence format's pages are made with, which the completion details must name: v5 is renderer v2,
 * and v6, the same evidence, is renderer v3 (every entry inside its field). Attest's anchor binds the details, so a
 * copy can't change renderer.
 */
const RENDERER_OF_FORMAT = { 5: "attest.render.v2", 6: "attest.render.v3" };

/**
 * Protocol v5 (agreement evidence v5 and v6): statements v3 name each signer by a salted commitment, never an email;
 * the signed state v3 lists each commitment with the SHA-256 of its statement; Attest's agreement anchor v2 also binds
 * the completion details (field layout, verification code, completion time, audit trail, renderer), so this page
 * re-makes the visible pages with the renderer the details name and compares them byte for byte.
 */
async function verifyAgreementV5(ev, files, format) {
  const renderer = RENDERER_OF_FORMAT[format];
  const id = str(ev.agreementId);
  const docSha = str(ev.document && ev.document.sha256);
  const signers = Array.isArray(ev.signers) ? ev.signers : [];
  // The certificate anyone may download carries the same record without the document, the entries or the audit trail.
  const certificate = Boolean(ev.visibleCopy && ev.visibleCopy.variant === "certificate");
  if (!/^agr_[0-9A-Za-z_-]+$/.test(id) || !isHex64(docSha) || !signers.length || typeof ev.details !== "string") {
    add("bad", "This isn't a complete agreement record", "It names no agreement, document, signers or completion details.");
    return render("agreement", "Signed agreement");
  }
  // 1. The signed state v3.
  const ss = ev.signedState || {};
  const stateSha = isHex64(ss.sha256) ? ss.sha256 : null;
  let state = null;
  const statementOf = new Map();
  for (const s of signers) { let st = null; try { st = JSON.parse(s.statement); } catch {} statementOf.set(s, st); }
  if (typeof ss.message === "string") {
    let m = null;
    try { m = JSON.parse(ss.message); } catch {}
    const h = await sha256hex(ss.message);
    let shape = m && m.kind === "attest.agreement_completion.v3" && m.agreementId === id && m.documentSha256 === docSha && Array.isArray(m.signers) && m.signers.length === signers.length;
    if (shape) {
      for (const s of signers) {
        const x = m.signers.find((y) => y.signer === s.commitment);
        if (!x || typeof s.statement !== "string" || x.statementSha256 !== (await sha256hex(s.statement))) { shape = false; break; }
      }
    }
    if (h === stateSha && shape) { state = m; add("ok", "The signed state names this agreement, its document and every signer's statement", `SHA-256 ${mono(h)}`); }
    else add("bad", "The signed state doesn't match this agreement", h !== stateSha ? `It hashes to ${mono(h)}, not to the anchored ${mono(stateSha || "")}.` : "It names a different agreement, document, set of signers or statements.");
  } else add("bad", "The signed state is missing", "");
  const title = state ? str(state.title) : null;

  // 2. The completion details, as Attest's anchor binds them.
  let details = null;
  try { details = JSON.parse(ev.details); } catch {}
  const detailsSha = await sha256hex(ev.details);
  const commitments = signers.map((s) => s.commitment).sort().join("\n");
  const detailsOk = details && canonicalJson(details) === ev.details && isHex64(details.trailSha256) && details.renderer === renderer && Array.isArray(details.signers) && [...details.signers].sort().join("\n") === commitments && Array.isArray(details.fields) && details.fields.every((f) => Array.isArray(f) && f.length === 8 && details.signers.includes(f[7]));
  if (!detailsOk) add("bad", "The completion details don't match this agreement", "They name other signers, or aren't in the form Attest anchors.");
  // The audit trail, which the details name by its SHA-256 (a signed copy carries it; the certificate doesn't).
  let trail = null;
  if (detailsOk && typeof ev.trail === "string") {
    if ((await sha256hex(ev.trail)) === details.trailSha256) { try { trail = JSON.parse(ev.trail); } catch {} }
    if (!Array.isArray(trail)) { trail = null; add("bad", "The audit trail isn't the one Attest anchored", "Its SHA-256 isn't the one the completion details name."); }
  } else if (ev.trail != null) add("bad", "The audit trail isn't readable", "");

  // 3. The original document inside.
  const original = files.pdf;
  if (original) {
    const h = await sha256hex(original);
    add(h === docSha ? "ok" : "bad", h === docSha ? `The original document${files.outer ? " inside" : ""} is exactly the one signed` : `The original document${files.outer ? " inside" : ""} is not the one signed`, `SHA-256 ${mono(h)}`);
  } else if (files.outer && certificate) add("info", "The document isn't in this certificate", `It stays with the parties, whose signed copy carries it. Its fingerprint is ${mono(docSha)}.`);
  else if (files.outer) add("warn", "The original document isn't in this file", "A signed copy carries it as original-document.pdf.");
  else add("info", "Drop the original document too, to check it is the one signed", `Its fingerprint is ${mono(docSha)}.`);

  // 4. Each signer: their statement (v3), their entries and where they appear, and their passkey signature.
  const names = [];
  const entries = {};
  let entriesComplete = true;
  for (const s of signers) {
    const st = statementOf.get(s);
    const who = st && typeof st.name === "string" && st.name ? st.name : "A signer";
    names.push(who);
    if (!st || !s.webauthnAssertion || !s.passkey || !isHex64(s.commitment)) { add("bad", `${who}: no signature evidence`, ""); continue; }
    const inState = state ? state.signers.find((x) => x.signer === s.commitment) : null;
    if (s.entries != null) {
      const eh = await sha256hex(s.entries);
      add(eh === s.entriesSha256 ? "ok" : "bad", `${who}: the entries are the ones they signed`, `Entries SHA-256 ${mono(eh)}`);
      try { for (const [fid, , value] of JSON.parse(s.entries)) entries[fid] = value; } catch { entriesComplete = false; }
    } else if (s.entriesSha256) entriesComplete = false;
    // Where their entries appear: the layout their statement signed is their fields in the anchored details.
    const mine = detailsOk ? details.fields.filter((f) => f[7] === s.commitment).map((f) => [f[0], f[1], f[2], f[3], f[4], f[5], f[6]]).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)) : null;
    const layoutOk = mine && st.layoutSha256 === (await sha256hex(JSON.stringify(mine)));
    const fields = (st.fieldsSha256 ?? null) === (s.entriesSha256 ?? null) && (!state || (inState && (inState.fieldsSha256 ?? null) === (st.fieldsSha256 ?? null)));
    const named = st.v === 3 && st.agreementId === id && st.documentSha256 === docSha && st.signer === s.commitment && st.title === title && fields && layoutOk && (!state || (inState && st.signedAt === inState.signedAt));
    add(named ? "ok" : "bad", `${who}: the signed statement names this agreement, its document${s.entriesSha256 ? ", their entries and where they appear" : ""}`, `${esc(str(st.statement))}${st.encryptionKey ? " It also commits to their own encryption key." : ""} No email appears in it: the signer is named by a salted commitment.`);
    try {
      const w = await signerPasskeyCheck(s);
      add(w.ok ? "ok" : "bad", `${who}: passkey signature valid`, w.ok ? `Signed ${when(st.signedAt)} on ${esc(TRUST.webauthn.origin)}, with the signer present and verified on their device` : esc(JSON.stringify(w.parts)));
    } catch (e) { add("bad", `${who}: passkey signature could not be checked`, esc(e.message)); }
  }

  // 5. The anchors: the signed state's receipt, then Attest's agreement anchor v2 (signatures and details).
  const an = ev.anchor;
  let wallet = null, stateAt = null, anchorTx = null;
  if (stateSha && an && an.merkleRoot) {
    const r = await checkAnchor("The signed state", { ...an, type: "merkle" }, stateSha);
    if (r) { wallet = r.wallet; stateAt = r.at; anchorTx = isTx(an.txHash) ? an.txHash : null; }
  } else add(an ? "bad" : "wait", an ? "The anchor's Merkle path is missing" : "The signed state isn't anchored yet", an ? "" : "Anchoring follows within minutes.");
  let agreementAt = null;
  if (stateSha && wallet) {
    const rows = signers
      .map((s) => [String(s.commitment), s.statement ?? "", (s.passkey && s.passkey.publicKeySpki) ?? "", (s.passkey && s.passkey.alg) ?? null, (s.webauthnAssertion && s.webauthnAssertion.authenticatorData) ?? "", (s.webauthnAssertion && s.webauthnAssertion.clientDataJSON) ?? "", (s.webauthnAssertion && s.webauthnAssertion.signature) ?? ""])
      .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    const value = await sha256hex(`attest.agreement.v2|${id}|${stateSha}|${await sha256hex(JSON.stringify(rows))}|${detailsSha}`);
    const r = await onChain("Attest's record of this agreement, its signatures and what its signed copy shows", value, {
      wallet,
      missing: "bad",
      missingDetail: "Attest anchors every completed agreement, with every signer's statement, passkey key and signature and the completion details, from the wallet that anchored its signed state. This one isn't anchored: either the evidence was changed, or the agreement was completed in the last few minutes and its anchor is on its way (check again shortly).",
    });
    if (r) agreementAt = r.at;
  }

  // 6. The visible pages, re-made here from what was signed.
  const notClean = files.outer ? await checkVisiblePagesV5(ev, files, { renderer, id, title, stateSha, anchorTx, wallet, details: detailsOk ? details : null, trail, signers, statementOf, state, entries, entriesComplete, original }) : false;
  if (!files.outer && ev.visibleCopy && isHex64(ev.visibleCopy.sha256)) add("info", "Drop the signed PDF itself to check the pages you see", `Its visible pages have SHA-256 ${mono(ev.visibleCopy.sha256)}.`);

  // 7. Zero-knowledge proofs about this agreement.
  for (const p of ev.proofs || []) {
    if (!p || !p.proof) continue;
    await checkAgreementProof({ ...p, revealed: p.revealed || {} }, p.root || null, `Proof ${str(p.id)}`);
  }
  const code = detailsOk && typeof details.verifyCode === "string" && /^[0-9A-Z]{8}$/.test(details.verifyCode) ? `ATT-${details.verifyCode.slice(0, 4)}-${details.verifyCode.slice(4)}` : null;
  render(
    "agreement",
    title || "Signed agreement",
    [names.length ? `Signed by ${esc(names.join(", "))}` : "", detailsOk ? `completed ${when(details.completedAt)}` : "", code ? `verification code ${esc(code)}` : "", stateAt || agreementAt ? `anchored ${when(stateAt || agreementAt)}` : ""].filter(Boolean).join(" · "),
    certificate && files.outer ? "Verified: this certificate's pages, re-made here from what was signed, every signer's passkey signature, and Attest's record of the agreement, anchored on the public blockchain." : original ? (files.outer ? (notClean ? `Verified: the document as signed (attached to this copy), every signer's passkey signature and entries, and Attest's record of the agreement, anchored on the public blockchain. This copy's pages were re-made here from what was signed. ${L.notCleanNote}` : "Verified: the pages you see, re-made here from what was signed, the document, every signer's passkey signature and entries, and Attest's record of the agreement, anchored on the public blockchain.") : null) : "Verified: every signer's passkey signature and entries, and Attest's record of the agreement, anchored on the public blockchain. Drop the original document too, to check it is the one signed.",
  );
}

/**
 * A v5 or v6 signed copy's visible pages must be exactly what its renderer (v2 or v3) makes from the original
 * document, the completion details, every signer's entries and name, the signed state and its anchor transaction. A
 * party's browser made them when it sealed the copy; this page makes them again and compares every byte. Returns
 * whether the document isn't clean for renderer v3 (its copy's pages may look different in some PDF readers).
 */
async function checkVisiblePagesV5(ev, files, c) {
  const v = ev.visibleCopy;
  const len = v ? Number(v.byteLength) : NaN;
  if (!v || !(Number.isInteger(len) && len > 0 && len < files.outer.length) || !["full", "pages", "certificate"].includes(v.variant) || v.renderer !== c.renderer) { add("bad", "The pages you see are not the signed copy", "The file's structure doesn't match its evidence."); return; }
  const certificate = v.variant === "certificate";
  const pages = files.outer.subarray(0, len);
  const remake = L.renderers && L.renderers[c.renderer];
  const needs = certificate ? null : !c.original ? "The original document isn't in this file." : !c.entriesComplete ? "A signer's entries are missing from the evidence." : v.variant === "full" && !c.trail ? "The audit trail isn't in the evidence." : null;
  // A v5 signed copy always carries what re-making its pages needs: without it, the file was changed.
  if (needs) { add("bad", "The pages you see can't be re-made from this file's evidence", `${needs} A ${v.variant === "pages" ? "signed pages copy" : "signed copy"} always carries it, so this file was changed.`); return; }
  if (!c.details || !c.state || !c.anchorTx || !remake) {
    add("warn", "The pages you see couldn't be re-made here", !c.anchorTx ? "The signed state's anchor transaction didn't check out." : "The signed state or the completion details didn't check out.");
    return;
  }
  let made = null;
  try {
    made = await remake({
      original: certificate ? null : c.original,
      variant: v.variant,
      appUrl: TRUST.webauthn.origin,
      agreement: { id: c.id, title: c.title, documentSha256: str(ev.document.sha256), completionHash: c.stateSha, anchorTxHash: c.anchorTx },
      details: c.details,
      trail: certificate ? null : c.trail,
      signers: c.signers.map((s) => ({ commitment: s.commitment, name: str((c.statementOf.get(s) || {}).name), signedAt: str((c.state.signers.find((x) => x.signer === s.commitment) || {}).signedAt) })),
      entries: certificate ? {} : c.entries,
      // The certificate alone carries the copy's note when the agreement recorded its document as not clean.
      ...(certificate && v.documentClean === false ? { documentNotClean: true } : {}),
    });
  } catch (e) {
    add("bad", "The pages you see couldn't be re-made from what was signed", esc(e.message));
    return;
  }
  const same = made.length === pages.length && made.every((b, i) => pages[i] === b);
  if (!same) {
    add("bad", "The pages you see aren't what was signed", "Re-made here from the original document, the completion details and every signer's entries, they differ from this file's pages. You can save the pages as they were signed.");
    downloads.push({ label: "Save the pages as signed (re-made here)", name: `${c.id}-signed-pages.pdf`, type: "application/pdf", bytes: made });
    return;
  }
  if (files.structure && !files.structure.ok) {
    add("bad", "Something was added to this file after Attest sealed it", `${esc(files.structure.why[0].toUpperCase() + files.structure.why.slice(1))}. A PDF reader shows additions like this on top of the signed pages. The signed pages themselves are intact: you can save them exactly as they were signed.`);
    downloads.push({ label: "Save the signed pages exactly as signed", name: `${c.id}-signed-pages.pdf`, type: "application/pdf", bytes: pages });
    return;
  }
  if (certificate) {
    add("ok", "The pages you see are exactly Attest's certificate of this agreement", `Re-made here, byte for byte, from every signer's signed statement, the signed state and Attest's anchored details (renderer ${c.renderer}). Nothing follows them but the evidence and this verifier, attached as files.`);
    return;
  }
  // A document renderer v3's check finds not clean: its copy was made with the best protection v3 can give, and says so.
  const check = L.cleanCheck && L.cleanCheck[c.renderer];
  const notClean = check ? !(await check(c.original).catch(() => false)) : false;
  if (notClean) {
    add("ok", "This copy's pages are exactly the ones Attest made from what was signed", `Re-made here, byte for byte, from the original document, every signer's entries in the places their statements name, and Attest's anchored details${v.variant === "full" ? " and audit trail, with the certificate pages" : ""} (renderer ${c.renderer}). Nothing follows them but the evidence, the original document and this verifier, attached as files.`);
    add("info", L.notCleanNote, "The original document is attached to this copy exactly as it was signed, and its fingerprint is the one anchored: that is what was signed. Open it from this copy's attachments, or save it here.");
    downloads.push({ label: "Save the document exactly as signed", name: `${c.id}-original-document.pdf`, type: "application/pdf", bytes: c.original });
  } else {
    add("ok", "The pages you see are exactly the document as signed", `Re-made here, byte for byte, from the original document, every signer's entries in the places their statements name, and Attest's anchored details${v.variant === "full" ? " and audit trail, with the certificate pages" : ""} (renderer ${c.renderer}). Nothing follows them but the evidence, the original document and this verifier, attached as files.`);
  }
  // The same pages, anchored when the copy was sealed: a second, independent hold on them.
  await onChain("The same pages, anchored when the copy was sealed", await sha256hex(`attest.signed_copy.v1|${c.id}|${v.variant}|${await sha256hex(pages)}`), {
    wallet: c.wallet,
    missing: "wait",
    missingDetail: "Attest anchors a signed copy's pages, from the wallet that anchored the agreement, when a party seals it. If the copy was made in the last few minutes, its anchor is on its way: check again shortly.",
  });
  return notClean;
}

// ============================================================================================== receipts
async function verifyReceipt(ev, files) {
  const r = ev.receipt || {};
  const sha = str(r.sha256);
  if (!isHex64(sha) || typeof r.id !== "string") { add("bad", "This isn't a complete receipt", ""); return render("receipt", "Receipt"); }
  if (files.other) {
    const h = await sha256hex(files.other);
    add(h === sha ? "ok" : "bad", h === sha ? `${files.otherName} is exactly the recorded content` : `${files.otherName} is not the recorded content`, `SHA-256 ${mono(h)}`);
  } else if (!ev.zkProof) add("info", "Drop the file too, to check it is the recorded content", `Recorded fingerprint ${mono(sha)}. Nothing is uploaded.`);
  if (ev.zkProof) {
    const z = ev.zkProof;
    if (z.circuit === "security_scan_proof_v2" && z.proof) {
      let ok = false;
      try { ok = await groth16("security_scan_proof_v2", z.publicSignals, z.proof); } catch {}
      add(ok ? "ok" : "bad", ok ? "The zero-knowledge proof is valid" : "The zero-knowledge proof is not valid", "Circuit security_scan_proof_v2, checked here with Groth16 (BN254) against its pinned verification key.");
      if (ok) {
        const bound = (await sha256hex(`attest.scan.v2|${z.publicSignals[1]}`)) === sha;
        add(bound ? "ok" : "bad", "The proof is about this receipt's commitment", `Commitment ${mono(z.publicSignals[1])}; the receipt records sha256("attest.scan.v2|" + commitment).`);
        add(z.publicSignals[0] === "1" ? "ok" : "bad", z.publicSignals[0] === "1" ? "The predicate holds" : "The predicate does NOT hold", "Proven without revealing the underlying scan.");
      }
    } else add("warn", "This proof's circuit has no public verification key", "It's an earlier circuit; Attest verified it when it was made.");
    if (z.zkverify && isTx(z.zkverify.txHash)) add("info", "Also verified on zkVerify", mono(z.zkverify.txHash));
  }
  const a = await checkAnchor("The receipt", ev.anchor, sha);
  if (typeof r.claim === "string" && r.claim) add("info", `Its description: “${r.claim}”`, "Written by the account that recorded it. The anchor commits to the receipt and its fingerprint, not to this text.");
  if (Array.isArray(r.supersededBy) && r.supersededBy.length) add("warn", "A correcting receipt supersedes this one", esc(r.supersededBy.join(", ")));
  render("receipt", "Receipt", `${esc(r.id)}${a ? ` · recorded by ${when(a.at)}` : ""}`);
}

// ========================================================================================== certificates
async function verifyCertificate(ev, files) {
  const c = ev.certificate || {};
  const content = c.content && typeof c.content === "object" ? c.content : null;
  if (!content || typeof c.id !== "string") { add("bad", "This isn't a complete certificate", ""); return render("certificate", "Certificate"); }
  // Content: what every signer signed and the issuer's credential carries.
  const ch = await sha256hex(canonicalJson(content));
  add(ch === c.contentSha256 && content.id === c.id ? "ok" : "bad", "The certificate's content is exactly what was signed", `SHA-256 of its canonical JSON ${mono(ch)}`);
  // The issuer: its key committed by an Attest wallet, then its signature.
  const issuer = ev.issuer || {};
  const key = await checkIssuerKey(issuer, c.issuedAt);
  let payload = null;
  if (typeof c.vcJwt === "string" && key) {
    try {
      const kid = JSON.parse(dec.decode(b64url(c.vcJwt.split(".")[0]))).kid;
      const vm = (key.doc.verificationMethod || []).find((m) => m.id === kid && m.publicKeyJwk);
      const j = vm ? await jwsValid(c.vcJwt, vm.publicKeyJwk) : { ok: false };
      const p = j.payload || {};
      const ok = j.ok && p.issuer && p.issuer.id === issuer.did && p.credentialSubject && p.credentialSubject.contentSha256 === ch;
      if (ok) payload = p;
      add(ok ? "ok" : "bad", `Signed by the issuer${ok && p.issuer.name ? `, ${p.issuer.name}` : ""}`, `W3C Verifiable Credential (vc+jwt, ES256), key ${mono(kid || "")}`);
    } catch (e) { add("bad", "The issuer's signature could not be checked", esc(e.message)); }
  } else if (!c.vcJwt) add("bad", "The issuer's signature is missing", "");
  // Signers: each statement and passkey signature, and the issuer's credential names each one's statement and key.
  const committed = (payload && payload.credentialSubject && payload.credentialSubject.signatures) || [];
  for (const s of ev.signers || []) {
    const e = s.evidence || null;
    let st = null; try { st = JSON.parse(e.consentJson); } catch {}
    const stSha = st ? await sha256hex(e.consentJson) : null;
    const entry = committed.find((x) => x && x.statementSha256 === stSha) || null;
    // Names come from what was signed: the issuer's credential, or the signer's own statement.
    const who = (entry && typeof entry.name === "string" && entry.name) || (st && typeof st.name === "string" && st.name) || "A signer";
    if (!e || !st) { add("bad", `${who}: no signature evidence`, ""); continue; }
    add(st.certificate === c.id && st.contentSha256 === ch ? "ok" : "bad", `${who}: the statement names this certificate and content`, "");
    try {
      const w = await passkeyCheck({ statement: e.consentJson, authenticatorData: e.authenticatorData, clientDataJSON: e.clientDataJSON, signature: e.signature, publicKeySpki: e.publicKeySpki, alg: e.alg });
      add(w.ok ? "ok" : "bad", `${who}: passkey signature valid`, w.ok ? `Signed on ${esc(TRUST.webauthn.origin)}, with the signer present and verified on their device` : esc(JSON.stringify(w.parts)));
    } catch (err) { add("bad", `${who}: passkey signature could not be checked`, esc(err.message)); }
    if (payload) {
      const keyShas = [await sha256hex(e.publicKeySpki), await sha256hex(b64(e.publicKeySpki))];
      add(entry && keyShas.includes(entry.publicKeySha256) ? "ok" : "bad", `${who}: the issuer's credential names this signature and passkey key`, "");
    }
  }
  // The PDF
  if (files.pdf) {
    const h = await sha256hex(files.pdf);
    add(h === c.pdfSha256 ? "ok" : "bad", h === c.pdfSha256 ? "The PDF is exactly the issued certificate" : "The PDF is not the issued certificate", `SHA-256 ${mono(h)}`);
  } else add("info", "Drop the certificate PDF too, to check it is the issued one", `Its fingerprint is ${mono(str(c.pdfSha256))}.`);
  // Issuance, from the issuer's own wallet
  if (!ev.anchor) add("wait", "The certificate isn't anchored yet", "");
  else if (!isHex64(c.pdfSha256) || typeof c.vcJwt !== "string") add("bad", "The certificate's anchor can't be checked", "Its evidence lacks the issued PDF's fingerprint or the issuer's credential, which the anchor commits to.");
  else if (key) {
    const value = await sha256hex(`attest.certificate.v1|${c.id}|${c.pdfSha256}|${await sha256hex(c.vcJwt)}`);
    if (onAttestChain("The issued certificate", ev.anchor)) await onChain("The issued certificate", value, { txHash: ev.anchor.txHash, wallet: key.wallet });
  }
  // Current status, read from the chain: a revocation anchored by the issuer's wallet.
  if (key) {
    try {
      const r = await attested(await node(), await sha256hex(`attest.certificate.revoked.v2|${c.id}`), key.wallet);
      if (r.anchored && r.ok) add("bad", "Revoked", `Revoked on ${when(r.at)} by the issuer's wallet, read from the chain just now.`);
      else if (ev.revocation) add("bad", "Revoked", `On ${when(ev.revocation.revokedAt)}, per the evidence.`);
      else add("ok", "Not revoked", "Read from the chain just now: no revocation has been anchored for this certificate.");
    } catch (e) {
      if (ev.revocation) add("bad", "Revoked", `On ${when(ev.revocation.revokedAt)}, per the evidence.`);
      add("warn", "The current status couldn't be read from the chain", esc(e.message));
    }
  } else if (ev.revocation) add("bad", "Revoked", `On ${when(ev.revocation.revokedAt)}, per the evidence.`);
  if (content.validUntil && new Date(content.validUntil) < new Date()) add("warn", "Expired", `Valid until ${when(content.validUntil)}.`);
  // Findings closure proof
  const z = ev.findingsClosure;
  if (z && z.proof) {
    const context = (BigInt("0x" + (await sha256hex(`attest.certificate.findings|${c.id}`))) % P).toString();
    const inContent = content.findingsClosure && content.findingsClosure.commitment;
    let ok = false;
    try { ok = z.publicSignals[1] === context && z.publicSignals[0] === z.commitment && inContent === BigInt(z.commitment).toString(16).padStart(64, "0") && (await groth16("findings_closure", z.publicSignals, z.proof)); } catch {}
    add(ok ? "ok" : "bad", "Zero-knowledge proof: every finding in the assessed set is closed", "Bound to this certificate and to the commitment in its signed content; checked here with Groth16 against the circuit's pinned verification key.");
  }
  const issuerName = payload && payload.issuer && payload.issuer.name ? payload.issuer.name : issuer.did;
  render("certificate", str(content.title) || "Certificate", `${esc(c.id)} · issued by ${esc(issuerName || "")}${content.asOf ? ` · as of ${when(content.asOf)}` : ""}`);
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
    // Keys come only from the issuer's DID document above: no other DID (did:key included) can sign.
    if (/^did:/i.test(url)) throw new Error(`Unknown key: ${url}`);
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
  if (!cred || typeof cred !== "object" || !ev.issuer) { add("bad", "This isn't a complete Proof Card", ""); return render("card", "Proof Card"); }
  const subject = cred.credentialSubject || {};
  const issuerDid = typeof cred.issuer === "string" ? cred.issuer : cred.issuer && cred.issuer.id;
  if (issuerDid !== ev.issuer.did) add("bad", "The card names a different issuer than its evidence", "");
  // Holder's approval of this exact disclosure
  const h = ev.holderApproval;
  if (h) {
    let st = null; try { st = JSON.parse(h.statementJson); } catch {}
    const disclosed = await sha256hex(canonicalJson(cred));
    const names = st && st.disclosedSha256 === disclosed && st.credentialId === cred.id;
    add(names ? "ok" : "bad", "The holder approved sharing exactly this copy", `${esc(st ? str(st.statement) : "")} Disclosed copy SHA-256 ${mono(disclosed)}`);
    try {
      const w = await passkeyCheck({ statement: h.statementJson, authenticatorData: h.authenticatorData, clientDataJSON: h.clientDataJSON, signature: h.signature, publicKeySpki: h.publicKeySpki, alg: h.alg });
      add(w.ok ? "ok" : "bad", "The holder's passkey signature is valid", w.ok ? `Approved ${when(st && st.approvedAt ? st.approvedAt : h.approvedAt)} on ${esc(TRUST.webauthn.origin)}, with the holder present and verified on their device` : esc(JSON.stringify(w.parts)));
    } catch (e) { add("bad", "The holder's passkey signature could not be checked", esc(e.message)); }
  } else add("warn", "This share has no passkey approval", "It was shared before approvals existed.");
  // The issuer's key, committed by an Attest wallet; then the issuer's signature and the signed status lists.
  const key = await checkIssuerKey(ev.issuer, cred.validFrom);
  // The vocabulary this verifier carries for the card's fields: the version Attest committed on chain.
  const ctxUrls = (Array.isArray(cred["@context"]) ? cred["@context"] : [cred["@context"]]).filter((u) => typeof u === "string" && L.contexts[u] && u.startsWith("https://attest.datahubz.com/"));
  for (const u of ctxUrls) {
    const anchor = (ev.contextAnchors && ev.contextAnchors[u]) || {};
    await onChain(`The card's vocabulary (${u})`, await sha256hex(`attest.context.v1|${u}|${canonicalJson(L.contexts[u])}`), { wallet: anchor.from, missing: "warn", missingDetail: "This verifier carries its own copy, so a file can't redefine what the fields mean; its commitment on chain couldn't be found." });
  }
  // Every proof, on the card and on its status lists, names the issuer's committed key.
  const proofsOf = (c) => (c && c.proof ? (Array.isArray(c.proof) ? c.proof : [c.proof]) : []);
  const foreign = [cred, ...(ev.statusLists || []).map((l) => l && l.credential)].flatMap(proofsOf).find((p) => !p || typeof p.verificationMethod !== "string" || !p.verificationMethod.startsWith(`${ev.issuer.did}#`));
  if (foreign) add("bad", "A signature names a key outside the issuer's DID document", mono(str(foreign && foreign.verificationMethod)));
  const loader = loaderFor(ev);
  const suite = [new L.DataIntegrityProof({ cryptosuite: L.createVerifyCryptosuite() }), new L.DataIntegrityProof({ cryptosuite: L.ecdsaRdfc2019 })];
  const validUntil = cred.validUntil ? new Date(cred.validUntil) : null;
  const at = validUntil && validUntil < new Date() ? new Date(validUntil.getTime() - 1000) : new Date();
  let sigOk = false;
  try {
    const r = await L.vc.verifyCredential({ credential: cred, suite, documentLoader: loader, checkStatus: L.checkStatus, now: at });
    sigOk = Boolean(key && !foreign && r.results && r.results.some((x) => x.verified));
    const why = sigOk ? "" : (() => { const e = (r.results || []).map((x) => x.error).find(Boolean) || r.error; const m = e && [e.message || (e.errors && e.errors[0] && e.errors[0].message), e.cause && e.cause.message].filter(Boolean).join(": "); return m ? ` (${esc(m)})` : ""; })();
    add(sigOk ? "ok" : "bad", "Signed by the issuer", `W3C Verifiable Credential with selective disclosure (ecdsa-sd-2023): only the fields shown were revealed, and each is covered by the issuer's signature.${why}`);
    const sts = (r.statusResult && r.statusResult.results) || [];
    for (const s of sts) {
      const purpose = s.credentialStatus && s.credentialStatus.statusPurpose;
      add(s.verified ? (s.status ? "bad" : "ok") : "bad", `${purpose === "suspension" ? "Suspension" : "Revocation"} list: ${s.status ? (purpose === "suspension" ? "suspended" : "revoked") : "clear"}`, "The issuer's signed status list in this evidence file.");
    }
  } catch (e) { add("bad", "The issuer's signature could not be checked", esc(e.message)); }
  // Each status list version is anchored
  for (const l of ev.statusLists || []) {
    const lh = await sha256hex(canonicalJson(l.credential));
    if (l.sha256 && lh !== l.sha256) { add("bad", `The ${str(l.purpose)} list is not the anchored version`, ""); continue; }
    await checkAnchor(`The ${str(l.purpose)} list (version ${esc(l.version)})`, l.anchor, lh);
  }
  // Issuance anchor: sha256 of the issuer's base signature, which this copy carries
  const bs = await baseSignatureSha256(cred);
  if (bs && ev.issuance) {
    if (ev.issuance.baseSignatureSha256 && bs !== ev.issuance.baseSignatureSha256) add("bad", "The issuance anchor is for a different card", "");
    else await checkAnchor("The card's issuance", ev.issuance.anchor, bs);
  }
  // Current status, read from the chain: the latest of sha256("attest.card.status.v1|" + cardId + "|" + n + "|" + state),
  // each from the issuer's wallet.
  if (key && ev.status && typeof ev.status.cardId === "string") {
    try {
      const url = await node();
      let state = "active", changed = null;
      for (let n = 1; n < 200; n++) {
        let hit = null;
        for (const s of ["revoked", "suspended", "active"]) {
          const r = await attested(url, await sha256hex(`attest.card.status.v1|${ev.status.cardId}|${n}|${s}`), key.wallet);
          if (r.anchored && r.ok) { hit = { s, at: r.at }; break; }
        }
        if (!hit) break;
        state = hit.s; changed = hit.at;
      }
      add(state === "active" ? "ok" : "bad", state === "active" ? "Active now" : state === "revoked" ? "Revoked" : "Suspended", `Read from the chain just now${changed ? `: last change on ${when(changed)}, by the issuer's wallet` : ": no status change has been anchored"}.`);
    } catch (e) { add("warn", "The current status couldn't be read from the chain", esc(e.message)); }
  }
  if (validUntil && validUntil < new Date()) add("warn", "Expired", `Valid until ${when(cred.validUntil)}.`);
  const issuerName = cred.issuer && typeof cred.issuer === "object" && typeof cred.issuer.name === "string" ? cred.issuer.name : issuerDid;
  const shown = sigOk ? Object.entries(subject).filter(([k]) => k !== "id" && k !== "type").map(([k, v]) => `${esc(k)}: ${esc(typeof v === "object" ? JSON.stringify(v) : v)}`).join(" · ") : "";
  render("card", sigOk && typeof cred.name === "string" ? cred.name : "Proof Card", `Issued by ${esc(issuerName || "")}${shown ? ` · ${shown}` : ""}`);
}

// ======================================================================================= agreement proofs
/**
 * An agreement proof: Groth16 against the circuit's pinned key, its public inputs recomputed from what it reveals,
 * and the root it proves against, anchored by an Attest wallet. Returns the statement it proves, or null.
 */
async function checkAgreementProof(p, root, label) {
  const circuit = p.circuit;
  if (circuit !== "agreement_membership" && circuit !== "agreement_with_party") { add("bad", `${label}: an unknown circuit`, esc(String(circuit))); return null; }
  const withParty = circuit === "agreement_with_party";
  const sig = Array.isArray(p.publicSignals) ? p.publicSignals : [];
  let ok = false;
  try { ok = await groth16(circuit, sig, p.proof); } catch {}
  add(ok ? "ok" : "bad", ok ? `${label}: the zero-knowledge proof is valid` : `${label}: the zero-knowledge proof is not valid`, `Circuit ${esc(circuit)}, checked here with Groth16 (BN254) against its pinned verification key.`);
  if (!ok) return null;
  const r = p.revealed || {};
  const party = typeof r.party === "string" && r.party ? r.party.trim().toLowerCase() : null;
  const counterparty = typeof r.counterparty === "string" && r.counterparty ? r.counterparty.trim().toLowerCase() : null;
  const partyOk = party && (await fieldOf(party)) === sig[1];
  const counterOk = !withParty || (counterparty && (await fieldOf(counterparty)) === sig[2]);
  add(partyOk && counterOk ? "ok" : "bad", `${label}: it is about ${esc(withParty ? `${party} and ${counterparty}` : party || "nobody named")}`, "Each email's field element, sha256(email) mod p, matches the proof's public input.");
  const daySig = sig[withParty ? 3 : 2];
  const date = daySig != null ? new Date(Number(daySig) * 86400000).toISOString().slice(0, 10) : null;
  add(date && (!r.dateISO || r.dateISO === date) ? "ok" : "bad", `${label}: completed on ${date || "no date"}`, "The completion day is a public input of the proof.");
  if (sig[withParty ? 4 : 3] !== (await fieldOf("attest.identity.v1"))) add("bad", `${label}: unexpected identity salt`, "");
  const rootHex = BigInt(sig[0] || "0").toString(16).padStart(64, "0");
  if (root && root.value && String(root.value).replace(/^0x/, "").toLowerCase() !== rootHex) add("bad", `${label}: proven against a different root than the evidence names`, "");
  const ra = (root && root.anchor) || {};
  if (onAttestChain(`${label}: the record it proves against`, ra)) {
    await onChain(`${label}: the record it proves against`, rootHex, { wallet: ra.from, txHash: ra.txHash, missing: "wait", missingDetail: `Root ${mono("0x" + rootHex)}. It commits to every completed agreement on Attest; anchoring follows within minutes.` });
  }
  if (p.zkverify && isTx(p.zkverify.txHash)) add("info", `${label}: also verified on zkVerify`, mono(p.zkverify.txHash));
  return partyOk && counterOk ? (withParty ? `${party} and ${counterparty} signed an agreement, completed on ${date}.` : `${party} signed an agreement, completed on ${date}.`) : null;
}

async function verifyProof(ev) {
  const p = ev.proof || {};
  const statement = await checkAgreementProof({ ...p, revealed: p.revealed || {} }, ev.root, "The proof");
  render("proof", statement || "Zero-knowledge proof", `${esc(str(p.id))} · ${esc(str(p.circuit))} · reveals only the emails shown and the completion day`);
}

// ============================================================================================= analytics
const FIGURE_LABELS = { newAccounts: "New accounts", sent: "Documents sent", completed: "Documents completed", signatures: "Passkey signatures", proofsShared: "Proofs shared", anchors: "Anchors on Horizen" };

/** A Merkle root over leaves sorted by value: SHA-256 of sorted pairs, an odd node promoted (as Attest's trees). */
async function rootOfLeaves(leaves) {
  if (!leaves.length) return null;
  let level = [...leaves].map((x) => String(x).toLowerCase()).sort();
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 === level.length) { next.push(level[i]); continue; }
      const [a, b] = level[i] < level[i + 1] ? [level[i], level[i + 1]] : [level[i + 1], level[i]];
      const both = new Uint8Array(64); both.set(unhex(a)); both.set(unhex(b), 32);
      next.push(await sha256hex(both));
    }
    level = next;
  }
  return level[0];
}

/**
 * Sealed daily figures: each snapshot's anchored summary names its figures and its commitments (a Merkle root per
 * figure over the records it counted) by SHA-256. Its receipt dates it; Attest's own anchor of the day,
 * sha256("attest.analytics.v1|" + day + "|" + scope + "|" + sha256), from the same wallet, makes it Attest's.
 */
async function verifyAnalytics(ev) {
  const days = [];
  for (const s of ev.snapshots || []) {
    const day = str(s.day), scope = str(s.scope);
    days.push(day);
    const label = `${day} (${scope})`;
    const h = await sha256hex(str(s.canonical));
    if (h !== s.sha256) { add("bad", `${label}: the sealed summary doesn't match its fingerprint`, ""); continue; }
    let content = null; try { content = JSON.parse(s.canonical); } catch {}
    // The day and scope come from the anchored summary itself (the file's labels are only labels).
    if (!content || content.day !== day || typeof content.scope !== "string") { add("bad", `${label}: the sealed summary is for a different day`, ""); continue; }
    const r = await checkAnchor(`${label}: the sealed summary`, s.anchor, s.sha256);
    if (r) {
      await onChain(`${label}: Attest's seal of the day`, await sha256hex(`attest.analytics.v1|${content.day}|${content.scope}|${h}`), {
        wallet: r.wallet,
        missing: "bad",
        missingDetail: "Attest anchors every sealed day under its own value, from the wallet that recorded it. This day isn't: a receipt alone could be anyone's record of the same fingerprint.",
      });
    }
    if (content.format !== "attest.analytics_snapshot.v2") {
      add("warn", `${label}: sealed before records were committed`, "Its figures are anchored as they were sealed, but not tied to the records behind them (snapshot format v1).");
      continue;
    }
    let commitments = null;
    if (s.commitments) {
      const ok = (await sha256hex(s.commitments)) === content.commitmentsSha256;
      add(ok ? "ok" : "bad", `${label}: the commitments are the sealed ones`, "One Merkle root per figure, named by its SHA-256 in the anchored summary.");
      if (ok) commitments = JSON.parse(s.commitments);
    }
    let figures = null;
    if (s.figures) {
      const ok = (await sha256hex(s.figures)) === content.figuresSha256;
      add(ok ? "ok" : "bad", `${label}: the figures are the sealed ones`, "");
      if (ok) figures = JSON.parse(s.figures);
    }
    // Full evidence: recount every figure from its leaves, and recompute every root.
    if (s.leaves && commitments) {
      for (const [f, leaves] of Object.entries(s.leaves)) {
        const root = await rootOfLeaves(leaves);
        const count = figures && figures.activity ? figures.activity[f] : null;
        const rootOk = root === commitments[f];
        const countOk = count == null || count === leaves.length;
        add(rootOk && countOk ? "ok" : "bad", `${label}: ${FIGURE_LABELS[f] || f}: ${count != null ? count : leaves.length}`, rootOk && countOk ? `Recounted from ${leaves.length} committed record${leaves.length === 1 ? "" : "s"}; their Merkle root matches the sealed one.` : `${leaves.length} records, root ${mono(root || "none")}: they don't match the sealed figure and root.`);
      }
      // Anchors are public: each committed transaction must be an anchor on Attest's registries, mined that day.
      const txs = (s.leaves.anchors || []).map((x) => "0x" + x);
      if (txs.length) {
        try {
          const url = await node();
          let good = 0, bad = 0;
          for (const tx of txs) {
            try {
              const rc = isTx(tx) ? await rpc(url, "eth_getTransactionReceipt", [tx]) : null;
              if (!rc || rc.status !== "0x1" || !rc.to || !REGISTRIES.includes(rc.to.toLowerCase())) { bad++; continue; }
              const block = await rpc(url, "eth_getBlockByNumber", [rc.blockNumber, false]);
              if (new Date(parseInt(block.timestamp, 16) * 1000).toISOString().slice(0, 10) === day) good++; else bad++;
            } catch { bad++; }
          }
          add(bad ? "bad" : "ok", `${label}: each committed anchor is on chain, that day`, `${good} of ${txs.length} transactions read from the chain${bad ? `; ${bad} don't check out` : ""}.`);
        } catch (e) { add("warn", `${label}: the committed anchors couldn't be read here`, esc(e.message)); }
      }
    }
    // Inclusion: the party's own records, salted, with their paths to the sealed roots.
    for (const p of s.inclusion || []) {
      const leaf = await sha256hex(`attest.analytics.leaf.v1|${p.figure}|${p.record.id}|${p.salt}`);
      const root = leaf === p.leaf ? await foldPath(leaf, p.path) : null;
      const ok = commitments && root === commitments[p.figure];
      add(ok ? "ok" : "bad", ok ? `Counted in ${FIGURE_LABELS[p.figure] || p.figure}, ${day}` : `Not shown to be counted in ${FIGURE_LABELS[p.figure] || p.figure}, ${day}`, `Your ${esc(p.record.kind)} ${mono(p.record.id)}: its salted leaf reaches the sealed root in ${(p.path || []).length} step${(p.path || []).length === 1 ? "" : "s"}.`);
    }
  }
  if (!days.length) add("warn", "No sealed days in this file", "");
  render("analytics", "Attest Analytics", `Sealed ${esc(days.join(", "))}`);
}

// =================================================================================================== input
async function verify(ev, files) {
  results = [];
  downloads = [];
  const f = formatOf(ev);
  if (!f) {
    add("bad", "No Attest evidence found", "Drop an Attest signed copy (PDF), or an evidence file (attest-evidence-….json) from a receipt, certificate, Proof Card or proof page.");
    return render(null, "Nothing to check");
  }
  const known = VERIFIER.formats[f.kind];
  if (f.unknown || !known || f.v > Math.max(...known)) {
    add("warn", `This record uses a newer evidence format (${esc(ev.format)})`, `This verifier (version ${VERIFIER.version}) reads ${Object.entries(VERIFIER.formats).map(([k, v]) => `${k} v${v.join(", v")}`).join("; ")}. Get the latest verifier: <a href="${VERIFIER.repo}/releases" target="_blank" rel="noopener noreferrer">${VERIFIER.repo}</a>, or attest.datahubz.com/attest-verifier.html. The record's evidence is unchanged and stays verifiable.`);
    return render(null);
  }
  if (!L) {
    add("bad", "This copy of the verifier is incomplete", "Its libraries are missing. Download it again from the releases page.");
    return render(f.kind);
  }
  if (files && files.verifiers && files.verifiers.length) await checkAttachedVerifiers(files.verifiers);
  if (files && files.extraPdfs) add("bad", "This file carries more than one PDF", `${files.extraPdfs} PDFs are attached: a signed copy carries one, the document exactly as signed. Don't open the others.`);
  if (files && files.inPages && files.inPages.length) add("warn", `The signed pages carry ${files.inPages.length === 1 ? "a file" : `${files.inPages.length} files`} of their own`, "They were in the document as it was signed, so a PDF reader lists them next to Attest's attachments. They aren't Attest's: don't open them as its verifier or evidence.");
  try {
    if (f.kind === "agreement") return f.v >= 5 ? await verifyAgreementV5(ev, files, f.v) : await verifyAgreement(f.v === 1 ? fromV1(ev) : ev, files);
    if (f.kind === "receipt") return await verifyReceipt(ev, files);
    if (f.kind === "certificate") return await verifyCertificate(ev, files);
    if (f.kind === "card") return await verifyCard(ev);
    if (f.kind === "proof") return await verifyProof(ev);
    if (f.kind === "analytics") return await verifyAnalytics(ev);
  } catch (e) {
    add("bad", "The check stopped with an error", esc(e.message));
    render(f.kind);
  }
}

const refuse = (why) => { $("out").innerHTML = `<div class="verdict bad">${esc(why)}</div>`; };

/**
 * One record at a time: a signed PDF, or an evidence file with (optionally) the one file it is about. In a signed
 * copy, only the attachments of Attest's update after the signed pages are used.
 */
async function handle(list) {
  if (!window.crypto || !crypto.subtle) return refuse("This browser can't run the checks on this page. Open the file in a current browser, from your disk (file://) or over https.");
  const records = [], others = [];
  for (const f of list) {
    const buf = new Uint8Array(await f.arrayBuffer());
    if (/\.json$/i.test(f.name) || buf[0] === 123) {
      let j = null;
      try { j = JSON.parse(dec.decode(buf)); } catch {}
      if (j && typeof j.format === "string") { records.push({ ev: j, files: { pdf: null, outer: null } }); continue; }
    }
    const isPdf = latin1.decode(buf.slice(0, 5)) === "%PDF-";
    let att = isPdf ? await attachmentsOf(buf) : [];
    if (att.noInflate) return refuse("This browser can't open the PDF's attachments. Open this page in a current browser.");
    // Also every file a reader would list (found through file specifications, whatever their streams declare).
    if (isPdf && L && L.attachedFiles) {
      let listed = null;
      try { listed = await L.attachedFiles(buf); } catch { return refuse(`${f.name} can't be read as a PDF.`); }
      const have = new Set(await Promise.all(att.map((b) => sha256hex(b))));
      for (const b of listed) if (!have.has(await sha256hex(b))) { att.push(b); have.add(await sha256hex(b)); }
    }
    // Every attached file is one of three things: Attest's evidence, a PDF (the signed document), or anything else, which
    // must be a verifier build Attest published (whatever its first bytes: a reader may open any file).
    const evidence = [], pdfs = [], other = [];
    for (const b of att) {
      if (latin1.decode(b.slice(0, 5)) === "%PDF-") { pdfs.push(b); continue; }
      let j = null;
      try { j = JSON.parse(dec.decode(b)); } catch {}
      if (j && typeof j === "object" && typeof j.format === "string") evidence.push(j);
      else other.push(b);
    }
    if (!evidence.length) { others.push({ name: f.name, buf, isPdf }); continue; }
    // A signed copy: read it strictly, and use only the attachments of Attest's update after the signed pages (the
    // pages may carry files of their own, such as a document that was itself a signed copy).
    let chosen = null, failed = null;
    for (const e of evidence) {
      if (!e.visibleCopy || !Number.isInteger(e.visibleCopy.byteLength)) continue;
      const sealed = await sealedCopy(buf, e.visibleCopy.byteLength);
      if (sealed.ok) { chosen = sealed; break; }
      failed = failed || { ev: e, sealed };
    }
    let ev, files;
    if (chosen) {
      try { ev = JSON.parse(dec.decode(chosen.files["attest-evidence.json"])); } catch { return refuse(`${f.name}'s evidence isn't readable.`); }
      // Files the signed pages carry themselves (the document as it was signed may hold attachments): not Attest's.
      const attest = new Set(await Promise.all(Object.values(chosen.files).map((b) => sha256hex(b))));
      const inPages = [];
      for (const b of att) if (!attest.has(await sha256hex(b))) inPages.push(b);
      files = { pdf: chosen.files["original-document.pdf"] || null, outer: buf, structure: chosen, verifiers: chosen.files["attest-verifier.html"] ? [chosen.files["attest-verifier.html"]] : [], inPages };
    } else if (evidence.length === 1) {
      ev = evidence[0];
      // Not read strictly (a certificate or a copy from before October 10, 2026): every file other than the evidence
      // and one PDF is checked as a verifier build, and a second PDF is refused.
      files = { pdf: pdfs.length === 1 ? pdfs[0] : null, outer: buf, structure: failed ? failed.sealed : null, verifiers: other, extraPdfs: pdfs.length > 1 ? pdfs.length : 0 };
    } else return refuse(`${f.name} carries more than one evidence file, and none is attached the way Attest seals a signed copy: this file was changed.`);
    records.push({ ev, files });
  }
  if (records.length !== 1) return refuse(records.length ? "Drop one record at a time: one signed PDF, or one evidence file with the file it's about." : (list.some((f) => /\.pdf$/i.test(f.name)) ? "This PDF carries no Attest evidence. Drop an Attest signed copy, or the evidence file with the PDF it's about." : "No Attest evidence found. Drop an Attest signed copy (PDF), or an evidence file (attest-evidence-….json)."));
  if (others.length > 1) return refuse("Drop one record at a time, with at most one file it's about.");
  const { ev, files } = records[0];
  if (others.length) {
    if (files.outer) return refuse("A signed copy carries everything it needs: drop it on its own.");
    files.other = others[0].buf;
    files.otherName = others[0].name;
    if (others[0].isPdf) files.pdf = others[0].buf;
  }
  $("out").innerHTML = '<p class="small">Checking…</p>';
  await verify(ev, files);
}

$("ver").textContent = `Version ${VERIFIER.version} · reads ${Object.keys(VERIFIER.formats).join(", ")} evidence · source and releases: github.com/DataHubz/attest-verifier ·`;
$("rpc").placeholder = `${TRUST.rpcs[0]} (Horizen's public node)`;
// Opt-in only: nothing is fetched unless this button is clicked.
const newer = (a, b) => { const x = a.split(".").map(Number), y = b.split(".").map(Number); for (let i = 0; i < 3; i++) { if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) > (y[i] || 0); } return false; };
$("update").addEventListener("click", async () => {
  $("updateOut").textContent = "Checking…";
  for (const url of VERIFIER.latest) {
    try {
      const r = await fetch(url, { cache: "no-store" });
      if (!r.ok) continue;
      const l = await r.json();
      if (typeof l.version !== "string" || !/^\d+\.\d+\.\d+$/.test(l.version) || typeof l.url !== "string" || !/^https:\/\//.test(l.url)) continue;
      $("updateOut").innerHTML = newer(l.version, VERIFIER.version)
        ? `Version ${esc(l.version)} is available: <a href="${esc(l.url)}" target="_blank" rel="noopener noreferrer">download</a> (SHA-256 ${mono(String(l.sha256).slice(0, 16) + "…")}, anchored on Horizen: check it at attest.datahubz.com/verify).`
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
