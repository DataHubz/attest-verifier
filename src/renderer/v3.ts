// Attest signed copy renderer v3 ("attest.render.v3"). Shared, byte for byte, with the open verifier
// (DataHubz/attest-verifier, src/renderer/v3.ts): a verifier re-makes a signed copy's visible pages from what was
// signed and compares them with the copy. Frozen: a change to what it draws is a new renderer version.
//
// v3 is v2 with these changes. First, everything Attest draws for an entry stays inside the field the sender placed. A
// signature's stamp is laid out within its field (v2 grew a smaller one to 120 by 30 points about its center, over the
// document around it, and set its label and code along the field's top and bottom edges, where the document's own lines
// and labels often are); its parts keep clear of the edges, sit along the bottom of the field as a signature sits on
// its line, and shrink or leave out the stamp's own text in a small field. A text entry wraps or shrinks until it fits.
// Second, fields land on the page as readers show it (its CropBox, turned by /Rotate, at /UserUnit), and everything is
// drawn upright on it; v2 used the MediaBox from its origin. Third, the page's own content is drawn as a form XObject,
// guarded against pdf.js's shared stack of saved states, so it can't move, hide or stretch what follows it. Fourth,
// what people typed is drawn on one line with a glyph for every character (charset-v3.ts; Noto Sans when Helvetica and
// Instrument Sans have none). Fifth, the certificate pages say what a Share proof shows, the date the agreement was
// completed (v2 said "and when"), and that a PDF reader's attachments panel lists the attached files (v2 said any reader
// lists them). Agreements whose completion details name v2 keep v2, unchanged.
//
// Deterministic in every JavaScript engine: pdf-lib's resource names come from a counter instead of Math.sin, the
// seal and the guilloche use their own sine (basic arithmetic only), dates are formatted here, QR codes are drawn as
// vectors, and nothing reads the clock or the locale. It prints only what is signed or anchored: the original
// document, each signer's entries, the signed state and the completion details bound by Attest's agreement anchor.

import {
  PDFArray,
  PDFDict,
  PDFDocument,
  PDFName,
  PDFNumber,
  PDFObjectParser,
  PDFRawStream,
  PDFRef,
  PDFString,
  StandardFonts,
  beginText,
  clip,
  concatTransformationMatrix,
  decodePDFRawStream,
  endPath,
  endText,
  popGraphicsState,
  pushGraphicsState,
  rectangle,
  rgb,
  setFillingRgbColor,
  setFontAndSize,
  setTextMatrix,
  showText,
  type PDFFont,
  type PDFImage,
  type PDFPage,
} from "pdf-lib";
import fontkit from "@pdf-lib/fontkit";
import QRCode from "qrcode";
import { printableV3, unprintableV3 } from "./charset-v3";
import { UnreadablePdf, openOriginalV3 } from "./decrypt-v3";
import { FALLBACK_FONT, fieldDrawing, fieldEnv, numberToString as pdfjsNumber, type FieldEnv } from "./fields-v3";

export const RENDERER_V3 = "attest.render.v3";

export interface RenderInputV3 {
  /** The document exactly as signed (null for the certificate, which the parties' document never reaches). */
  original: Uint8Array | null;
  /** "full": with the certificate pages; "pages": the signed pages only; "certificate": the certificate pages alone. */
  variant: "full" | "pages" | "certificate";
  /** Where verification links point: https://attest.datahubz.com. */
  appUrl: string;
  agreement: { id: string; title: string; documentSha256: string; completionHash: string; anchorTxHash: string | null };
  /** The completion details, as bound by the agreement anchor v2 (parsed). */
  details: {
    verifyCode: string | null;
    completedAt: string;
    signers: string[];
    fields: [string, string, number, number, number, number, number, string][];
    /** SHA-256 of the audit trail's canonical JSON: the trail itself is the parties' own. */
    trailSha256: string;
  };
  /** The audit trail up to completion, [type, at, name or null], whose SHA-256 the details name (full copies only). */
  trail: [string, string, string | null][] | null;
  /** Each signer, by commitment: their name (from their statement) and when they signed (from the signed state). */
  signers: { commitment: string; name: string; signedAt: string }[];
  /** Every entry, by field id (from the signers' entries). */
  entries: Record<string, string>;
  /**
   * Instrument Sans and JetBrains Mono for the certificate pages, and Noto Sans (regular and bold, cut to charset-v3.ts)
   * for anything people typed that Helvetica or Instrument Sans has no glyph for.
   */
  fonts: { sans: Uint8Array; bold: Uint8Array; mono: Uint8Array; noto?: Uint8Array; notoBold?: Uint8Array };
}

// ---- Determinism -------------------------------------------------------------------------------------

const PI = 3.141592653589793;
/** sin with basic arithmetic only, so every engine computes the same bits (Math.sin may differ in the last bit). */
function dsin(x: number): number {
  const r = x - 2 * PI * Math.round(x / (2 * PI));
  const r2 = r * r;
  let term = r;
  let sum = r;
  for (let n = 1; n <= 10; n++) {
    term *= -r2 / (2 * n * (2 * n + 1));
    sum += term;
  }
  return sum;
}
const dcos = (x: number) => dsin(x + PI / 2);

/** pdf-lib names resources with a generator seeded on Math.sin: a counter replaces it. */
function deterministic(pdf: PDFDocument) {
  let n = 0;
  (pdf.context as unknown as { rng: { nextInt: () => number } }).rng = { nextInt: () => ((n = (n * 48271 + 1) % 2147483647) / 2147483647) };
}

const MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
const SHORT = MONTHS.map((m) => m.slice(0, 3));
const two = (n: number) => String(n).padStart(2, "0");
/** "October 12, 2026, 14:03:22 UTC", from an ISO time. */
function fmtUtc(iso: string): string {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})/.exec(iso);
  if (!m) return iso;
  return `${MONTHS[Number(m[2]) - 1]} ${Number(m[3])}, ${m[1]}, ${m[4]}:${m[5]}:${m[6]} UTC`;
}
/** "Oct 12, 2026". */
function fmtDay(iso: string): string {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(iso);
  return m ? `${SHORT[Number(m[2]) - 1]} ${Number(m[3])}, ${m[1]}` : iso;
}
const fmtCode = (code: string) => `ATT-${code.slice(0, 4)}-${code.slice(4, 8)}`;

// ---- Active content ----------------------------------------------------------------------------------

const ACTIVE_ACTIONS = new Set(["JavaScript", "Launch", "SubmitForm", "ImportData", "ResetForm", "Rendition", "Sound", "Movie", "GoToE", "GoToR", "Hide", "SetOCGState", "RichMediaExecute", "Trans", "GoTo3DView"]);
/** Annotations that play, run or carry content of their own. */
const ACTIVE_ANNOTATIONS = new Set(["FileAttachment", "RichMedia", "Screen", "Movie", "Sound", "3D"]);
/** Keys that run something, attach files or replace the document with another: never kept, wherever they are. */
const ACTIVE_KEYS = ["AA", "OpenAction", "AF", "EF", "Collection", "XFA", "JS", "Base"];

const nameOf = (v: unknown) => (v instanceof PDFName ? v.decodeText() : null);
/** A name, through any indirect reference (readers resolve them, so this must too). */
const nameIn = (pdf: PDFDocument, v: unknown) => nameOf(v instanceof PDFRef ? pdf.context.lookup(v) : v);
const dictIn = (o: unknown): PDFDict | null => (o instanceof PDFDict ? o : (o as { dict?: unknown } | null)?.dict instanceof PDFDict ? (o as { dict: PDFDict }).dict : null);

/** Every object reachable from the document's trailer, each once, depth first in a fixed order. */
function reachable(pdf: PDFDocument, visit: (o: PDFDict | PDFArray) => void): Set<PDFRef> {
  const ctx = pdf.context;
  const refs = new Set<PDFRef>();
  const seen = new Set<unknown>();
  const stack: unknown[] = [ctx.trailerInfo.Info, ctx.trailerInfo.Root].filter(Boolean);
  while (stack.length) {
    let o = stack.pop();
    if (o instanceof PDFRef) {
      if (refs.has(o)) continue;
      refs.add(o);
      o = ctx.lookup(o);
    }
    if (!o || seen.has(o)) continue;
    seen.add(o);
    const dict = dictIn(o);
    if (dict) {
      visit(dict);
      const values = dict.entries().map(([, v]) => v);
      for (let i = values.length - 1; i >= 0; i--) stack.push(values[i]);
    } else if (o instanceof PDFArray) {
      visit(o);
      const items = o.asArray();
      for (let i = items.length - 1; i >= 0; i--) stack.push(items[i]);
    }
  }
  return refs;
}

/** Viewer commands that only turn pages; any other (print, save, open a dialog) is removed. */
const PAGE_COMMANDS = new Set(["NextPage", "PrevPage", "FirstPage", "LastPage"]);
/** A link's address: kept only for the web and email (no javascript:, data:, file: or relative addresses). */
function safeUri(pdf: PDFDocument, v: unknown): boolean {
  const x = v instanceof PDFRef ? pdf.context.lookup(v) : v;
  const text = x && typeof (x as { decodeText?: unknown }).decodeText === "function" ? (x as { decodeText: () => string }).decodeText() : null;
  // Browsers ignore control characters and spaces inside a scheme ("java\tscript:"): so does this check.
  return text !== null && /^(https?|mailto):/i.test(text.replace(/[\u0000-\u0020\u007f-\u00a0]/g, ""));
}

/** The actions a link, an outline item or a chained action may keep: jumps within the document, article threads, web and email links, page turns. */
function allowedAction(pdf: PDFDocument, d: PDFDict): boolean {
  const s = nameIn(pdf, d.get(PDFName.of("S")));
  if (s === "GoTo" || s === "Thread") return true;
  if (s === "URI") return safeUri(pdf, d.get(PDFName.of("URI")));
  if (s === "Named") return PAGE_COMMANDS.has(nameIn(pdf, d.get(PDFName.of("N"))) ?? "");
  return false;
}
/** Keys whose value is an action (a dictionary with /S; for /Next, also an array of them). */
const ACTION_KEYS = ["A", "PA", "Next"];
/** Whether a value under an action key is an action this document may not keep. */
function disallowed(pdf: PDFDocument, v: unknown): boolean {
  const d = dictIn(v instanceof PDFRef ? pdf.context.lookup(v) : v);
  return Boolean(d && d.has(PDFName.of("S")) && !allowedAction(pdf, d));
}

/** Whether a value is a script or other active action, an annotation that plays or carries files, or a file. */
function harmful(pdf: PDFDocument, v: unknown): string | null {
  const d = dictIn(v instanceof PDFRef ? pdf.context.lookup(v) : v);
  if (!d) return null;
  const s = nameIn(pdf, d.get(PDFName.of("S")));
  if (s && ACTIVE_ACTIONS.has(s)) return `a ${s} action`;
  if (s === "URI" && !safeUri(pdf, d.get(PDFName.of("URI")))) return "a link that isn't to the web or email";
  if (s === "Named" && !PAGE_COMMANDS.has(nameIn(pdf, d.get(PDFName.of("N"))) ?? "")) return "a viewer command";
  const sub = nameIn(pdf, d.get(PDFName.of("Subtype")));
  if (sub && ACTIVE_ANNOTATIONS.has(sub)) return `a ${sub} annotation`;
  if (nameIn(pdf, d.get(PDFName.of("Type"))) === "EmbeddedFile") return "an embedded file";
  return null;
}
const NAMED = ["JavaScript", "EmbeddedFiles"];

/** What still runs or attaches something, anywhere in the document (empty for a signed copy's pages). */
export function activeContent(pdf: PDFDocument): string[] {
  const found: string[] = [];
  reachable(pdf, (o) => {
    if (o instanceof PDFArray) {
      for (const x of o.asArray()) { const h = harmful(pdf, x); if (h) found.push(h); }
      return;
    }
    for (const k of ACTIVE_KEYS) if (o.has(PDFName.of(k))) found.push(`/${k}`);
    for (const k of ACTION_KEYS) {
      const v = o.get(PDFName.of(k));
      const x = v instanceof PDFRef ? pdf.context.lookup(v) : v;
      if (x instanceof PDFArray ? x.asArray().some((y) => disallowed(pdf, y)) : disallowed(pdf, v)) found.push(`an action under /${k} that isn't a jump, a web or email link, or a page turn`);
    }
    for (const [k, v] of o.entries()) {
      const h = harmful(pdf, v);
      if (h) found.push(h);
      if (k.decodeText() === "Names") { const n = dictIn(v instanceof PDFRef ? pdf.context.lookup(v) : v); if (n && NAMED.some((x) => n.has(PDFName.of(x)))) found.push("named scripts or files"); }
    }
  });
  return found;
}

/**
 * The signed copy shows the document; it doesn't run it. Every object reachable from the document is visited: keys
 * that run something or attach files are removed, and so is every reference to a script or other active action, to
 * an annotation that plays media or carries a file, and to an embedded file, with every name read through any
 * indirect reference. A link, an outline item or a chained action (/Next) keeps only a jump within the document, an
 * article thread, a web or email address, or a page turn; any other action, of any type, is removed. Objects nothing refers to any more are
 * dropped when the pages are saved, and the result is checked for anything left. The original document itself is
 * attached to the signed copy as it is.
 */
function stripActiveContent(pdf: PDFDocument) {
  const ctx = pdf.context;
  reachable(pdf, (o) => {
    if (o instanceof PDFArray) {
      for (let i = o.size() - 1; i >= 0; i--) if (harmful(pdf, o.get(i))) o.remove(i);
      return;
    }
    for (const k of ACTIVE_KEYS) o.delete(PDFName.of(k));
    for (const k of ACTION_KEYS) {
      const v = o.get(PDFName.of(k));
      const x = v instanceof PDFRef ? ctx.lookup(v) : v;
      if (k === "Next" && x instanceof PDFArray) {
        for (let i = x.size() - 1; i >= 0; i--) if (disallowed(pdf, x.get(i))) x.remove(i);
      } else if (disallowed(pdf, v)) o.delete(PDFName.of(k));
    }
    for (const [k, v] of o.entries()) {
      if (harmful(pdf, v)) o.delete(k);
      else if (k.decodeText() === "Names") { const n = dictIn(v instanceof PDFRef ? ctx.lookup(v) : v); if (n) for (const x of NAMED) n.delete(PDFName.of(x)); }
    }
  });
}

/** Drop every object nothing reachable refers to (pdf-lib keeps them), so no stripped script lingers in the bytes. */
function dropUnreachable(pdf: PDFDocument) {
  const keep = reachable(pdf, () => {});
  for (const [ref] of pdf.context.enumerateIndirectObjects()) if (!keep.has(ref)) pdf.context.delete(ref);
}

// ---- What makes a document clean -----------------------------------------------------------------------------------
// The signer saw each page as pdf.js draws it for print. A clean document is one v3 can prove every reader displays the
// same way: its copy shows exactly what pdf.js showed the signer, with Attest's layer on top, in every reader tested
// (pdf.js, PDFium, MuPDF, Poppler, Ghostscript and Apple PDFKit). This check only classifies: every document is
// signed, and one that isn't clean gets the best protection v3 can give (below, "Protecting a document that isn't
// clean"). The check's reasons are recorded with the agreement as issue codes (src/lib/document-check.ts).
//
// - Content: every content stream any reader can run (the page's content, form XObjects, tiling pattern cells, Type 3
//   glyph procedures, soft-mask groups) decodes with the filters and predictors below, and follows one unambiguous
//   grammar: tokens separated by white space or delimiters, numbers and names well formed, no bytes outside text but
//   printable ASCII and white space, no operator inside an array or a dictionary, no braces. Only allowlisted operators,
//   each with its operands. Every stream is balanced on its own: saves and restores (q/Q), text objects (BT/ET), marked
//   content (BMC/BDC/EMC), compatibility sections (BX/EX); every path is painted (or used as a clip and painted) before
//   anything else, and none is left open. A text object holds only what ISO 32000-1 allows in one. Type 3 glyphs start
//   with d0 or d1, and only they use them. Text is filled, invisible or added to the clip, never stroked (readers
//   take a text stroke's width differently). A page's content split across streams is split between tokens, at white
//   space. Inline images only unfiltered, exactly their declared size, with no "EI" in their data.
// - Resources: everything content names is there; forms and patterns are checked the same way; no PostScript XObject,
//   no form that draws itself; graphics states without transfer functions, halftones, black generation, undercolour
//   removal or overprint (overprint mode is accepted: it changes nothing while overprint is off), and a smoothness
//   tolerance only in a document that draws no smooth shading (it changes nothing else).
// - No optional content at all (layers decided by /VE, /Intent, print or view state, and so on, differ between
//   readers): no /OCProperties, no /OC, no OCG or OCMD.
// - Fonts: carried by the PDF, but for the standard fonts (Helvetica, Times, Courier) in a standard encoding; composite
//   fonts with Identity-H or Identity-V. Images only in filters every reader decodes (the content filters, DCT, CCITT,
//   JBIG2 and JPEG 2000, which the signer's pdf.js decodes with its JavaScript decoders).
// - Annotations: only links without an appearance of their own (or with one that has no area, as macOS writes them),
//   which print nothing and are left out of the copy, and invisible digital signatures (signature fields whose widgets
//   have no area), left out with the form. Any other annotation, and any other form field, makes it not clean.
// - Pages: a stated MediaBox, a CropBox (if any) that overlaps it, /Rotate in quarter turns, no /UserUnit but 1.
//
// A clean page's content is drawn as one form XObject, so what Attest draws next starts from the page's own state.

const FILTERS: Record<string, string> = {
  FlateDecode: "FlateDecode", Fl: "FlateDecode", LZWDecode: "LZWDecode", LZW: "LZWDecode", ASCII85Decode: "ASCII85Decode",
  A85: "ASCII85Decode", ASCIIHexDecode: "ASCIIHexDecode", AHx: "ASCIIHexDecode", RunLengthDecode: "RunLengthDecode", RL: "RunLengthDecode",
};

/** A predictor's rows undone, as pdf.js's PredictorStream does: PNG (10 to 15) or TIFF (2), whole rows only. */
function unpredict(data: Uint8Array, p: { predictor: number; colors: number; bits: number; columns: number }): Uint8Array | string {
  const { predictor, colors, bits, columns } = p;
  if (predictor === 2) {
    if (bits !== 8) return "a TIFF predictor on other than 8-bit samples";
    const row = columns * colors;
    if (row <= 0 || data.length % row) return "a predicted stream with a partial row";
    const out = new Uint8Array(data.length);
    for (let r = 0; r < data.length; r += row) {
      for (let k = 0; k < row; k++) out[r + k] = (data[r + k] + (k >= colors ? out[r + k - colors] : 0)) & 0xff;
    }
    return out;
  }
  if (predictor < 10 || predictor > 15) return `predictor ${predictor}`;
  const pix = (colors * bits + 7) >> 3;
  const row = (columns * colors * bits + 7) >> 3;
  if (row <= 0 || data.length % (row + 1)) return "a predicted stream with a partial row";
  const rows = data.length / (row + 1);
  const out = new Uint8Array(rows * row);
  let prev = new Uint8Array(row);
  for (let r = 0; r < rows; r++) {
    const type = data[r * (row + 1)];
    const raw = data.subarray(r * (row + 1) + 1, (r + 1) * (row + 1));
    const cur = out.subarray(r * row, (r + 1) * row);
    for (let k = 0; k < row; k++) {
      const left = k >= pix ? cur[k - pix] : 0;
      const up = prev[k];
      const upLeft = k >= pix ? prev[k - pix] : 0;
      let v: number;
      if (type === 0) v = raw[k];
      else if (type === 1) v = raw[k] + left;
      else if (type === 2) v = raw[k] + up;
      else if (type === 3) v = raw[k] + ((left + up) >> 1);
      else if (type === 4) {
        const pa = Math.abs(up - upLeft), pb = Math.abs(left - upLeft), pc = Math.abs(left + up - 2 * upLeft);
        v = raw[k] + (pa <= pb && pa <= pc ? left : pb <= pc ? up : upLeft);
      } else return `PNG predictor row type ${type}`;
      cur[k] = v & 0xff;
    }
    prev = cur;
  }
  return out;
}

/** A content stream decoded completely with the filters and predictors above, or why not. */
function contentOf(pdf: PDFDocument, v: unknown): Uint8Array | string {
  const ctx = pdf.context;
  const lookup = (x: unknown) => (x instanceof PDFRef ? ctx.lookup(x) : x);
  const s = lookup(v);
  if (!(s instanceof PDFRawStream)) return "content that isn't a stream";
  const filter = lookup(s.dict.get(PDFName.of("Filter")));
  const names = (filter instanceof PDFArray ? filter.asArray().map(lookup) : filter === undefined ? [] : [filter]).map((f) => (f instanceof PDFName ? f.decodeText() : null));
  const parmsRaw = lookup(s.dict.get(PDFName.of("DecodeParms")));
  const parms = (parmsRaw instanceof PDFArray ? parmsRaw.asArray() : [parmsRaw]).map(lookup);
  const full: string[] = [];
  let predict: { predictor: number; colors: number; bits: number; columns: number } | null = null;
  const plain: (PDFDict | null)[] = [];
  for (const [k, name] of names.entries()) {
    const f = name ? FILTERS[name] : undefined;
    if (!f) return `content encoded with ${name ?? "an unnamed filter"}`;
    full.push(f);
    const d = parms[filter instanceof PDFArray ? k : 0];
    const num = (key: string, dflt: number) => {
      const x = d instanceof PDFDict ? lookup(d.get(PDFName.of(key))) : undefined;
      return x instanceof PDFNumber ? x.asNumber() : dflt;
    };
    const predictor = num("Predictor", 1);
    if (predictor > 1) {
      if ((f !== "FlateDecode" && f !== "LZWDecode") || k !== names.length - 1) return "a predictor pdf.js wouldn't apply";
      predict = { predictor, colors: num("Colors", 1), bits: num("BitsPerComponent", 8), columns: num("Columns", 1) };
    }
    plain.push(f === "LZWDecode" && d instanceof PDFDict ? ctx.obj({ EarlyChange: num("EarlyChange", 1) }) : null);
  }
  let data: Uint8Array;
  try {
    const dict = ctx.obj({ Filter: full, DecodeParms: plain.map((p) => p ?? null) });
    data = full.length ? (decodePDFRawStream(PDFRawStream.of(dict, s.contents)) as unknown as { decode: () => Uint8Array }).decode() : s.contents;
  } catch {
    return "content that doesn't decode";
  }
  if (predict) {
    const out = unpredict(data, predict);
    if (typeof out === "string") return out;
    data = out;
  }
  return data;
}

// The operators v3 accepts, each with its operands: n a number, N a name, s a string, a an array, D a dictionary or a
// name, + one to four numbers, * numbers then an optional name (at least one operand).
const OPERATORS: Record<string, string> = {
  w: "n", J: "n", j: "n", M: "n", d: "an", ri: "N", i: "n", gs: "N",
  q: "", Q: "", cm: "nnnnnn",
  m: "nn", l: "nn", c: "nnnnnn", v: "nnnn", y: "nnnn", h: "", re: "nnnn",
  S: "", s: "", f: "", F: "", "f*": "", B: "", "B*": "", b: "", "b*": "", n: "", W: "", "W*": "",
  BT: "", ET: "", Tc: "n", Tw: "n", Tz: "n", TL: "n", Tf: "Nn", Tr: "n", Ts: "n",
  Td: "nn", TD: "nn", Tm: "nnnnnn", "T*": "", Tj: "s", TJ: "a", "'": "s", '"': "nns",
  d0: "nn", d1: "nnnnnn",
  CS: "N", cs: "N", SC: "+", SCN: "*", sc: "+", scn: "*", G: "n", g: "n", RG: "nnn", rg: "nnn", K: "nnnn", k: "nnnn",
  sh: "N", Do: "N", MP: "N", DP: "ND", BMC: "N", BDC: "ND", EMC: "", BX: "", EX: "", BI: "",
};
const PATH_START = new Set(["m", "re"]);
const PATH_MORE = new Set(["l", "c", "v", "y", "h"]);
const PAINT = new Set(["S", "s", "f", "F", "f*", "B", "B*", "b", "b*", "n"]);
const COLOUR = new Set(["CS", "cs", "SC", "SCN", "sc", "scn", "G", "g", "RG", "rg", "K", "k"]);
const TEXT_STATE = new Set(["Tc", "Tw", "Tz", "TL", "Tf", "Tr", "Ts"]);
const TEXT_SHOW = new Set(["Tj", "TJ", "'", '"']);
const TEXT_MOVE = new Set(["Td", "TD", "Tm", "T*"]);
// What ISO 32000-1 (9.4, table 51) allows inside a text object.
const IN_TEXT = new Set(["w", "J", "j", "M", "d", "ri", "i", "gs", ...COLOUR, ...TEXT_STATE, ...TEXT_SHOW, ...TEXT_MOVE, "MP", "DP", "BMC", "BDC", "EMC", "ET"]);
const DEVICE_SPACES = new Set(["DeviceGray", "DeviceRGB", "DeviceCMYK", "Pattern"]);
const WHITE = (c: number) => c === 9 || c === 10 || c === 12 || c === 13 || c === 32;
const DELIM = (c: number) => c === 40 || c === 41 || c === 60 || c === 62 || c === 91 || c === 93 || c === 123 || c === 125 || c === 47 || c === 37;
const REGULAR = (c: number) => c > 32 && c < 127 && !DELIM(c);
const NUMBER = /^[+-]?(\d+\.?\d*|\.\d+)$/;
const isHex = (c: number) => (c >= 48 && c <= 57) || (c >= 65 && c <= 70) || (c >= 97 && c <= 102);
/** An operator or token as a reason may show it: printable ASCII, at most 12 characters. */
const shown = (t: string) => t.replace(/[^\x21-\x7e]/g, "?").slice(0, 12);

/** The resources a content stream names, by kind (each name once, in order). */
export interface ContentUses {
  XObject: string[];
  ExtGState: string[];
  ColorSpace: string[];
  Pattern: string[];
  Shading: string[];
  Font: string[];
  Properties: string[];
}

type Operand = { k: "n"; v?: number } | { k: "N"; v: string } | { k: "s" } | { k: "a"; items: Operand[] } | { k: "D" } | { k: "b" };

/**
 * Checks one content stream against v3's grammar, operators and balance: the first reason it isn't accepted (null when
 * it is), and the resources it names. `glyph`: a Type 3 glyph procedure. `parts`: where the page's content streams were
 * joined (each part must end between tokens, at white space).
 */
export function checkContent(b: Uint8Array, opts: { glyph?: boolean; parts?: number[] } = {}): { problem: string | null; uses: ContentUses } {
  const uses: ContentUses = { XObject: [], ExtGState: [], ColorSpace: [], Pattern: [], Shading: [], Font: [], Properties: [] };
  const use = (kind: keyof ContentUses, name: string) => { if (!uses[kind].includes(name)) uses[kind].push(name); };
  // Optional content is recorded and reading goes on, so what else is wrong in the stream is found too.
  let layers = false;
  const out = (problem: string) => ({ problem, uses });
  const parts = new Set(opts.parts ?? []);
  // Each join between a page's content streams falls between tokens, with white space on one side of it.
  const between = (start: number, end: number) => {
    for (const p of parts) if (p > start && p < end) return false;
    return true;
  };
  for (const p of parts) if (p > 0 && p < b.length && !WHITE(b[p - 1]) && !WHITE(b[p])) return out("content split across streams where readers join them differently");
  const containers: { k: "[" | "<<"; items: Operand[] }[] = [];
  let operands: Operand[] = [];
  const push = (o: Operand) => (containers.length ? containers[containers.length - 1].items.push(o) : operands.push(o));
  let saves = 0;
  let text = false;
  let marked = 0;
  let markedAtText = 0;
  let compat = 0;
  let path = false;
  let clip = false;
  let first = true;
  let uncoloured = false;
  let i = 0;
  while (i < b.length) {
    const c = b[i];
    if (WHITE(c)) { i++; continue; }
    if (c === 37) { while (i < b.length && b[i] !== 10 && b[i] !== 13) i++; continue; }
    const start = i;
    if (c === 40) {
      let depth = 1;
      i++;
      while (i < b.length && depth > 0) {
        if (b[i] === 92) i += 2;
        else { if (b[i] === 40) depth++; else if (b[i] === 41) depth--; i++; }
      }
      if (depth > 0) return out("a string that isn't closed");
      if (!between(start, i)) return out("content split across streams where readers join them differently");
      push({ k: "s" });
      continue;
    }
    if (c === 60) {
      if (b[i + 1] === 60) { containers.push({ k: "<<", items: [] }); i += 2; continue; }
      i++;
      while (i < b.length && b[i] !== 62) {
        if (!isHex(b[i]) && !WHITE(b[i])) return out("a hex string with other characters");
        i++;
      }
      if (i >= b.length) return out("a hex string that isn't closed");
      i++;
      if (!between(start, i)) return out("content split across streams where readers join them differently");
      push({ k: "s" });
      continue;
    }
    if (c === 62) {
      if (b[i + 1] !== 62) return out("a stray delimiter (>)");
      const top = containers.pop();
      if (!top || top.k !== "<<") return out("a stray delimiter (>>)");
      if (top.items.length % 2 || top.items.some((x, k) => k % 2 === 0 && x.k !== "N")) return out("a malformed dictionary");
      i += 2;
      push({ k: "D" });
      continue;
    }
    if (c === 91) { containers.push({ k: "[", items: [] }); i++; continue; }
    if (c === 93) {
      const top = containers.pop();
      if (!top || top.k !== "[") return out("a stray delimiter (])");
      i++;
      push({ k: "a", items: top.items });
      continue;
    }
    if (c === 123 || c === 125) return out("braces in content");
    if (c === 41) return out("a stray delimiter ())");
    if (c === 47) {
      i++;
      let name = "";
      while (i < b.length && REGULAR(b[i])) {
        if (b[i] === 35) {
          if (!(isHex(b[i + 1] ?? 0) && isHex(b[i + 2] ?? 0))) return out("a malformed name");
          name += String.fromCharCode(parseInt(String.fromCharCode(b[i + 1], b[i + 2]), 16));
          i += 3;
        } else name += String.fromCharCode(b[i++]);
      }
      if (!name) return out("a malformed name");
      if (i < b.length && !WHITE(b[i]) && !DELIM(b[i])) return out("bytes outside text");
      if (!between(start, i)) return out("content split across streams where readers join them differently");
      push({ k: "N", v: name });
      continue;
    }
    if (!REGULAR(c)) return out("bytes outside text");
    while (i < b.length && REGULAR(b[i])) i++;
    if (i < b.length && !WHITE(b[i]) && !DELIM(b[i])) return out("bytes outside text");
    if (!between(start, i)) return out("content split across streams where readers join them differently");
    const word = String.fromCharCode(...b.subarray(start, i));
    if (NUMBER.test(word)) { push({ k: "n", v: Number(word) }); continue; }
    if (/^[+\-.0-9]/.test(word)) return out("a malformed number");
    if (word === "true" || word === "false") { push({ k: "b" }); continue; }
    if (word === "null") { push({ k: "b" }); continue; }
    // An operator.
    if (containers.length) return out("an operator inside an array or dictionary");
    const sig = OPERATORS[word];
    if (sig === undefined) return out(`an operator Attest doesn't accept (${shown(word)})`);
    const fits =
      sig === "+" ? operands.length >= 1 && operands.length <= 4 && operands.every((o) => o.k === "n")
      : sig === "*" ? operands.length >= 1 && operands.length <= 33 && operands.slice(0, -1).every((o) => o.k === "n") && (operands[operands.length - 1].k === "n" || operands[operands.length - 1].k === "N")
      : operands.length === sig.length && [...sig].every((t, k) => (t === "D" ? operands[k].k === "D" || operands[k].k === "N" : operands[k].k === t));
    if (!fits) return out(`an operator with the wrong operands (${word})`);
    if (word === "TJ" && (operands[0] as { items: Operand[] }).items.some((o) => o.k !== "n" && o.k !== "s")) return out("an operator with the wrong operands (TJ)");
    if (word === "d" && (operands[0] as { items: Operand[] }).items.some((o) => o.k !== "n")) return out("an operator with the wrong operands (d)");
    // Text filled, invisible or added to the clip; never stroked: readers take a text stroke's width differently.
    if (word === "Tr") {
      const mode = (operands[0] as { v?: number }).v ?? NaN;
      if (!Number.isInteger(mode) || mode < 0 || mode > 7) return out("an operator with the wrong operands (Tr)");
      if (mode === 1 || mode === 2 || mode === 5 || mode === 6) return out("text drawn with a stroke (Tr)");
    }
    // Type 3 glyphs: d0 or d1 first, and only there; an uncoloured glyph (d1) sets no colour.
    if (word === "d0" || word === "d1") {
      if (!opts.glyph || !first) return out("a glyph operator outside the start of a Type 3 glyph");
      uncoloured = word === "d1";
    } else if (opts.glyph && first) return out("a Type 3 glyph that doesn't start with d0 or d1");
    if (uncoloured && COLOUR.has(word)) return out("a colour inside an uncoloured Type 3 glyph");
    first = false;
    // Paths: started by m or re, painted (or clipped, then painted) before anything else.
    if (path) {
      if (PATH_START.has(word) || PATH_MORE.has(word)) {
        if (clip) return out("a path that isn't painted");
      } else if (word === "W" || word === "W*") clip = true;
      else if (PAINT.has(word)) { path = false; clip = false; }
      else return out("a path that isn't painted");
    } else if (PATH_START.has(word)) path = true;
    else if (PATH_MORE.has(word) || PAINT.has(word) || word === "W" || word === "W*") return out("a path that doesn't start with m or re");
    // Text objects, and what they hold.
    if (text && word === "BT") return out("text objects that don't balance (BT/ET)");
    if (text && !IN_TEXT.has(word)) return out(`an operator a text object can't hold (${word})`);
    if (!text && (TEXT_SHOW.has(word) || TEXT_MOVE.has(word))) return out(`text outside a text object (${word})`);
    if (word === "BT") {
      if (text) return out("text objects that don't balance (BT/ET)");
      text = true;
      markedAtText = marked;
    } else if (word === "ET") {
      if (!text) return out("text objects that don't balance (BT/ET)");
      if (marked !== markedAtText) return out("marked content that doesn't balance (BMC/BDC/EMC)");
      text = false;
    } else if (word === "q") saves++;
    else if (word === "Q") {
      if (--saves < 0) return out("saves and restores that don't balance (q/Q)");
    } else if (word === "BMC" || word === "BDC") {
      if ((operands[0] as { v: string }).v === "OC") layers = true;
      if (word === "BDC" && operands[1].k === "N") use("Properties", (operands[1] as { v: string }).v);
      marked++;
    } else if (word === "EMC") {
      if (marked === 0 || (text && marked === markedAtText)) return out("marked content that doesn't balance (BMC/BDC/EMC)");
      marked--;
    } else if (word === "BX") compat++;
    else if (word === "EX") {
      if (--compat < 0) return out("compatibility sections that don't balance (BX/EX)");
    } else if (word === "DP" && operands[1].k === "N") use("Properties", (operands[1] as { v: string }).v);
    else if (word === "Do") use("XObject", (operands[0] as { v: string }).v);
    else if (word === "gs") use("ExtGState", (operands[0] as { v: string }).v);
    else if (word === "sh") use("Shading", (operands[0] as { v: string }).v);
    else if (word === "Tf") use("Font", (operands[0] as { v: string }).v);
    else if (word === "CS" || word === "cs") {
      const v = (operands[0] as { v: string }).v;
      if (!DEVICE_SPACES.has(v)) use("ColorSpace", v);
    } else if ((word === "SCN" || word === "scn") && operands[operands.length - 1].k === "N") use("Pattern", (operands[operands.length - 1] as { v: string }).v);
    else if (word === "BI") {
      const end = inlineImageEnd(b, i);
      if (typeof end === "string") return out(end);
      if (!between(start, end)) return out("content split across streams where readers join them differently");
      i = end;
    }
    operands = [];
  }
  if (containers.length) return out("an array or dictionary that isn't closed");
  if (operands.length) return out("operands without an operator");
  if (saves !== 0) return out("saves and restores that don't balance (q/Q)");
  if (text) return out("text objects that don't balance (BT/ET)");
  if (marked !== 0) return out("marked content that doesn't balance (BMC/BDC/EMC)");
  if (compat !== 0) return out("compatibility sections that don't balance (BX/EX)");
  if (path) return out("a path that isn't painted");
  if (opts.glyph && first) return out("a Type 3 glyph that doesn't start with d0 or d1");
  return { problem: layers ? "layers (optional content)" : null, uses };
}

const INLINE_KEYS: Record<string, string> = { W: "W", Width: "W", H: "H", Height: "H", BPC: "BPC", BitsPerComponent: "BPC", CS: "CS", ColorSpace: "CS", IM: "IM", ImageMask: "IM", D: "D", Decode: "D", I: "I", Interpolate: "I" };
const INLINE_SPACES: Record<string, number> = { G: 1, DeviceGray: 1, RGB: 3, DeviceRGB: 3, CMYK: 4, DeviceCMYK: 4 };

/**
 * An inline image after "BI" at `i`: its dictionary (only W, H, BPC, CS, IM, D and I, no filter), "ID" and one white
 * space byte, data of exactly its declared size (rows padded to whole bytes) with no "EI" in it, white space, then "EI"
 * ending at white space, a delimiter or the end. Returns where it ends, or why it isn't accepted.
 */
function inlineImageEnd(b: Uint8Array, i: number): number | string {
  const dict: Record<string, string | number | boolean> = {};
  for (;;) {
    while (i < b.length && WHITE(b[i])) i++;
    if (i >= b.length) return "an inline image without its end";
    if (b[i] === 73 && b[i + 1] === 68 && (i + 2 >= b.length || !REGULAR(b[i + 2]))) { i += 2; break; }
    if (b[i] !== 47) return "an inline image Attest doesn't accept";
    let j = i + 1;
    while (j < b.length && REGULAR(b[j])) j++;
    const key = String.fromCharCode(...b.subarray(i + 1, j));
    if (key === "F" || key === "Filter") return "an inline image with a filter";
    const k = INLINE_KEYS[key];
    if (!k) return "an inline image Attest doesn't accept";
    i = j;
    while (i < b.length && WHITE(b[i])) i++;
    if (b[i] === 91) {
      // Decode: an array of numbers.
      let j2 = i + 1;
      while (j2 < b.length && b[j2] !== 93) { if (!WHITE(b[j2]) && !REGULAR(b[j2])) return "an inline image Attest doesn't accept"; j2++; }
      const items = String.fromCharCode(...b.subarray(i + 1, j2)).trim().split(/\s+/).filter(Boolean);
      if (k !== "D" || !items.every((x) => NUMBER.test(x))) return "an inline image Attest doesn't accept";
      dict[k] = items.length;
      i = j2 + 1;
      continue;
    }
    let j3 = i;
    if (b[i] === 47) j3++;
    while (j3 < b.length && REGULAR(b[j3])) j3++;
    const v = String.fromCharCode(...b.subarray(i, j3));
    if (v.startsWith("/")) dict[k] = v.slice(1);
    else if (NUMBER.test(v)) dict[k] = Number(v);
    else if (v === "true" || v === "false") dict[k] = v === "true";
    else return "an inline image Attest doesn't accept";
    i = j3;
  }
  const mask = dict.IM === true;
  const W = dict.W, H = dict.H;
  if (typeof W !== "number" || typeof H !== "number" || !Number.isInteger(W) || !Number.isInteger(H) || W < 1 || H < 1 || W * H > 1e7) return "an inline image Attest doesn't accept";
  const bpc = mask ? (dict.BPC === undefined ? 1 : dict.BPC) : dict.BPC;
  const comps = mask ? 1 : typeof dict.CS === "string" ? INLINE_SPACES[dict.CS] : undefined;
  if (!comps || (mask && (bpc !== 1 || dict.CS !== undefined)) || ![1, 2, 4, 8, 16].includes(bpc as number)) return "an inline image Attest doesn't accept";
  if (!WHITE(b[i] ?? 0)) return "an inline image Attest doesn't accept";
  const start = i + 1;
  const length = H * Math.ceil((W * comps * (bpc as number)) / 8);
  const end = start + length;
  if (end + 3 > b.length) return "an inline image whose data isn't its declared size";
  for (let k = start; k + 1 < end; k++) if (b[k] === 69 && b[k + 1] === 73) return "an inline image whose data contains EI";
  let e = end;
  if (!WHITE(b[e])) return "an inline image whose data isn't its declared size";
  while (e < b.length && WHITE(b[e])) e++;
  if (b[e] !== 69 || b[e + 1] !== 73) return "an inline image whose data isn't its declared size";
  if (e + 2 < b.length && !WHITE(b[e + 2]) && !DELIM(b[e + 2])) return "an inline image without its end";
  return e + 2;
}

const lookupIn = (pdf: PDFDocument, v: unknown) => (v instanceof PDFRef ? pdf.context.lookup(v) : v);
const numberOf = (pdf: PDFDocument, v: unknown) => { const x = lookupIn(pdf, v); return x instanceof PDFNumber ? x.asNumber() : null; };
const ALLOWED_GRAPHICS_STATE = new Set(["Type", "LW", "LC", "LJ", "ML", "D", "RI", "FL", "SA", "SM", "BM", "SMask", "CA", "ca", "AIS", "TK", "Font", "OP", "op", "OPM"]);

/**
 * Everything in the document v3 checks before making a copy: why it isn't accepted (empty when it is). Run on the
 * document as it arrived, before anything is taken out of it.
 */
/** The standard fonts every reader replaces, when a PDF doesn't carry them, with a design of the same metrics. */
const STANDARD_FONTS = new Set(["Helvetica", "Helvetica-Bold", "Helvetica-Oblique", "Helvetica-BoldOblique", "Times-Roman", "Times-Bold", "Times-Italic", "Times-BoldItalic", "Courier", "Courier-Bold", "Courier-Oblique", "Courier-BoldOblique"]);
const STANDARD_ENCODINGS = new Set(["WinAnsiEncoding", "StandardEncoding", "MacRomanEncoding"]);
const embeddedIn = (pdf: PDFDocument, desc: unknown) => {
  const d = lookupIn(pdf, desc);
  return d instanceof PDFDict && ["FontFile", "FontFile2", "FontFile3"].some((k) => lookupIn(pdf, d.get(PDFName.of(k))) instanceof PDFRawStream);
};

/**
 * Why a font (other than Type 3, whose glyphs are content) could look different from one reader to another: one the PDF
 * doesn't carry, but for the standard fonts in a standard encoding (every reader substitutes a design of the same
 * metrics, and maps their codes the same way), or a composite font without its glyphs or with a character map other
 * than Identity-H or Identity-V (a predefined map is each reader's own copy).
 */
function fontProblem(pdf: PDFDocument, font: PDFDict): string | null {
  const sub = nameIn(pdf, font.get(PDFName.of("Subtype")));
  const base = nameIn(pdf, font.get(PDFName.of("BaseFont"))) ?? "unnamed";
  if (sub === "Type0") {
    const enc = nameIn(pdf, font.get(PDFName.of("Encoding")));
    if (enc !== "Identity-H" && enc !== "Identity-V") return `a font Attest doesn't accept (${shown(base)})`;
    const kids = lookupIn(pdf, font.get(PDFName.of("DescendantFonts")));
    const cid = kids instanceof PDFArray && kids.size() === 1 ? lookupIn(pdf, kids.get(0)) : undefined;
    if (!(cid instanceof PDFDict)) return `a font Attest doesn't accept (${shown(base)})`;
    return embeddedIn(pdf, cid.get(PDFName.of("FontDescriptor"))) ? null : `a font that isn't embedded (${shown(base)})`;
  }
  if (sub !== "Type1" && sub !== "MMType1" && sub !== "TrueType") return `a font Attest doesn't accept (${shown(base)})`;
  if (embeddedIn(pdf, font.get(PDFName.of("FontDescriptor")))) return null;
  const enc = lookupIn(pdf, font.get(PDFName.of("Encoding")));
  const standardEncoding =
    enc === undefined ||
    (enc instanceof PDFName && STANDARD_ENCODINGS.has(enc.decodeText())) ||
    (enc instanceof PDFDict && !enc.has(PDFName.of("Differences")) && (!enc.has(PDFName.of("BaseEncoding")) || STANDARD_ENCODINGS.has(nameIn(pdf, enc.get(PDFName.of("BaseEncoding"))) ?? "")));
  return STANDARD_FONTS.has(base) && standardEncoding ? null : `a font that isn't embedded (${shown(base)})`;
}

/** Filters every reader, and the signer's pdf.js as Attest opens it (its JavaScript decoders), decodes the same way. */
const IMAGE_FILTERS = new Set([...Object.keys(FILTERS), "DCTDecode", "DCT", "CCITTFaxDecode", "CCF", "JBIG2Decode", "JPXDecode"]);

/** Why an image (or its soft mask or stencil mask) could decode differently from one reader to another. */
function imageProblem(pdf: PDFDocument, image: PDFRawStream, depth = 0): string | null {
  const f = lookupIn(pdf, image.dict.get(PDFName.of("Filter")));
  const filters = f === undefined ? [] : f instanceof PDFArray ? f.asArray().map((x) => nameIn(pdf, x)) : [nameIn(pdf, f)];
  const bad = filters.find((x) => x === null || !IMAGE_FILTERS.has(x));
  if (bad !== undefined) return `an image Attest doesn't accept (${shown(bad ?? "filter")})`;
  if (depth > 0) return null;
  for (const k of ["SMask", "Mask"]) {
    const m = lookupIn(pdf, image.dict.get(PDFName.of(k)));
    if (m instanceof PDFRawStream) {
      const why = imageProblem(pdf, m, depth + 1);
      if (why) return why;
    }
  }
  return null;
}

/**
 * An appearance dictionary every one of whose streams (normal, rollover and down, each directly or by state) is a form
 * whose bounding box has no area: nothing can be drawn in it, in any reader. macOS gives links such appearances.
 */
function drawsNothing(pdf: PDFDocument, ap: unknown): boolean {
  const d = lookupIn(pdf, ap);
  if (!(d instanceof PDFDict)) return false;
  const empty = (x: unknown): boolean => {
    const v = lookupIn(pdf, x);
    if (v instanceof PDFDict) return v.entries().every(([, y]) => { const z = lookupIn(pdf, y); return z instanceof PDFRawStream && empty(z); });
    if (!(v instanceof PDFRawStream)) return false;
    const box = lookupIn(pdf, v.dict.get(PDFName.of("BBox")));
    if (!(box instanceof PDFArray) || box.size() !== 4) return false;
    const n = box.asArray().map((b) => numberOf(pdf, b));
    if (n.some((b) => b === null || !Number.isFinite(b))) return false;
    return n[0] === n[2] || n[1] === n[3];
  };
  return d.entries().every(([, v]) => empty(v));
}

/**
 * A widget of a signature field (its /FT, inherited, is /Sig) whose rectangle has no area: an invisible digital
 * signature, which signing services add to the PDFs they deliver. Nothing can be drawn in a rectangle without area, so
 * no reader shows anything for it.
 */
function invisibleSignature(pdf: PDFDocument, widget: PDFDict): boolean {
  let ft: string | null = null;
  for (let d: unknown = widget, seen = 0; d instanceof PDFDict && seen < 32 && ft === null; d = lookupIn(pdf, d.get(PDFName.of("Parent"))), seen++) ft = nameIn(pdf, d.get(PDFName.of("FT")));
  if (ft !== "Sig") return false;
  const sub = nameIn(pdf, widget.get(PDFName.of("Subtype")));
  if (sub !== null && sub !== "Widget") return false;
  const rect = lookupIn(pdf, widget.get(PDFName.of("Rect")));
  if (!(rect instanceof PDFArray) || rect.size() !== 4) return false;
  const n = rect.asArray().map((v) => numberOf(pdf, v));
  if (n.some((x) => x === null || !Number.isFinite(x))) return false;
  const [x0, y0, x1, y1] = n as number[];
  return x0 === x1 || y0 === y1;
}

function documentProblems(pdf: PDFDocument): string[] {
  const ctx = pdf.context;
  const problems: string[] = [];
  const add = (p: string) => { if (!problems.includes(p)) problems.push(p); };
  // A smoothness tolerance (SM) changes only how smooth shadings are approximated: accepted unless one is drawn.
  let smoothness = false;
  let shading = false;
  // No optional content, anywhere.
  if (pdf.catalog.has(PDFName.of("OCProperties"))) add("layers (optional content)");
  reachable(pdf, (o) => {
    if (!(o instanceof PDFDict)) return;
    const type = nameIn(pdf, o.get(PDFName.of("Type")));
    if (type === "OCG" || type === "OCMD" || o.has(PDFName.of("OC"))) add("layers (optional content)");
  });
  // No form fields, but invisible digital signatures (signature fields whose widgets have no area: they show nothing in
  // any reader, and are left out of the copy with the form).
  const acro = lookupIn(pdf, pdf.catalog.get(PDFName.of("AcroForm")));
  if (acro instanceof PDFDict) {
    const fields = lookupIn(pdf, acro.get(PDFName.of("Fields")));
    if (acro.has(PDFName.of("XFA"))) add("form fields");
    const visit = (f: unknown, depth: number): boolean => {
      const d = lookupIn(pdf, f);
      if (!(d instanceof PDFDict) || depth > 32) return false;
      const kids = lookupIn(pdf, d.get(PDFName.of("Kids")));
      if (kids instanceof PDFArray && kids.size() > 0) return kids.asArray().every((k) => visit(k, depth + 1));
      return invisibleSignature(pdf, d);
    };
    if (fields !== undefined && !(fields instanceof PDFArray)) add("form fields");
    else if (fields instanceof PDFArray && !fields.asArray().every((f) => visit(f, 0))) add("form fields");
  }
  let pages: PDFPage[];
  try {
    pages = pdf.getPages();
  } catch {
    return [...problems, "a PDF without pages"];
  }
  if (!pages.length) add("a PDF without pages");
  const checked = new Set<unknown>();
  // A content stream any reader can run, with the resources it draws from: decoded, checked, and its resources too.
  const checkStream = (s: unknown, res: unknown, opts: { glyph?: boolean } = {}, drawing: unknown[] = []) => {
    const data = contentOf(pdf, s);
    if (typeof data === "string") return add(data);
    const r = checkContent(data, opts);
    if (r.problem) add(r.problem);
    checkResources(res, r.uses, [...drawing, s]);
  };
  const checkResources = (resRaw: unknown, uses: ContentUses, drawing: unknown[]) => {
    const res = lookupIn(pdf, resRaw);
    const dict = (kind: string) => { const d = res instanceof PDFDict ? lookupIn(pdf, res.get(PDFName.of(kind))) : undefined; return d instanceof PDFDict ? d : null; };
    const get = (kind: keyof ContentUses, name: string) => {
      const v = dict(kind)?.get(PDFName.of(name));
      if (v === undefined) add(`a resource that isn't there (${kind})`);
      return v;
    };
    for (const name of uses.XObject) {
      const ref = get("XObject", name);
      const x = lookupIn(pdf, ref);
      if (ref === undefined) continue;
      if (!(x instanceof PDFRawStream)) { add("an XObject Attest doesn't accept"); continue; }
      const sub = nameIn(pdf, x.dict.get(PDFName.of("Subtype")));
      if (sub === "Image") {
        const why = imageProblem(pdf, x);
        if (why) add(why);
        continue;
      }
      if (sub === "PS") { add("a PostScript XObject"); continue; }
      if (sub !== "Form") { add("an XObject Attest doesn't accept"); continue; }
      if (drawing.includes(x)) { add("a form that draws itself"); continue; }
      if (checked.has(x)) continue;
      checked.add(x);
      checkStream(x, x.dict.get(PDFName.of("Resources")) ?? resRaw, {}, drawing);
    }
    for (const name of uses.ExtGState) {
      const gs = lookupIn(pdf, get("ExtGState", name));
      if (gs === undefined) continue;
      if (!(gs instanceof PDFDict)) { add("a graphics state Attest doesn't accept"); continue; }
      for (const [k, v] of gs.entries()) {
        const key = k.decodeText();
        if (!ALLOWED_GRAPHICS_STATE.has(key)) add(`a graphics state Attest doesn't accept (${shown(key)})`);
        else if ((key === "OP" || key === "op") && lookupIn(pdf, v)?.toString() === "true") add("a graphics state Attest doesn't accept (overprint)");
        else if (key === "OPM" && numberOf(pdf, v) !== 0 && numberOf(pdf, v) !== 1) add("a graphics state Attest doesn't accept (overprint)");
        else if (key === "SM") smoothness = true;
        else if (key === "SMask") {
          const mask = lookupIn(pdf, v);
          if (mask instanceof PDFName) continue;
          const group = mask instanceof PDFDict ? lookupIn(pdf, mask.get(PDFName.of("G"))) : undefined;
          if (!(mask instanceof PDFDict) || !(group instanceof PDFRawStream) || mask.has(PDFName.of("TR"))) { add("a soft mask Attest doesn't accept"); continue; }
          if (drawing.includes(group)) { add("a form that draws itself"); continue; }
          if (checked.has(group)) continue;
          checked.add(group);
          checkStream(group, group.dict.get(PDFName.of("Resources")) ?? resRaw, {}, drawing);
        }
      }
    }
    for (const name of uses.Font) {
      const font = lookupIn(pdf, get("Font", name));
      if (!(font instanceof PDFDict) || checked.has(font)) continue;
      if (nameIn(pdf, font.get(PDFName.of("Subtype"))) !== "Type3") {
        checked.add(font);
        const why = fontProblem(pdf, font);
        if (why) add(why);
        continue;
      }
      checked.add(font);
      const procs = lookupIn(pdf, font.get(PDFName.of("CharProcs")));
      if (!(procs instanceof PDFDict)) { add("a Type 3 font without its glyphs"); continue; }
      for (const [, proc] of procs.entries()) checkStream(proc, font.get(PDFName.of("Resources")) ?? resRaw, { glyph: true }, drawing);
    }
    for (const name of uses.Pattern) {
      const ref = get("Pattern", name);
      const pat = lookupIn(pdf, ref);
      if (ref === undefined) continue;
      const pd = pat instanceof PDFRawStream ? pat.dict : pat instanceof PDFDict ? pat : null;
      const type = pd ? numberOf(pdf, pd.get(PDFName.of("PatternType"))) : null;
      if (type === 2) { shading = true; continue; }
      if (type !== 1 || !(pat instanceof PDFRawStream)) { add("a pattern Attest doesn't accept"); continue; }
      if (drawing.includes(pat)) { add("a form that draws itself"); continue; }
      if (checked.has(pat)) continue;
      checked.add(pat);
      checkStream(pat, pat.dict.get(PDFName.of("Resources")), {}, drawing);
    }
    for (const name of uses.Shading) { shading = true; get("Shading", name); }
    for (const name of uses.ColorSpace) get("ColorSpace", name);
  };
  for (const page of pages) {
    const node = page.node;
    // Pages every reader sizes and turns the same way.
    if (!boxOf(pdf, node, "MediaBox")) add("a page whose size isn't stated (MediaBox)");
    const media = boxOf(pdf, node, "MediaBox");
    if (inherited(pdf, node, "CropBox") !== undefined) {
      const crop = boxOf(pdf, node, "CropBox");
      if (!crop || !media || Math.min(crop[2], media[2]) <= Math.max(crop[0], media[0]) || Math.min(crop[3], media[3]) <= Math.max(crop[1], media[1])) add("a page whose shown area isn't clear (CropBox)");
    }
    const rotate = inherited(pdf, node, "Rotate");
    if (rotate !== undefined && (!(rotate instanceof PDFNumber) || !Number.isInteger(rotate.asNumber()) || rotate.asNumber() % 90 !== 0)) add("a page turned by other than quarter turns (Rotate)");
    const unit = lookupIn(pdf, node.get(PDFName.of("UserUnit")));
    if (unit !== undefined && !(unit instanceof PDFNumber && unit.asNumber() === 1)) add("a page scaled by /UserUnit");
    // Annotations, on the page and on any page tree node above it: only links without an appearance of their own.
    for (let d: unknown = node, seen = 0; d instanceof PDFDict && seen < 64; d = lookupIn(pdf, d.get(PDFName.of("Parent"))), seen++) {
      const annots = lookupIn(pdf, d.get(PDFName.of("Annots")));
      if (annots === undefined) continue;
      if (!(annots instanceof PDFArray)) { add("an annotation (unknown)"); continue; }
      for (const raw of annots.asArray()) {
        const a = lookupIn(pdf, raw);
        const sub = a instanceof PDFDict ? nameIn(pdf, a.get(PDFName.of("Subtype"))) : null;
        if (sub === "Widget") { if (!invisibleSignature(pdf, a as PDFDict)) add("form fields"); }
        else if (sub !== "Link") add(`an annotation (${shown(sub ?? "unknown")})`);
        else if ((a as PDFDict).has(PDFName.of("AP")) && !drawsNothing(pdf, (a as PDFDict).get(PDFName.of("AP")))) add("a link with its own appearance");
      }
    }
    // The page's content: its streams decoded, joined at white space between tokens, and checked as one.
    const raw = lookupIn(pdf, node.get(PDFName.of("Contents")));
    const parts = raw === undefined ? [] : raw instanceof PDFArray ? raw.asArray() : [raw];
    const datas: Uint8Array[] = [];
    let bad = false;
    for (const p of parts) {
      const d = contentOf(pdf, p);
      if (typeof d === "string") { add(d); bad = true; break; }
      datas.push(d);
    }
    if (bad) continue;
    const joins: number[] = [];
    let total = 0;
    for (const d of datas.slice(0, -1)) { total += d.length; joins.push(total); }
    const r = checkContent(joined(datas), { parts: joins });
    if (r.problem) add(r.problem);
    checkResources(inherited(pdf, node, "Resources"), r.uses, []);
  }
  if (smoothness && shading) add("a graphics state Attest doesn't accept (SM)");
  return problems;
}

function joined(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

/** A value a page inherits (it or its nearest ancestor in the page tree), as readers look it up. */
function inherited(pdf: PDFDocument, page: PDFDict, key: string): unknown {
  const seen = new Set<unknown>();
  let d: unknown = page;
  while (d instanceof PDFDict && !seen.has(d)) {
    seen.add(d);
    const v = d.get(PDFName.of(key));
    if (v !== undefined) return v instanceof PDFRef ? pdf.context.lookup(v) : v;
    const parent = d.get(PDFName.of("Parent"));
    d = parent instanceof PDFRef ? pdf.context.lookup(parent) : parent;
  }
  return undefined;
}
type Rect4 = [number, number, number, number];
/** A page box as pdf.js reads it: four numbers, in either order, with an area; or none. */
function boxOf(pdf: PDFDocument, page: PDFDict, key: string): Rect4 | null {
  const v = inherited(pdf, page, key);
  if (!(v instanceof PDFArray) || v.size() !== 4) return null;
  const n = v.asArray().map((x) => (x instanceof PDFRef ? pdf.context.lookup(x) : x));
  if (!n.every((x) => x instanceof PDFNumber)) return null;
  const [a, b, c, d] = n.map((x) => (x as PDFNumber).asNumber());
  const r: Rect4 = [Math.min(a, c), Math.min(b, d), Math.max(a, c), Math.max(b, d)];
  return r[2] - r[0] > 0 && r[3] - r[1] > 0 ? r : null;
}

/**
 * The page as readers show it, from pdf.js's own rules (the field placer and the signing page draw it with pdf.js):
 * the CropBox, within the MediaBox, turned by /Rotate. Fields are fractions of this page from its top-left. `m` maps the
 * shown page, in points from its bottom-left, to the page's own coordinates.
 */
export function shownPage(pdf: PDFDocument, page: PDFPage): { width: number; height: number; m: [number, number, number, number, number, number]; media: Rect4 } {
  const node = page.node;
  const media = boxOf(pdf, node, "MediaBox") ?? [0, 0, 612, 792];
  const crop = boxOf(pdf, node, "CropBox") ?? media;
  let view = media;
  if (crop.some((v, k) => v !== media[k])) {
    const x0 = Math.max(crop[0], media[0]), x1 = Math.min(crop[2], media[2]);
    const y0 = Math.max(crop[1], media[1]), y1 = Math.min(crop[3], media[3]);
    if (x1 - x0 > 0 && y1 - y0 > 0) view = [x0, y0, x1, y1];
  }
  const r = inherited(pdf, node, "Rotate");
  let rotate = r instanceof PDFNumber ? r.asNumber() : 0;
  if (rotate % 90 !== 0) rotate = 0;
  else if (rotate >= 360) rotate %= 360;
  else if (rotate < 0) rotate = ((rotate % 360) + 360) % 360;
  const uu = node.get(PDFName.of("UserUnit"));
  const u = uu instanceof PDFRef ? pdf.context.lookup(uu) : uu;
  const unit = u instanceof PDFNumber && u.asNumber() > 0 ? u.asNumber() : 1;
  const [x0, y0, x1, y1] = view;
  const [W, H] = [(x1 - x0) * unit, (y1 - y0) * unit];
  const k = 1 / unit;
  const m: [number, number, number, number, number, number] =
    rotate === 90 ? [0, k, -k, 0, x1, y0] : rotate === 180 ? [-k, 0, 0, -k, x1, y1] : rotate === 270 ? [0, -k, k, 0, x0, y1] : [k, 0, 0, k, x0, y0];
  return rotate % 180 === 0 ? { width: W, height: H, m, media } : { width: H, height: W, m, media };
}

/**
 * The page's own content (accepted by documentProblems) drawn as one form XObject, which readers draw with its own
 * graphics state: what Attest draws next starts from the page's own state, on top of everything the signer saw. The
 * content's resources stay its own, so it can't name anything Attest adds. Its links, which print nothing, are left out.
 */
function isolatePage(pdf: PDFDocument, page: PDFPage, media: Rect4) {
  const ctx = pdf.context;
  const node = page.node;
  const raw = lookupIn(pdf, node.get(PDFName.of("Contents")));
  const parts = raw === undefined ? [] : raw instanceof PDFArray ? raw.asArray() : [raw];
  const body = joined(parts.map((p) => contentOf(pdf, p) as Uint8Array));
  const resources = inherited(pdf, node, "Resources");
  const form = ctx.flateStream(body, {
    Type: "XObject",
    Subtype: "Form",
    BBox: media,
    Resources: resources instanceof PDFDict ? resources : ctx.obj({}),
  });
  node.set(PDFName.of("Resources"), ctx.obj({ XObject: { AttestPage: ctx.register(form) } }));
  node.set(PDFName.of("Contents"), ctx.register(ctx.flateStream("q /AttestPage Do Q\n")));
  for (let d: unknown = node, seen = 0; d instanceof PDFDict && seen < 64; d = lookupIn(pdf, d.get(PDFName.of("Parent"))), seen++) d.delete(PDFName.of("Annots"));
}

/**
 * Why a document isn't clean (empty when it is): what keeps v3 from proving every reader shows it the same way. It only
 * classifies; renderV3 signs every document. Only an engine running out of room throws.
 */
export async function documentProblemsV3(original: Uint8Array): Promise<string[]> {
  let pdf: PDFDocument;
  try {
    // Decrypted first, if it's encrypted and pdf.js opens it without a password: its content decides, as any other's.
    pdf = await openOriginalV3(original);
  } catch (e) {
    if (resourceError(e)) throw e;
    return [UNREADABLE[unreadableKind(e)]];
  }
  // A file pdf-lib opens without a catalog (not really a PDF) is as unreadable as one it can't open.
  if (!(pdf.catalog instanceof PDFDict)) return [UNREADABLE.damaged];
  try {
    return documentProblems(pdf);
  } catch (e) {
    if (resourceError(e)) throw e;
    return ["a PDF whose structure can't be read through"];
  }
}

// ---- Protecting a document that isn't clean ---------------------------------------------------------------------
//
// v3 signs every document. One that isn't clean gets the best protection v3 can give, and its copy says so
// (NOT_CLEAN_NOTE, at the foot of every page of the document and on the certificate of completion). The anchored
// original, attached to the copy, is what was signed, and the verifier shows it exactly.
//
// - Each page's content is drawn as one form XObject, read as pdf.js reads it (its lexer, its operators, its inline
//   images) and closed off: preceded by as many saves as it could restore beyond its own, followed by what ends every
//   state a content stream can leave open (ET, n, EMC, EX). Every other content stream a page may run (form XObjects,
//   Type 3 glyphs, soft masks, annotation appearances) is closed off the same way. Content v3 can't decode, or can't
//   read to its end, is kept exactly as it was, inside the form: never dropped or rewritten.
// - Annotations pdf.js prints (flagged Print, not Hidden or Invisible, valid QuadPoints) are drawn into the page from
//   their appearance (the state /AS names), as pdf.js draws them, under Attest's layer; form fields with their current
//   appearances. The ones pdf.js doesn't print are dropped, and no annotation or form field is left in the copy.
// - Optional content: visibility decided exactly as pdf.js decides it for print (the signer's view), and only what
//   pdf.js showed kept: an XObject pdf.js hid is emptied, an annotation it hid dropped, and in content the painting
//   inside marked content it hid is taken out, every change of state kept. The copy then has no optional content, so no
//   reader can hide anything with it (Attest's layer included), however it reads the content. Only where v3 keeps
//   content as it was (it can't read it) in a document whose optional content pdf.js hides does the copy keep optional
//   content: pdf.js's decisions, as one layer that is on and one that is off.
// - Attest's layer is drawn last.

/** Why a document can't be opened at all, as the check gives it. */
const UNREADABLE = {
  password: "a PDF that can't be read (it opens only with a password)",
  unsupported: "a PDF that can't be read (encrypted in a way pdf.js doesn't open)",
  damaged: "a PDF that can't be read (a damaged file)",
} as const;
const unreadableKind = (e: unknown): keyof typeof UNREADABLE => (e instanceof UnreadablePdf ? e.kind : "damaged");

/** The sentence a copy of a document that isn't clean carries. */
export const NOT_CLEAN_NOTE = "Some PDF readers may display parts of this document differently. Attest's verifier shows exactly what was signed.";

/** pdf.js's operators and their operand counts (EvaluatorPreprocessor.opMap; negative: up to that many). */
const PDFJS_OPERATORS: Record<string, number> = {
  w: 1, J: 1, j: 1, M: 1, d: 2, ri: 1, i: 1, gs: 1, q: 0, Q: 0, cm: 6, m: 2, l: 2, c: 6, v: 4, y: 4, h: 0, re: 4, S: 0, s: 0, f: 0,
  F: 0, "f*": 0, B: 0, "B*": 0, b: 0, "b*": 0, n: 0, W: 0, "W*": 0, BT: 0, ET: 0, Tc: 1, Tw: 1, Tz: 1, TL: 1, Tf: 2, Tr: 1, Ts: 1,
  Td: 2, TD: 2, Tm: 6, "T*": 0, Tj: 1, TJ: 1, "'": 1, '"': 3, d0: 2, d1: 6, CS: 1, cs: 1, SC: -4, SCN: -33, sc: -4, scn: -33, G: 1,
  g: 1, RG: 3, rg: 3, K: 4, k: 4, sh: 1, BI: 0, ID: 0, EI: 1, Do: 1, MP: 1, DP: 2, BMC: 1, BDC: 2, EMC: 0, BX: 0, EX: 0,
};
/** Every word pdf.js's lexer knows, which it splits a run of characters into ("fQ" is f, then Q). */
const LEXER_WORDS = new Set([...Object.keys(PDFJS_OPERATORS), "BM", "BD", "true", "fa", "fal", "fals", "false", "nu", "nul", "null"]);
const PATH_OPS = new Set(["m", "l", "c", "v", "y", "h", "re"]);
const PAINT_OPS = new Set(["S", "s", "f", "F", "f*", "B", "B*", "b", "b*", "n"]);
const isWhite = (c: number) => c === 0 || c === 9 || c === 10 || c === 12 || c === 13 || c === 32;
const isDelim = (c: number) => c === 40 || c === 41 || c === 60 || c === 62 || c === 91 || c === 93 || c === 123 || c === 125 || c === 47 || c === 37;
const isSpecial = (c: number) => isWhite(c) || isDelim(c);

type Tok = { k: "op"; v: string } | { k: "num" | "str" | "hex" | "name" | "lit"; v: string } | { k: "[" | "]" | "<<" | ">>" | "{" | "}" | ">" } | { k: "eof" };
type Lexed = { tok: Tok; start: number; end: number } | { error: string };

/** One token at `i` (where it starts, after white space and comments), as pdf.js's lexer reads it (Lexer.getObj), or why pdf.js would stop reading there. */
function lexAt(b: Uint8Array, i: number): Lexed {
  const n = b.length;
  for (;;) {
    if (i >= n) return { tok: { k: "eof" }, start: n, end: n };
    if (b[i] === 37) {
      while (i < n && b[i] !== 10 && b[i] !== 13) i++;
      continue;
    }
    if (isWhite(b[i])) {
      i++;
      continue;
    }
    break;
  }
  const c = b[i];
  const start = i;
  if ((c >= 48 && c <= 57) || c === 43 || c === 45 || c === 46) {
    let j = i;
    let ch = b[j];
    if (ch === 45) {
      ch = b[++j];
      if (ch === 45) ch = b[++j];
    } else if (ch === 43) ch = b[++j];
    while (ch === 10 || ch === 13) ch = b[++j];
    let dot = false;
    if (ch === 46) {
      dot = true;
      ch = b[++j];
    }
    if (!(ch >= 48 && ch <= 57)) {
      if (j >= n || isWhite(ch) || ch === 40 || ch === 60) return { start, tok: { k: "num", v: "0" }, end: j };
      return { error: "a number pdf.js can't read" };
    }
    for (j++; j < n; j++) {
      const x = b[j];
      if (x >= 48 && x <= 57) continue;
      if (x === 46) {
        if (!dot) {
          dot = true;
          continue;
        }
        break;
      }
      if (x === 45) continue;
      break;
    }
    return { start, tok: { k: "num", v: "" }, end: j };
  }
  if (c === 40) {
    let depth = 1;
    let j = i + 1;
    while (j < n) {
      const x = b[j++];
      if (x === 92) {
        if (j < n) j++;
      } else if (x === 40) depth++;
      else if (x === 41 && --depth === 0) return { start, tok: { k: "str", v: "" }, end: j };
    }
    return { error: "a string that isn't closed" };
  }
  if (c === 47) {
    let j = i + 1;
    while (j < n && !isSpecial(b[j])) j++;
    return { start, tok: { k: "name", v: String.fromCharCode(...b.subarray(i + 1, j)) }, end: j };
  }
  if (c === 91) return { start, tok: { k: "[" }, end: i + 1 };
  if (c === 93) return { start, tok: { k: "]" }, end: i + 1 };
  if (c === 123) return { start, tok: { k: "{" }, end: i + 1 };
  if (c === 125) return { start, tok: { k: "}" }, end: i + 1 };
  if (c === 60) {
    if (b[i + 1] === 60) return { start, tok: { k: "<<" }, end: i + 2 };
    let j = i + 1;
    while (j < n && b[j] !== 62) j++;
    if (j >= n) return { error: "a hex string that isn't closed" };
    return { start, tok: { k: "hex", v: "" }, end: j + 1 };
  }
  if (c === 62) return b[i + 1] === 62 ? { start, tok: { k: ">>" }, end: i + 2 } : { start, tok: { k: ">" }, end: i + 1 };
  if (c === 41) return { error: "a stray parenthesis, where pdf.js stops reading" };
  // A command: pdf.js reads characters while they make one of its words, or until it has one and the next would end it.
  if ((c < 0x20 || c > 0x7f) && i + 1 < n && b[i + 1] >= 0x20 && b[i + 1] <= 0x7f) return { start, tok: { k: "op", v: String.fromCharCode(c) }, end: i + 1 };
  let str = String.fromCharCode(c);
  let known = LEXER_WORDS.has(str);
  let j = i + 1;
  for (; j < n && !isSpecial(b[j]); j++) {
    const next = str + String.fromCharCode(b[j]);
    if (known && !LEXER_WORDS.has(next)) break;
    if (str.length === 128) return { error: "a command pdf.js finds too long" };
    str = next;
    known = LEXER_WORDS.has(str);
  }
  if (str === "true" || str === "false" || str === "null") return { start, tok: { k: "lit", v: str }, end: j };
  return { start, tok: { k: "op", v: str }, end: j };
}

/** What a content stream leaves open at its end, the most saved states it could restore beyond its own, or why it can't be read to its end. */
interface ContentState {
  restores: number;
  text: boolean;
  path: boolean;
  marked: number;
  compat: number;
  problem: string | null;
}

/** Where an inline image's data ends (its "EI"), found as pdf.js finds it, or why it can't be found. */
function pdfjsImageEnd(b: Uint8Array, dataStart: number, filter: string | null): number | string {
  const n = b.length;
  let from = dataStart;
  // pdf.js finds an ASCII85 or ASCIIHex image's end by its EOD marker, and every other's by "EI".
  if (filter === "A85" || filter === "ASCII85Decode") {
    for (let k = dataStart; k + 1 < n; k++) if (b[k] === 0x7e && b[k + 1] === 0x3e) { from = k + 2; break; }
  } else if (filter === "AHx" || filter === "ASCIIHexDecode") {
    for (let k = dataStart; k < n; k++) if (b[k] === 0x3e) { from = k + 1; break; }
  }
  // "E", "I", then a space, line feed or carriage return, followed by text and a command with its operands (pdf.js
  // looks again past a candidate that isn't).
  for (let at = from; at + 2 < n; at++) {
    if (b[at] !== 0x45 || b[at + 1] !== 0x49 || !(b[at + 2] === 0x20 || b[at + 2] === 0x0a || b[at + 2] === 0x0d)) continue;
    const after = b.subarray(at + 3, at + 3 + 15);
    let text = true;
    for (let k = 0; k < after.length; k++) {
      const ch = after[k];
      if (ch === 0 && after[k + 1] !== 0) continue;
      if (ch !== 0x0a && ch !== 0x0d && (ch < 0x20 || ch > 0x7f)) { text = false; break; }
    }
    if (!text) continue;
    if (!after.length) return at;
    const window = b.subarray(at + 3, at + 3 + 75);
    let p = 0;
    let operands = 0;
    let ok = false;
    for (;;) {
      const r = lexAt(window, p);
      if ("error" in r || r.tok.k === "eof") break;
      p = r.end;
      if (r.tok.k === "op") {
        const count = PDFJS_OPERATORS[r.tok.v];
        if (count === undefined) break;
        if (count < 0 ? operands <= -count : operands === count) { ok = true; break; }
        operands = 0;
        continue;
      }
      operands++;
    }
    if (ok) return at;
  }
  return "an inline image without its end";
}

/** Where an inline image ends (just after its "EI"), its dictionary read from `i` (just after "BI") as pdf.js reads it, or why it can't be read. */
function pdfjsInlineImageEnd(b: Uint8Array, i: number): number | string {
  let filter: string | null = null;
  for (;;) {
    const k = lexAt(b, i);
    if ("error" in k) return k.error;
    i = k.end;
    if (k.tok.k === "eof") return "an inline image without its data";
    if (k.tok.k === "op" && k.tok.v === "ID") break;
    if (k.tok.k !== "name") return "an inline image whose dictionary pdf.js can't read";
    const key = k.tok.v;
    const v = lexAt(b, i);
    if ("error" in v) return v.error;
    i = v.end;
    if (v.tok.k === "eof" || (v.tok.k === "op" && v.tok.v === "ID")) return "an inline image whose dictionary pdf.js can't read";
    if (v.tok.k === "[" || v.tok.k === "<<") {
      let depth = 1;
      let first = true;
      while (depth > 0) {
        const y = lexAt(b, i);
        if ("error" in y) return y.error;
        i = y.end;
        if (y.tok.k === "eof") return "an inline image whose dictionary pdf.js can't read";
        if (y.tok.k === "[" || y.tok.k === "<<") depth++;
        else if (y.tok.k === "]" || y.tok.k === ">>") depth--;
        else if (first && depth === 1 && y.tok.k === "name" && (key === "F" || key === "Filter")) filter = y.tok.v;
        first = false;
      }
    } else if ((key === "F" || key === "Filter") && v.tok.k === "name") filter = v.tok.v;
  }
  const end = pdfjsImageEnd(b, i + 1, filter);
  return typeof end === "string" ? end : end + 2;
}

/** Reads a content stream as pdf.js does: what it leaves open at its end, or why v3 can't read it to its end. */
function readContent(b: Uint8Array): ContentState {
  const s: ContentState = { restores: 0, text: false, path: false, marked: 0, compat: 0, problem: null };
  let saved = 0;
  let nest = 0;
  let i = 0;
  const fail = (why: string) => ((s.problem = why), s);
  for (;;) {
    const r = lexAt(b, i);
    if ("error" in r) return fail(r.error);
    i = r.end;
    const t = r.tok;
    if (t.k === "eof") break;
    if (t.k === "[" || t.k === "<<") nest++;
    else if (t.k === "]" || t.k === ">>") nest = Math.max(0, nest - 1);
    if (t.k !== "op") continue;
    const op = t.v;
    if (nest > 0) {
      if (op === "BI") return fail("an inline image inside an array or a dictionary");
      continue;
    }
    if (op === "q") saved++;
    else if (op === "Q") {
      saved--;
      if (-saved > s.restores) s.restores = -saved;
    } else if (op === "BT") s.text = true;
    else if (op === "ET") s.text = false;
    else if (op === "BMC" || op === "BDC") s.marked++;
    else if (op === "EMC") s.marked = Math.max(0, s.marked - 1);
    else if (op === "BX") s.compat++;
    else if (op === "EX") s.compat = Math.max(0, s.compat - 1);
    else if (PATH_OPS.has(op) || op === "W" || op === "W*") s.path = true;
    else if (PAINT_OPS.has(op)) s.path = false;
    else if (op === "BI") {
      const end = pdfjsInlineImageEnd(b, i);
      if (typeof end === "string") return fail(end);
      i = end;
    }
  }
  if (nest > 0) return fail("an array or a dictionary that isn't closed");
  return s;
}

const ascii = (s: string) => Uint8Array.from(s, (ch) => ch.charCodeAt(0));
/** Content closed off: preceded by the saves it could restore beyond its own, followed by what ends what it left open. */
const closedOff = (data: Uint8Array, s: ContentState) =>
  joined([ascii(s.restores ? `${"q ".repeat(s.restores)}\n` : ""), data, ascii(`\n${s.text ? "ET\n" : ""}${s.path ? "n\n" : ""}${"EMC\n".repeat(s.marked)}${"EX\n".repeat(s.compat)}`)]);
const needsClosing = (s: ContentState) => s.restores > 0 || s.text || s.path || s.marked > 0 || s.compat > 0;
const STREAM_KEYS = new Set(["Filter", "DecodeParms", "Length", "DL", "F", "FFilter", "FDecodeParms"]);

/**
 * A stream's content closed off where v3 can read it to its end (`content`: the same content with what pdf.js hid taken
 * out, when v3 took it out); otherwise the stream as it was.
 */
function closedOffStream(pdf: PDFDocument, s: PDFRawStream, extra: Record<string, unknown> | null, content?: Uint8Array): PDFRawStream {
  const ctx = pdf.context;
  const data = content ?? contentOf(pdf, s);
  const state = typeof data === "string" ? null : readContent(data);
  if (typeof data === "string" || !state || state.problem) {
    if (!extra) return s;
    const kept = PDFRawStream.of(s.dict.clone(ctx), s.contents);
    for (const [k, v] of Object.entries(extra)) kept.dict.set(PDFName.of(k), ctx.obj(v as never));
    return kept;
  }
  const fresh = ctx.flateStream(needsClosing(state) ? closedOff(data, state) : data);
  for (const [k, v] of s.dict.entries()) if (!STREAM_KEYS.has(k.decodeText())) fresh.dict.set(k, v);
  if (extra) for (const [k, v] of Object.entries(extra)) fresh.dict.set(PDFName.of(k), ctx.obj(v as never));
  return fresh;
}

type StreamKind = "form" | "glyph" | "pattern" | "mask";
/** Every content stream a page may run besides its own: forms, Type 3 glyphs, tiling patterns' cells and soft masks' groups. */
function contentStreams(pdf: PDFDocument): Map<PDFRef, StreamKind> {
  const ctx = pdf.context;
  const out = new Map<PDFRef, StreamKind>();
  for (const [ref, o] of ctx.enumerateIndirectObjects()) {
    const dict = o instanceof PDFDict ? o : o instanceof PDFRawStream ? o.dict : null;
    if (!dict) continue;
    const pattern = lookupIn(pdf, dict.get(PDFName.of("PatternType")));
    if (o instanceof PDFRawStream && pattern instanceof PDFNumber && pattern.asNumber() === 1) out.set(ref, "pattern");
    else if (o instanceof PDFRawStream && nameIn(pdf, dict.get(PDFName.of("Subtype"))) === "Form" && !out.has(ref)) out.set(ref, "form");
    if (nameIn(pdf, dict.get(PDFName.of("Subtype"))) === "Type3") {
      const procs = lookupIn(pdf, dict.get(PDFName.of("CharProcs")));
      if (procs instanceof PDFDict) for (const [, v] of procs.entries()) if (v instanceof PDFRef) out.set(v, "glyph");
    }
    const mask = lookupIn(pdf, dict.get(PDFName.of("SMask")));
    const group = mask instanceof PDFDict ? mask.get(PDFName.of("G")) : undefined;
    if (group instanceof PDFRef) out.set(group, "mask");
  }
  return out;
}

/** Every other content stream a page may run, closed off where v3 can read it (with what pdf.js hid taken out, if v3 took it out). */
function closeOffContentStreams(pdf: PDFDocument, rewritten: Map<PDFRawStream, Uint8Array>) {
  const ctx = pdf.context;
  for (const [ref] of contentStreams(pdf)) {
    const s = ctx.lookup(ref);
    if (!(s instanceof PDFRawStream)) continue;
    const out = closedOffStream(pdf, s, null, rewritten.get(s));
    if (out !== s) ctx.assign(ref, out);
  }
}

/** The ref of an object as pdf.js names it (Ref.toString: its number, then its generation). */
const refId = (r: PDFRef) => `${r.objectNumber}R${r.generationNumber || ""}`;

/**
 * Whether pdf.js shows a piece of optional content for print (the signer's view), from its own rules
 * (OptionalContentConfig with the print intent, parseMarkedContentProps): `value` is what the document holds for it, at
 * /OC or in /Properties.
 */
function pdfjsOptionalContent(pdf: PDFDocument): (value: unknown) => boolean {
  const groups = new Map<string, boolean>();
  try {
    const props = lookupIn(pdf, pdf.catalog.get(PDFName.of("OCProperties")));
    const d = props instanceof PDFDict ? lookupIn(pdf, props.get(PDFName.of("D"))) : undefined;
    const list = props instanceof PDFDict ? lookupIn(pdf, props.get(PDFName.of("OCGs"))) : undefined;
    if (d instanceof PDFDict && list instanceof PDFArray) {
      const printOff = new Map<string, boolean>();
      for (const raw of list.asArray()) {
        if (!(raw instanceof PDFRef) || printOff.has(refId(raw))) continue;
        const g = pdf.context.lookup(raw);
        if (!(g instanceof PDFDict)) throw new Error("not a group");
        const usage = lookupIn(pdf, g.get(PDFName.of("Usage")));
        const print = usage instanceof PDFDict ? lookupIn(pdf, usage.get(PDFName.of("Print"))) : undefined;
        printOff.set(refId(raw), print instanceof PDFDict && nameIn(pdf, print.get(PDFName.of("PrintState"))) === "OFF");
      }
      const base = nameIn(pdf, d.get(PDFName.of("BaseState")));
      const state = new Map([...printOff.keys()].map((id) => [id, base !== "OFF"]));
      for (const [key, on] of [["ON", true], ["OFF", false]] as const) {
        const refs = lookupIn(pdf, d.get(PDFName.of(key)));
        if (refs instanceof PDFArray) for (const r of refs.asArray()) if (r instanceof PDFRef && state.has(refId(r))) state.set(refId(r), on);
      }
      for (const [id, on] of state) groups.set(id, on && !printOff.get(id));
    }
  } catch {
    groups.clear();
  }
  type Expr = (string | Expr)[];
  const parse = (array: PDFArray, nesting: number, out: Expr) => {
    if (++nesting > 10) return;
    const items = array.asArray();
    const op = lookupIn(pdf, items[0]);
    if (items.length < 2 || !(op instanceof PDFName) || !["And", "Or", "Not"].includes(op.decodeText())) return;
    out.push(op.decodeText());
    for (const raw of items.slice(1)) {
      const o = lookupIn(pdf, raw);
      if (o instanceof PDFArray) {
        const nested: Expr = [];
        out.push(nested);
        parse(o, nesting, nested);
      } else if (raw instanceof PDFRef) out.push(refId(raw));
    }
  };
  const evaluate = (e: Expr): boolean => {
    if (e.length < 2) return true;
    const op = e[0];
    for (const el of e.slice(1)) {
      let st: boolean;
      if (Array.isArray(el)) st = evaluate(el);
      else if (groups.has(el)) st = groups.get(el)!;
      else return true;
      if (op === "And") { if (!st) return false; }
      else if (op === "Or") { if (st) return true; }
      else if (op === "Not") return !st;
      else return true;
    }
    return op === "And";
  };
  return (value: unknown) => {
    if (groups.size === 0) return true;
    const dict = lookupIn(pdf, value);
    if (!(dict instanceof PDFDict)) return true;
    const type = nameIn(pdf, dict.get(PDFName.of("Type")));
    if (type === "OCG") return value instanceof PDFRef && groups.has(refId(value)) ? groups.get(refId(value))! : true;
    if (type !== "OCMD") return true;
    const ve = lookupIn(pdf, dict.get(PDFName.of("VE")));
    if (ve instanceof PDFArray) {
      const e: Expr = [];
      parse(ve, 0, e);
      if (e.length) return evaluate(e);
    }
    const raw = dict.get(PDFName.of("OCGs"));
    const ocgs = lookupIn(pdf, raw);
    let ids: string[];
    if (ocgs instanceof PDFArray) ids = ocgs.asArray().map((x) => (x instanceof PDFRef ? refId(x) : "?"));
    else if (ocgs instanceof PDFDict) ids = [raw instanceof PDFRef ? refId(raw) : "?"];
    else return true;
    const p = nameIn(pdf, dict.get(PDFName.of("P"))) ?? "AnyOn";
    const on = (id: string) => groups.get(id)!;
    if (ids.some((id) => !groups.has(id))) {
      // pdf.js shows it as soon as it meets a group it doesn't know, in the order it looks.
      for (const id of ids) {
        if (!groups.has(id)) return true;
        if ((p === "AnyOn" && on(id)) || (p === "AnyOff" && !on(id))) return true;
        if ((p === "AllOn" && !on(id)) || (p === "AllOff" && on(id))) return false;
      }
    }
    if (p === "AnyOn") return ids.some(on);
    if (p === "AllOn") return ids.every(on);
    if (p === "AnyOff") return ids.some((id) => !on(id));
    if (p === "AllOff") return ids.every((id) => !on(id));
    return true;
  };
}

/** Every place a document names optional content (at /OC, and in /Properties), and what pdf.js decides for each. */
type OcPlace = { dict: PDFDict; key: PDFName; value: unknown; shown: boolean; ref: PDFRef | null };
function optionalContentPlaces(pdf: PDFDocument, visible: (value: unknown) => boolean): OcPlace[] {
  const isOC = (v: unknown) => {
    const d = lookupIn(pdf, v);
    const t = d instanceof PDFDict ? nameIn(pdf, d.get(PDFName.of("Type"))) : null;
    return t === "OCG" || t === "OCMD";
  };
  const places: OcPlace[] = [];
  const seen = new Set<unknown>();
  const walk = (o: unknown, ref: PDFRef | null) => {
    const dict = o instanceof PDFDict ? o : o instanceof PDFRawStream ? o.dict : null;
    if (dict && !seen.has(dict)) {
      seen.add(dict);
      const oc = dict.get(PDFName.of("OC"));
      if (oc !== undefined) places.push({ dict, key: PDFName.of("OC"), value: oc, shown: visible(oc), ref });
      const props = lookupIn(pdf, dict.get(PDFName.of("Properties")));
      if (props instanceof PDFDict) for (const [k, v] of props.entries()) if (isOC(v)) places.push({ dict: props, key: k, value: v, shown: visible(v), ref: null });
      for (const [, v] of dict.entries()) if (v instanceof PDFDict || v instanceof PDFArray) walk(v, null);
    } else if (o instanceof PDFArray && !seen.has(o)) {
      seen.add(o);
      for (const v of o.asArray()) if (v instanceof PDFDict || v instanceof PDFArray) walk(v, null);
    }
  };
  for (const [ref, o] of pdf.context.enumerateIndirectObjects()) walk(o, ref);
  return places;
}

/** pdf.js running a document's content, for taking out what it hid: each form it runs, rewritten once. */
interface HiddenWalk {
  pdf: PDFDocument;
  visible: (value: unknown) => boolean;
  forms: Map<PDFRawStream, Uint8Array>;
  active: Set<PDFRawStream>;
}
const TEXT_SHOWING = new Set(["Tj", "TJ", "'", '"']);
const PAINTING = new Set(["S", "s", "f", "F", "f*", "B", "B*", "b", "b*"]);
const latin1 = (b: Uint8Array) => {
  let out = "";
  for (let k = 0; k < b.length; k++) out += String.fromCharCode(b[k]);
  return out;
};

/**
 * A content stream with what pdf.js hid in it taken out, read as pdf.js reads it (its lexer, its operators and their
 * operands, its inline images): inside marked content whose optional content pdf.js hides, a path ends without being
 * painted, text is shown in the invisible rendering mode (it still moves the text position, as pdf.js moves it), and an
 * image, shading or inline image, or a form, is left out; every change of state stays, so what follows is drawn where
 * pdf.js drew it. A dictionary of optional content written into the content is emptied. Forms it runs are rewritten
 * the same way (the first call decides, by the text rendering mode it's called in). pdf.js keeps each stream's marked
 * content to itself (it ignores an EMC beyond the stream's own, and closes what the stream leaves open at its end), so
 * each stream is read on its own. `tr` is the text rendering mode the content starts in, as written.
 */
function withoutHidden(w: HiddenWalk, data: Uint8Array, resources: unknown, tr: string): Uint8Array {
  const pdf = w.pdf;
  const res = lookupIn(pdf, resources);
  const sub = (key: string) => {
    const d = res instanceof PDFDict ? lookupIn(pdf, res.get(PDFName.of(key))) : undefined;
    return d instanceof PDFDict ? d : null;
  };
  const edits: { at: number; end: number; text: string }[] = [];
  const open: boolean[] = [];
  const saved: string[] = [];
  type Operand = { k: string; v: string; start: number; end: number };
  let operands: Operand[] = [];
  const pending: Operand[] = [];
  let nest = 0;
  let nestStart = 0;
  let i = 0;
  const hidden = () => open.includes(false);
  for (;;) {
    const r = lexAt(data, i);
    if ("error" in r) break;
    i = r.end;
    const t = r.tok;
    if (t.k === "eof") break;
    if (t.k === "[" || t.k === "<<") {
      if (nest++ === 0) nestStart = r.start;
      continue;
    }
    if (t.k === "]" || t.k === ">>") {
      if (nest > 0 && --nest === 0) operands.push({ k: t.k === "]" ? "array" : "dict", v: "", start: nestStart, end: r.end });
      continue;
    }
    if (nest > 0) continue;
    if (t.k !== "op") {
      // pdf.js keeps no null operand.
      if (!(t.k === "lit" && t.v === "null")) operands.push({ k: t.k, v: t.k === "name" ? t.v : latin1(data.subarray(r.start, r.end)), start: r.start, end: r.end });
      continue;
    }
    const op = t.v;
    const count = PDFJS_OPERATORS[op];
    // A command pdf.js doesn't know: skipped, its operands kept for the next.
    if (count === undefined) continue;
    const from = operands.length ? operands[0].start : r.start;
    let args = operands;
    operands = [];
    if (count >= 0 && args.length !== count) {
      while (args.length > count) pending.push(args.shift()!);
      while (args.length < count && pending.length) args.unshift(pending.pop()!);
      // Too few operands: pdf.js skips the command.
      if (args.length < count) continue;
    }
    if (op === "BI") {
      // The inline image, as far as pdf.js reads it: left out if pdf.js hid it.
      const end = pdfjsInlineImageEnd(data, i);
      if (typeof end === "string") break;
      if (hidden()) edits.push({ at: r.start, end, text: " " });
      i = end;
      continue;
    }
    if (op === "q") saved.push(tr);
    else if (op === "Q") {
      if (saved.length) tr = saved.pop()!;
    } else if (op === "Tr") tr = args[0].v;
    else if (op === "BMC") open.push(true);
    else if (op === "BDC") {
      let shown = true;
      if (args[0].k === "name" && args[0].v === "OC") {
        const value = args[1];
        if (value.k === "name") shown = w.visible(sub("Properties")?.get(PDFName.of(value.v)));
        else if (value.k === "dict") {
          try {
            shown = w.visible(PDFObjectParser.forBytes(data.subarray(value.start, value.end), pdf.context).parseObject());
          } catch {
            shown = true;
          }
          // Emptied: written into the content, optional content no reader is left to read.
          edits.push({ at: value.start, end: value.end, text: "<<>>" });
        }
      }
      open.push(shown);
    } else if (op === "EMC") open.pop();
    else if (hidden()) {
      if (PAINTING.has(op)) edits.push({ at: r.start, end: r.end, text: "n" });
      else if (op === "sh" || op === "Do") edits.push({ at: from, end: r.end, text: " " });
      else if (TEXT_SHOWING.has(op)) {
        edits.push({ at: from, end: from, text: " 3 Tr " });
        edits.push({ at: r.end, end: r.end, text: ` ${tr} Tr ` });
      }
    } else if (op === "Do" && args[0].k === "name") {
      // A form pdf.js runs: its own content rewritten, once.
      const form = lookupIn(pdf, sub("XObject")?.get(PDFName.of(args[0].v)));
      if (form instanceof PDFRawStream && nameIn(pdf, form.dict.get(PDFName.of("Subtype"))) === "Form" && !w.active.has(form) && !w.forms.has(form)) {
        const content = contentOf(pdf, form);
        if (typeof content !== "string") {
          w.active.add(form);
          w.forms.set(form, withoutHidden(w, content, form.dict.get(PDFName.of("Resources")) ?? resources, tr));
          w.active.delete(form);
        }
      }
    }
  }
  if (!edits.length) return data;
  edits.sort((x, y) => x.at - y.at || x.end - y.end);
  const parts: Uint8Array[] = [];
  let at = 0;
  for (const e of edits) {
    if (e.at < at) continue;
    parts.push(data.subarray(at, e.at), ascii(e.text));
    at = e.end;
  }
  parts.push(data.subarray(at));
  return joined(parts);
}

/**
 * Optional content as pdf.js showed it to the signer, in a copy with none left: what pdf.js hid is taken out (an
 * XObject it hid is emptied, an annotation it hid is dropped by the caller, and in content the painting inside marked
 * content it hid), and every /OC, optional content entry in /Properties and /OCProperties goes, so no reader can hide
 * anything with it, however it reads the document's content. Returns each page's content and each other content
 * stream (forms, annotations' appearances, glyphs, patterns' cells, soft masks' groups) with what pdf.js hid taken out.
 */
function withoutOptionalContent(pdf: PDFDocument, pages: PDFPage[], places: OcPlace[], visible: (value: unknown) => boolean, printed: Printed[][]) {
  const ctx = pdf.context;
  const w: HiddenWalk = { pdf, visible, forms: new Map(), active: new Set() };
  const pageContent = new Map<PDFPage, Uint8Array>();
  const rewritten = new Map<PDFRawStream, Uint8Array>();
  if (places.some((p) => !p.shown)) {
    for (const page of pages) {
      const raw = lookupIn(pdf, page.node.get(PDFName.of("Contents")));
      const parts = raw === undefined ? [] : raw instanceof PDFArray ? raw.asArray() : [raw];
      const decoded = parts.map((p) => contentOf(pdf, p));
      if (decoded.every((d): d is Uint8Array => typeof d !== "string")) pageContent.set(page, withoutHidden(w, joined(decoded), inherited(pdf, page.node, "Resources"), "0"));
    }
    // Annotations pdf.js prints, then glyphs, patterns' cells and soft masks' groups: each from a start with nothing hidden.
    const others: PDFRawStream[] = printed.flat().flatMap((x) => (x.appearance ? [x.appearance] : []));
    for (const [ref, kind] of contentStreams(pdf)) {
      const s = ctx.lookup(ref);
      if (kind !== "form" && s instanceof PDFRawStream) others.push(s);
    }
    for (const s of others) {
      if (rewritten.has(s) || w.forms.has(s)) continue;
      const content = contentOf(pdf, s);
      if (typeof content !== "string") rewritten.set(s, withoutHidden(w, content, s.dict.get(PDFName.of("Resources")), "0"));
    }
    for (const [form, data] of w.forms) rewritten.set(form, data);
  }
  // Only now, with every decision taken from the document as it came: optional content goes.
  for (const p of places) {
    // An XObject pdf.js hid draws nothing in any reader.
    if (!p.shown && p.ref && p.key.decodeText() === "OC" && ctx.lookup(p.ref) instanceof PDFRawStream) {
      const sub = nameIn(pdf, p.dict.get(PDFName.of("Subtype")));
      if (sub === "Form" || sub === "Image") {
        ctx.assign(p.ref, ctx.flateStream("", { Type: "XObject", Subtype: "Form", BBox: [0, 0, 0, 0] } as never));
        continue;
      }
    }
    if (p.key.decodeText() === "OC") p.dict.delete(p.key);
    else p.dict.set(p.key, ctx.obj({}));
  }
  pdf.catalog.delete(PDFName.of("OCProperties"));
  return { pageContent, rewritten };
}

/** Whether v3 can read, to its end, every content stream pdf.js may run. */
function readableThroughout(pdf: PDFDocument, pages: PDFPage[]): boolean {
  for (const page of pages) {
    const raw = lookupIn(pdf, page.node.get(PDFName.of("Contents")));
    const parts = raw === undefined ? [] : raw instanceof PDFArray ? raw.asArray() : [raw];
    const decoded = parts.map((p) => contentOf(pdf, p));
    if (!decoded.every((d): d is Uint8Array => typeof d !== "string") || readContent(joined(decoded)).problem) return false;
  }
  for (const [ref] of contentStreams(pdf)) {
    const data = contentOf(pdf, ref);
    if (typeof data === "string" || readContent(data).problem) return false;
  }
  for (const page of pages) {
    const annots = lookupIn(pdf, inherited(pdf, page.node, "Annots"));
    if (!(annots instanceof PDFArray)) continue;
    for (const a of annots.asArray()) {
      const d = lookupIn(pdf, a);
      const ap = d instanceof PDFDict ? lookupIn(pdf, d.get(PDFName.of("AP"))) : undefined;
      let n: unknown = ap instanceof PDFDict ? lookupIn(pdf, ap.get(PDFName.of("N"))) : undefined;
      if (n instanceof PDFDict && !(n instanceof PDFRawStream)) for (const [, v] of n.entries()) { const x = lookupIn(pdf, v); if (x instanceof PDFRawStream && (typeof contentOf(pdf, x) === "string" || readContent(contentOf(pdf, x) as Uint8Array).problem)) return false; }
      else if (n instanceof PDFRawStream) {
        const c = contentOf(pdf, n);
        if (typeof c === "string" || readContent(c).problem) return false;
      }
    }
  }
  return true;
}

/**
 * Optional content as pdf.js showed it to the signer, for every reader, in a document whose content v3 can't read
 * throughout: each /OC and each optional content entry in /Properties points to one layer that is on or one that is
 * off, by pdf.js's decision; an XObject pdf.js hid is emptied; and the document's only layers are those two, with no
 * conditions. Returns whether a value is shown.
 */
function settleOptionalContent(pdf: PDFDocument, places: OcPlace[]): (value: unknown) => boolean {
  const ctx = pdf.context;
  if (!places.length && !pdf.catalog.has(PDFName.of("OCProperties"))) return () => true;
  const shownRef = ctx.register(ctx.obj({ Type: "OCG", Name: PDFString.of("Shown when signed") } as never));
  const hiddenRef = ctx.register(ctx.obj({ Type: "OCG", Name: PDFString.of("Hidden when signed") } as never));
  for (const p of places) {
    p.dict.set(p.key, p.shown ? shownRef : hiddenRef);
    // An XObject pdf.js hid draws nothing in any reader, whether or not the reader knows optional content.
    if (!p.shown && p.ref && p.key.decodeText() === "OC" && ctx.lookup(p.ref) instanceof PDFRawStream) {
      const sub = nameIn(pdf, p.dict.get(PDFName.of("Subtype")));
      if (sub === "Form" || sub === "Image") ctx.assign(p.ref, ctx.flateStream("", { Type: "XObject", Subtype: "Form", BBox: [0, 0, 0, 0], OC: hiddenRef } as never));
    }
  }
  pdf.catalog.set(PDFName.of("OCProperties"), ctx.obj({ OCGs: [shownRef, hiddenRef], D: { Name: PDFString.of("As signed"), BaseState: "ON", OFF: [hiddenRef], Order: [] } } as never));
  return (value: unknown) => !(value instanceof PDFRef && value.objectNumber === hiddenRef.objectNumber);
}

/** How pdf.js maps an appearance's BBox (through its Matrix) onto the annotation's Rect: getTransformMatrix. */
function appearanceTransform(rect: Rect4, bbox: number[], m: number[]): [number, number, number, number, number, number] {
  const [r0, r1, r2, r3] = bbox;
  let a0 = m[0] * r0 + m[4], a2 = a0, a1 = m[0] * r2 + m[4], a3 = a1;
  let b0 = m[3] * r1 + m[5], b2 = b0, b1 = m[3] * r3 + m[5], b3 = b1;
  if (m[1] !== 0 || m[2] !== 0) {
    a0 += m[2] * r1; a3 += m[2] * r1; a1 += m[2] * r3; a2 += m[2] * r3;
    b0 += m[1] * r0; b3 += m[1] * r0; b1 += m[1] * r2; b2 += m[1] * r2;
  }
  // pdf.js keeps the box in 32-bit floats.
  const minX = Math.fround(Math.min(a0, a1, a2, a3)), maxX = Math.fround(Math.max(a0, a1, a2, a3));
  const minY = Math.fround(Math.min(b0, b1, b2, b3)), maxY = Math.fround(Math.max(b0, b1, b2, b3));
  if (minX === maxX || minY === maxY) return [1, 0, 0, 1, rect[0], rect[1]];
  const xr = (rect[2] - rect[0]) / (maxX - minX);
  const yr = (rect[3] - rect[1]) / (maxY - minY);
  return [xr, 0, 0, yr, rect[0] - minX * xr, rect[1] - minY * yr];
}

const QUAD_TYPES = new Set(["Highlight", "Underline", "Squiggly", "StrikeOut"]);
const KNOWN_ANNOTATIONS = new Set(["Link", "Text", "Widget", "Popup", "FreeText", "Line", "Square", "Circle", "PolyLine", "Polygon", "Caret", "Ink", "Highlight", "Underline", "Squiggly", "StrikeOut", "Stamp", "FileAttachment"]);
/** A number array of this length, read through references, or null (pdf.js's isNumberArray). */
function numbers(pdf: PDFDocument, v: unknown, len: number | null): number[] | null {
  const x = lookupIn(pdf, v);
  if (!(x instanceof PDFArray) || (len !== null && x.size() !== len)) return null;
  const out = x.asArray().map((y) => lookupIn(pdf, y));
  return out.every((y) => y instanceof PDFNumber) ? out.map((y) => (y as PDFNumber).asNumber()) : null;
}
/** A number as content streams write it: pdf-lib's own form (no exponent), the same in every engine. */
const numberText = (x: number) => PDFNumber.of(x).toString();

/**
 * An annotation pdf.js prints, with the appearance it draws and where: its own appearance stream, or content pdf.js
 * generates for a form field (drawn with the field's resources, mapped from [0 0 width height] onto its Rect, then
 * turned by its rotation), or a value pdf.js draws with a font of the browser's own (`unencodable`).
 */
type Printed =
  | { appearance: PDFRawStream; rect: Rect4 }
  | { appearance?: undefined; rect: Rect4; generated: { content: string; resources: PDFDict; width: number; height: number; matrix: number[]; exact: boolean; unencodable?: { lines: string[]; fontSize: number; alignment: number; multiline: boolean; comb: boolean } } };

/**
 * The annotations pdf.js prints on a page, in pdf.js's order (others, then widgets): flagged Print, and not Hidden or
 * Invisible (pdf.js ignores Invisible on the types it knows), with valid QuadPoints where their type needs them, in
 * optional content it shows, with an appearance stream (the one /AS names, in a state dictionary). Links and pop-ups
 * print nothing.
 */
function printedAnnotations(pdf: PDFDocument, page: PDFPage, shown: (oc: unknown) => boolean, env: FieldEnv): Printed[] {
  const annots = lookupIn(pdf, inherited(pdf, page.node, "Annots"));
  if (!(annots instanceof PDFArray)) return [];
  const all = annots.asArray().map((x) => lookupIn(pdf, x)).filter((a): a is PDFDict => a instanceof PDFDict);
  const kind = (a: PDFDict) => nameIn(pdf, a.get(PDFName.of("Subtype")));
  const ordered = [...all.filter((a) => kind(a) !== "Widget" && kind(a) !== "Popup"), ...all.filter((a) => kind(a) === "Widget"), ...all.filter((a) => kind(a) === "Popup")];
  const out: Printed[] = [];
  for (const a of ordered) {
    const subtype = kind(a);
    // pdf.js draws a pop-up with its parent's flags and no canvas of its own when printing: it draws none here.
    if (subtype === "Popup" || subtype === "Link") continue;
    const f = lookupIn(pdf, a.get(PDFName.of("F")));
    let flags = f instanceof PDFNumber && Number.isInteger(f.asNumber()) && f.asNumber() > 0 ? f.asNumber() : 0;
    if (flags & 1 && subtype !== null && KNOWN_ANNOTATIONS.has(subtype)) flags ^= 1;
    if (subtype && QUAD_TYPES.has(subtype)) {
      const q = numbers(pdf, a.get(PDFName.of("QuadPoints")), null);
      if (!q || q.length === 0 || q.length % 8) continue;
    }
    // pdf.js prints an annotation flagged Print, and not Hidden or Invisible, in optional content it shows.
    if (flags === 0 || !(flags & 4) || flags & 2 || flags & 1) continue;
    const oc = a.get(PDFName.of("OC"));
    if (oc !== undefined && !shown(oc)) continue;
    const r = numbers(pdf, a.get(PDFName.of("Rect")), 4) ?? [0, 0, 0, 0];
    const rect: Rect4 = [Math.min(r[0], r[2]), Math.min(r[1], r[3]), Math.max(r[0], r[2]), Math.max(r[1], r[3])];
    if (subtype === "Widget") {
      // A form field: what pdf.js draws for it (fields-v3.ts), its own appearance or one pdf.js generates.
      let d: ReturnType<typeof fieldDrawing>;
      try {
        d = fieldDrawing(pdf, a, env);
      } catch (e) {
        if (resourceError(e)) throw e;
        d = { kind: "none" };
      }
      if (d.kind === "stored") out.push({ appearance: d.stream, rect });
      else if (d.kind === "default-checked") {
        const resources = pdf.context.obj({ Font: { PdfJsZaDb: pdf.context.obj({ Type: "Font", Subtype: "Type1", BaseFont: "ZapfDingbats" } as never) } } as never) as unknown as PDFDict;
        out.push({ rect, generated: { content: d.content, resources, width: d.width, height: d.height, matrix: [1, 0, 0, 1, 0, 0], exact: true } });
      } else if (d.kind === "generated") {
        let resources = d.resources;
        if (d.fallbackFont) {
          // pdf.js draws with its fallback Helvetica when the DA's font isn't there: the copy names the same font.
          resources = d.resources.clone(pdf.context);
          const fonts = lookupIn(pdf, resources.get(PDFName.of("Font")));
          const f = fonts instanceof PDFDict ? fonts.clone(pdf.context) : (pdf.context.obj({}) as PDFDict);
          f.set(PDFName.of(d.fallbackFont), pdf.context.obj(FALLBACK_FONT as never));
          resources.set(PDFName.of("Font"), f);
        }
        out.push({ rect, generated: { content: d.content, resources, width: d.width, height: d.height, matrix: d.matrix, exact: d.exact, unencodable: d.unencodable } });
      }
      continue;
    }
    const ap = lookupIn(pdf, a.get(PDFName.of("AP")));
    let appearance: unknown = ap instanceof PDFDict ? lookupIn(pdf, ap.get(PDFName.of("N"))) : undefined;
    if (appearance instanceof PDFDict) {
      const as = lookupIn(pdf, a.get(PDFName.of("AS")));
      appearance = as instanceof PDFName && appearance.has(as) ? lookupIn(pdf, appearance.get(as)) : undefined;
    }
    if (appearance instanceof PDFRawStream) out.push({ appearance, rect });
  }
  return out;
}

/**
 * Annotations pdf.js prints, drawn as page content after the page's own: each appearance a form XObject added to
 * `xobjects` (closed off, with what pdf.js hid taken out where v3 took it out), mapped from its BBox through its Matrix
 * onto its Rect as pdf.js maps it, and clipped to its Rect. A field's generated appearance is drawn the same way, from
 * [0 0 width height] onto its Rect and turned by its rotation, with the field's resources.
 */
function drawAnnotations(pdf: PDFDocument, printed: Printed[], xobjects: PDFDict, rewritten: Map<PDFRawStream, Uint8Array>, notoFields: Map<Printed, { content: string; resources: PDFDict }>): string {
  const ctx = pdf.context;
  let out = "";
  const nums = (xs: number[]) => xs.map((x) => numberText(x)).join(" ");
  for (const item of printed) {
    const { rect } = item;
    const w = rect[2] - rect[0], h = rect[3] - rect[1];
    const k = xobjects.keys().length;
    if (!item.appearance) {
      const g = item.generated;
      const noto = notoFields.get(item);
      const content = noto ? noto.content : g.content;
      const form = ctx.flateStream(Uint8Array.from(content, (c) => c.charCodeAt(0) & 0xff), { Type: "XObject", Subtype: "Form", BBox: [-1e9, -1e9, 1e9, 1e9] } as never);
      form.dict.set(PDFName.of("Resources"), noto ? noto.resources : g.resources);
      xobjects.set(PDFName.of(`AttestAnnot${k}`), ctx.register(form));
      const t = appearanceTransform(rect, [0, 0, g.width, g.height], [1, 0, 0, 1, 0, 0]);
      out += `q ${nums([rect[0], rect[1], w, h])} re W n ${nums(t)} cm ${nums(g.matrix)} cm /AttestAnnot${k} Do Q\n`;
      continue;
    }
    const appearance = item.appearance;
    const bbox = numbers(pdf, appearance.dict.get(PDFName.of("BBox")), 4) ?? [0, 0, w, h];
    const matrix = numbers(pdf, appearance.dict.get(PDFName.of("Matrix")), 6) ?? [1, 0, 0, 1, 0, 0];
    const t = appearanceTransform(rect, bbox, matrix);
    const resources = lookupIn(pdf, appearance.dict.get(PDFName.of("Resources")));
    const form = closedOffStream(pdf, appearance, { Type: "XObject", Subtype: "Form", BBox: [-1e9, -1e9, 1e9, 1e9], Resources: resources instanceof PDFDict ? resources : {} }, rewritten.get(appearance));
    form.dict.delete(PDFName.of("Matrix"));
    form.dict.delete(PDFName.of("OC"));
    xobjects.set(PDFName.of(`AttestAnnot${k}`), ctx.register(form));
    out += `q ${nums([rect[0], rect[1], w, h])} re W n ${nums(t)} cm ${nums(matrix)} cm /AttestAnnot${k} Do Q\n`;
  }
  return out;
}

/**
 * A value pdf.js draws with a font of the browser's own (the field's font can't encode it): drawn here with Noto Sans,
 * embedded, laid out as pdf.js lays out a value (its size, or one fitted to the field; aligned; over lines for a
 * multiline field). Not what the signer's browser drew, glyph for glyph: the document isn't clean, and its copy says so.
 */
function notoFieldContent(pdf: PDFDocument, g: Extract<Printed, { generated: unknown }>["generated"], font: PDFFont): { content: string; resources: PDFDict } {
  const u = g.unencodable!;
  let totalWidth = g.width, totalHeight = g.height;
  if (g.matrix[1] !== 0) [totalWidth, totalHeight] = [totalHeight, totalWidth];
  const text = (s: string) => printable(s);
  const widthOf = (s: string, size: number) => font.widthOfTextAtSize(text(s), size);
  let fontSize = u.fontSize;
  const lines = u.lines.map(text);
  if (!fontSize) {
    const longest = lines.reduce((m, l) => Math.max(m, widthOf(l, 1)), 0);
    fontSize = Math.floor(Math.min((totalHeight - 2) / (u.multiline ? 1.35 * Math.max(lines.length, 1) : 1.35), longest ? (totalWidth - 4) / longest : Infinity) * 100) / 100;
  }
  const ops: string[] = ["/Tx BMC q BT", `/AttestNotoField ${pdfjsNumber(fontSize)} Tf 0 g`];
  const place = (line: string, y: number) => {
    const lw = widthOf(line, fontSize);
    const x = u.alignment === 1 ? (totalWidth - lw) / 2 : u.alignment === 2 ? totalWidth - lw - 2 : 2;
    ops.push(`1 0 0 1 ${pdfjsNumber(x)} ${pdfjsNumber(y)} Tm ${font.encodeText(line).toString()} Tj`);
  };
  if (u.multiline) {
    const lineHeight = fontSize * 1.35;
    let y = totalHeight - 1 - fontSize;
    for (const line of lines) {
      place(line, y);
      y -= lineHeight;
    }
  } else place(lines[0] ?? "", (totalHeight - 1.35 * fontSize) / 2 + 0.35 * fontSize);
  ops.push("ET Q EMC");
  const resources = g.resources.clone(pdf.context);
  const fonts = lookupIn(pdf, resources.get(PDFName.of("Font")));
  const f = fonts instanceof PDFDict ? fonts.clone(pdf.context) : (pdf.context.obj({}) as PDFDict);
  f.set(PDFName.of("AttestNotoField"), font.ref);
  resources.set(PDFName.of("Font"), f);
  return { content: ops.join("\n"), resources };
}

/**
 * A page of a document that isn't clean: its content as one form XObject (closed off where v3 can read it, with what
 * pdf.js hid taken out where v3 took it out, kept as it was where v3 can't read it), then the annotations pdf.js prints,
 * drawn as page content. No annotation is left on the page.
 */
function protectPage(pdf: PDFDocument, page: PDFPage, media: Rect4, printed: Printed[], pageContent: Uint8Array | undefined, rewritten: Map<PDFRawStream, Uint8Array>, notoFields: Map<Printed, { content: string; resources: PDFDict }>) {
  const ctx = pdf.context;
  const node = page.node;
  const resources = inherited(pdf, node, "Resources");
  const res = resources instanceof PDFDict ? resources : ctx.obj({});
  const raw = lookupIn(pdf, node.get(PDFName.of("Contents")));
  const parts = raw === undefined ? [] : raw instanceof PDFArray ? raw.asArray() : [raw];
  const decoded = parts.map((p) => contentOf(pdf, p));
  const xobjects = ctx.obj({});
  let content = "";
  if (decoded.every((d): d is Uint8Array => typeof d !== "string")) {
    // The page's streams joined as pdf.js joins them, and closed off if v3 can read them to the end.
    const data = pageContent ?? joined(decoded);
    const state = readContent(data);
    const body = state.problem ? data : needsClosing(state) ? closedOff(data, state) : data;
    xobjects.set(PDFName.of("AttestPage"), ctx.register(ctx.flateStream(body, { Type: "XObject", Subtype: "Form", BBox: media, Resources: res } as never)));
    content = "q /AttestPage Do Q\n";
  } else {
    // A stream v3 can't decode is kept as it was (its bytes and its filters), each stream in a form of its own.
    for (const [k, p] of parts.entries()) {
      const s = lookupIn(pdf, p);
      if (!(s instanceof PDFRawStream)) continue;
      const form = PDFRawStream.of(ctx.obj({}), s.contents);
      for (const [key, v] of s.dict.entries()) if (["Filter", "DecodeParms", "DL"].includes(key.decodeText())) form.dict.set(key, v);
      for (const [key, v] of Object.entries({ Type: "XObject", Subtype: "Form", BBox: media })) form.dict.set(PDFName.of(key), ctx.obj(v as never));
      form.dict.set(PDFName.of("Resources"), res);
      form.dict.set(PDFName.of("Length"), PDFNumber.of(s.contents.length));
      xobjects.set(PDFName.of(`AttestPage${k}`), ctx.register(form));
      content += `q /AttestPage${k} Do Q\n`;
    }
  }
  content += drawAnnotations(pdf, printed, xobjects, rewritten, notoFields);
  node.set(PDFName.of("Resources"), ctx.obj({ XObject: xobjects }));
  node.set(PDFName.of("Contents"), ctx.register(ctx.flateStream(content)));
  for (let d: unknown = node, seen = 0; d instanceof PDFDict && seen < 64; d = lookupIn(pdf, d.get(PDFName.of("Parent"))), seen++) d.delete(PDFName.of("Annots"));
}

/**
 * Every page of a document that isn't clean, protected (the pages' boxes found before anything changes). Optional
 * content: taken out of the copy, with what pdf.js hid taken out first, whenever v3 can read throughout the content
 * pdf.js runs; otherwise (content v3 keeps as it was, in a document whose optional content pdf.js hides) given to every
 * reader as pdf.js decided it, in two layers.
 */
async function protectDocument(pdf: PDFDocument, pages: PDFPage[], media: Rect4[], noto: () => Promise<PDFFont>, env: FieldEnv) {
  const visible = pdfjsOptionalContent(pdf);
  const places = optionalContentPlaces(pdf, visible);
  // Values pdf.js draws with a font of the browser's own, drawn here with Noto Sans.
  const notoFieldsOf = async (printed: Printed[][]) => {
    const out = new Map<Printed, { content: string; resources: PDFDict }>();
    for (const item of printed.flat()) if (!item.appearance && item.generated.unencodable) out.set(item, notoFieldContent(pdf, item.generated, await noto()));
    return out;
  };
  if (places.some((p) => !p.shown) && !readableThroughout(pdf, pages)) {
    const shown = settleOptionalContent(pdf, places);
    const none = new Map<PDFRawStream, Uint8Array>();
    closeOffContentStreams(pdf, none);
    const printed = pages.map((p) => printedAnnotations(pdf, p, shown, env));
    const notoFields = await notoFieldsOf(printed);
    for (const [i, p] of pages.entries()) protectPage(pdf, p, media[i], printed[i], undefined, none, notoFields);
    return;
  }
  const printed = pages.map((p) => printedAnnotations(pdf, p, visible, env));
  const done = withoutOptionalContent(pdf, pages, places, visible, printed);
  closeOffContentStreams(pdf, done.rewritten);
  const notoFields = await notoFieldsOf(printed);
  for (const [i, p] of pages.entries()) protectPage(pdf, p, media[i], printed[i], done.pageContent.get(p), done.rewritten, notoFields);
}

/** An error from the engine running out of room, not from the document: never turned into a different copy. */
const resourceError = (e: unknown) => /Maximum call stack|too much recursion|allocation failed|out of memory/i.test(String((e as Error)?.message ?? e));

// ---- Drawing -----------------------------------------------------------------------------------------

const INK = rgb(0.039, 0.145, 0.251);
const BODY = rgb(0.258, 0.329, 0.4);
const MUTED = rgb(0.412, 0.451, 0.525);
const HAIR = rgb(0.89, 0.91, 0.933);
const ACCENT = rgb(0.31, 0.275, 0.898);
const NAVY = rgb(0.027, 0.071, 0.169);
const SUCCESS = rgb(0.063, 0.725, 0.506);
const STAMP = rgb(0.086, 0.247, 0.553);

/** A QR code as vector squares (no canvas, no image encoder: the same bytes everywhere). */
function drawQr(page: PDFPage, text: string, x: number, y: number, size: number, color = INK) {
  const qr = QRCode.create(text, { errorCorrectionLevel: "M" });
  const n = qr.modules.size;
  const m = size / n;
  let d = "";
  for (let r = 0; r < n; r++) {
    for (let c = 0; c < n; c++) {
      if (!qr.modules.get(r, c)) continue;
      const px = c * m;
      const py = r * m;
      d += `M${px.toFixed(3)},${py.toFixed(3)} h${m.toFixed(3)} v${m.toFixed(3)} h${(-m).toFixed(3)} Z `;
    }
  }
  page.drawSvgPath(d, { x, y: y + size, color });
}

/** Text along any angle, positioned with this file's own sine (pdf-lib's rotation uses Math.sin). */
function drawRotated(page: PDFPage, text: string, font: PDFFont, size: number, x: number, y: number, angle: number, color = ACCENT) {
  page.setFont(font);
  const key = (page as unknown as { fontKey: PDFName }).fontKey;
  const c = dcos(angle);
  const s = dsin(angle);
  page.pushOperators(
    pushGraphicsState(),
    setFillingRgbColor(color.red, color.green, color.blue),
    beginText(),
    setFontAndSize(key, size),
    setTextMatrix(c, s, -s, c, x, y),
    showText(font.encodeText(text)),
    endText(),
    popGraphicsState(),
  );
}

/** Whether a standard font can set this text (Helvetica's encoding is WinAnsi). */
function encodes(font: PDFFont, value: string): boolean {
  try {
    font.encodeText(value);
    return true;
  } catch {
    return false;
  }
}

function wrap(text: string, font: PDFFont, size: number, width: number): string[] {
  const out: string[] = [];
  let line = "";
  for (const word of text.split(" ")) {
    const next = line ? `${line} ${word}` : word;
    if (font.widthOfTextAtSize(next, size) > width && line) {
      out.push(line);
      line = word;
    } else line = next;
  }
  if (line) out.push(line);
  return out;
}
const chunk = (s: string, n: number) => Array.from({ length: Math.ceil(s.length / n) }, (_, i) => s.slice(i * n, i * n + n));

/**
 * Text people typed, on one line: a line break of any kind (\n, \r, U+2028, U+2029, U+0085, \v, \f) would start a new
 * line below wherever it's drawn, so each run of them is one space.
 */
const oneLine = (s: string) => s.replace(/[\n\r\u2028\u2029\u0085\u000b\u000c]+/g, " ");

/**
 * Text people typed, as v3 prints it: on one line, composed (NFC), and each character it can't print (charset-v3.ts)
 * shown as U+FFFD, so no reader ever draws a missing glyph. A composed character v3 has no glyph for is drawn as its
 * parts, when it has those.
 */
function printable(s: string): string {
  let out = "";
  for (const ch of oneLine(s).normalize("NFC")) {
    if (printableV3(ch.codePointAt(0)!)) out += ch;
    else {
      const parts = ch.normalize("NFD");
      out += [...parts].every((c) => printableV3(c.codePointAt(0)!)) ? parts : "\uFFFD";
    }
  }
  return out;
}

/** Whether a font has a glyph for every character of a text. */
const covers = (font: PDFFont, text: string) => {
  const set = new Set(font.getCharacterSet());
  return [...text].every((ch) => set.has(ch.codePointAt(0)!));
};

/** Noto Sans, embedded once and only when some text needs it. */
function notoFonts(pdf: PDFDocument, input: RenderInputV3) {
  let regular: PDFFont | null = null;
  let bold: PDFFont | null = null;
  const embed = async (bytes: Uint8Array | undefined) => {
    if (!bytes) throw new Error("Renderer v3 needs Noto Sans (fonts.noto and fonts.notoBold)");
    pdf.registerFontkit(fontkit);
    return pdf.embedFont(bytes, { subset: true });
  };
  return {
    regular: async () => (regular ??= await embed(input.fonts.noto)),
    bold: async () => (bold ??= await embed(input.fonts.notoBold)),
  };
}
type Noto = ReturnType<typeof notoFonts>;

type Box = { x: number; y: number; w: number; h: number };
const clampTo = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v));

/** A signature or initials as drawn: an image and the part of it that carries ink, or a name set in type. */
type Mark = { image: PDFImage; ink: Box } | { name: string; font: PDFFont };

/**
 * The part of a signature image that carries ink, in its pixels from the top-left: the pad and the typed styles leave
 * empty margins, which would take room from the signature in a small field. Read from the pixels pdf-lib decoded to
 * embed the image (integers only, so the same in every engine); the whole image when no pixel carries ink.
 */
function markOf(image: PDFImage): Mark {
  const whole = { x: 0, y: 0, w: image.width, h: image.height };
  const png = (image as unknown as { embedder?: { image?: { width: number; height: number; alphaChannel?: Uint8Array; rgbChannel?: Uint8Array } } }).embedder?.image;
  if (!png || png.width !== image.width || png.height !== image.height) return { image, ink: whole };
  const { width: W, height: H, alphaChannel: alpha, rgbChannel: color } = png;
  // Ink: a pixel at least an eighth opaque or, in an image with no transparency, darker than light gray.
  const inked = alpha ? (i: number) => alpha[i] >= 32 : color ? (i: number) => Math.min(color[3 * i], color[3 * i + 1], color[3 * i + 2]) < 224 : null;
  if (!inked) return { image, ink: whole };
  let x0 = W, y0 = H, x1 = -1, y1 = -1;
  for (let y = 0; y < H; y++) {
    for (let x = 0; x < W; x++) {
      if (!inked(y * W + x)) continue;
      if (x < x0) x0 = x;
      if (x > x1) x1 = x;
      if (y < y0) y0 = y;
      if (y > y1) y1 = y;
    }
  }
  return { image, ink: x1 < 0 ? whole : { x: x0, y: y0, w: x1 - x0 + 1, h: y1 - y0 + 1 } };
}

/** The size a signature or initials takes in an area: as large as fits, keeping its proportions. */
function markSize(mark: Mark, area: Box): { w: number; h: number } {
  if (!(area.w > 0 && area.h > 0)) return { w: 0, h: 0 };
  if ("name" in mark) {
    const size = Math.min(14, area.h * 0.8, area.w / Math.max(mark.font.widthOfTextAtSize(mark.name, 1), 0.001));
    return { w: mark.font.widthOfTextAtSize(mark.name, size), h: size };
  }
  const scale = Math.min(area.w / mark.ink.w, area.h / mark.ink.h);
  return { w: mark.ink.w * scale, h: mark.ink.h * scale };
}

/** A signature or initials, as large as fits in the area, centered in its height; nothing of it shows outside `bounds`. */
function drawMark(page: PDFPage, mark: Mark, area: Box, bounds: Box, center: boolean) {
  const { w, h } = markSize(mark, area);
  if (!(w > 0 && h > 0)) return;
  const x = area.x + (center ? (area.w - w) / 2 : 0);
  if ("name" in mark) {
    page.drawText(mark.name, { x, y: area.y + (area.h - h) / 2 + h * 0.22, size: h, font: mark.font, color: INK });
    return;
  }
  const { image, ink } = mark;
  const scale = w / ink.w;
  const y = area.y + (area.h - h) / 2;
  // The image's empty margins reach past the area: it is clipped to the stamp, so nothing shows outside the field.
  page.pushOperators(pushGraphicsState(), rectangle(bounds.x, bounds.y, bounds.w, bounds.h), clip(), endPath());
  page.drawImage(image, { x: x - ink.x * scale, y: y - (image.height - ink.y - ink.h) * scale, width: image.width * scale, height: image.height * scale });
  page.pushOperators(popGraphicsState());
}

/** The stamp's own text: at most this size, and at least this, or the line is left out (every page's foot carries the code). */
const STAMP_TEXT = { max: 5, min: 4, leading: 1.22 };
/**
 * The QR code: at most this tall, and this share of the field's width; under the minimum, which a phone scans reliably
 * from a page printed at 300 dpi (0.22 mm modules), it's left out.
 */
const STAMP_QR = { max: 24, share: 0.22, min: 18 };

/** Where a stamp's parts go: its text (its lines, their size, left edge and middle), the signature's area, and the QR code. */
interface StampPlan { lines: string[]; fs: number; tx: number; mid: number; area: Box; center: boolean; qr: Box | null }

/**
 * The "Signed with Attest" stamp, entirely inside the field the sender placed: a bracket, the signature (an image, or
 * the signer's name), the label, the verification code and the signing day, and a QR code to the certificate. Initials
 * get an "Attest" stamp with the code, and no day or QR code.
 *
 * Everything keeps clear of the field's edges: a tenth of its height (at most 3 points) above and below, and 3% of its
 * width (at most 3 points) at the sides. Everything sits in a band along the bottom of what is left, as a signature
 * sits on its line, which leaves free the top 28% (at most 9 points), where a label above the field often reaches into
 * it. The QR code is centered on the band, at most 24 points and 22% of the field's width, so it never dominates the
 * field; one under 18 points, too fine to scan reliably from a printed page, is left out.
 *
 * Side by side, the signature comes first, then the text, then the QR code. In a field too tall for that, the text and
 * the QR code go above the signature, when that keeps the QR code (when side by side does), and more of the text with
 * the signature at least 80% as large, or the same text with the signature a quarter larger. The text is as large as fits, at most 5 points and within 40% of the
 * room beside the QR code (initials: 60% of the field); a field too small for it at 4 points leaves out the label, then
 * the day, then the code, so no line is ever smaller, and the foot of every page carries the code with the link to
 * verify.
 */
function drawStamp(page: PDFPage, box: Box, mark: Mark, o: { initials: boolean; code: string | null; signedAt: string | null; qrUrl: string | null; font: PDFFont; bold: PDFFont }) {
  if (!(box.w > 0 && box.h > 0)) return;
  const sign = !o.initials;
  const ex = Math.min(clampTo(box.w * 0.03, 0.5, 3), box.w / 6);
  const ey = Math.min(clampTo(box.h * 0.1, 0.5, 3), box.h / 6);
  const r = { x: box.x + ex, y: box.y + ey, w: box.w - 2 * ex, h: box.h - 2 * ey };
  const band = { y: r.y, h: r.h - Math.min(r.h * 0.28, 9) };
  const thick = clampTo(box.h * 0.025, 0.4, 0.75);
  const tick = clampTo(band.h * 0.15, 1.2, 3.5);
  const inset = tick + Math.max(1, thick * 2);
  // The text: the label, the code and the day, leaving out lines until it fits at 4 points or more.
  const label = sign ? "Signed with Attest" : "Attest";
  const code = o.code ? fmtCode(o.code) : null;
  const day = sign && o.signedAt ? `${fmtDay(o.signedAt)} UTC` : null;
  const fontOf = (t: string) => (t === label ? o.bold : o.font);
  const widest = (ls: string[], size: number) => Math.max(0, ...ls.map((t) => fontOf(t).widthOfTextAtSize(t, size)));
  const sets = [[label, code, day], [code, day], [code]].map((ls) => ls.filter((t): t is string => Boolean(t))).filter((ls) => ls.length);
  const text = (h: number, w: number) => {
    for (const ls of sets) {
      // From the first line's capitals to the last one's descenders: (n - 1) leadings, a cap height and a descender.
      const fs = Math.min(STAMP_TEXT.max, h / ((ls.length - 1) * STAMP_TEXT.leading + 0.93), w / widest(ls, 1));
      if (fs >= STAMP_TEXT.min) return { lines: ls, fs };
    }
    return { lines: [] as string[], fs: 0 };
  };
  const qrGap = (q: number) => (q ? q + Math.max(2, q * 0.1) : 0);
  // The QR code fits in the given height, never dominates the field, and is left out when too fine for a phone's camera.
  const qrIn = (h: number) => {
    const q = sign && o.qrUrl ? Math.min(h, r.w * STAMP_QR.share, STAMP_QR.max) : 0;
    return q >= STAMP_QR.min ? q : 0;
  };
  // Side by side: the signature, the text, and the QR code, all in the band.
  const side = (): StampPlan => {
    const q = qrIn(band.h);
    const left = r.w - qrGap(q);
    let t = text(band.h, left * (sign ? 0.4 : 0.6));
    // The signature always keeps room: in a field too narrow for both, the text is left out.
    if (left - widest(t.lines, t.fs) - Math.max(2, t.fs) - inset < Math.max(left * 0.2, 4)) t = { lines: [], fs: 0 };
    const tw = widest(t.lines, t.fs);
    const gap = t.lines.length ? Math.max(2, t.fs) : 0;
    const area = { x: r.x + inset, y: band.y + thick, w: left - tw - gap - inset, h: band.h - 2 * thick };
    return { ...t, tx: r.x + left - tw, mid: band.y + band.h / 2, area, center: !sign, qr: q ? { x: r.x + r.w - q, y: band.y + (band.h - q) / 2, w: q, h: q } : null };
  };
  // Stacked: the text and the QR code above, the signature below.
  const stack = (): StampPlan => {
    const lower = band.h * 0.55;
    const gapV = Math.max(1.5, band.h * 0.05);
    const upper = band.h - lower - gapV;
    const q = qrIn(upper);
    const t = text(upper, r.w - inset - qrGap(q));
    const mid = band.y + lower + gapV + upper / 2;
    const area = { x: r.x + inset, y: band.y + thick, w: r.w - inset, h: lower - thick };
    return { ...t, tx: r.x + inset, mid, area, center: !sign, qr: q ? { x: r.x + r.w - q, y: mid - q / 2, w: q, h: q } : null };
  };
  const a = side();
  const b = stack();
  // Stacked when that keeps the QR code (if side by side does) and more of the text with the signature at least 80% as
  // large, or the same text (no smaller) with the signature a quarter larger.
  const [ma, mb] = [markSize(mark, a.area).h, markSize(mark, b.area).h];
  const keepsQr = Boolean(b.qr) || !a.qr;
  const plan = keepsQr && ((b.lines.length > a.lines.length && mb >= ma * 0.8) || (b.lines.length === a.lines.length && b.fs >= a.fs * 0.9 && mb > ma * 1.25)) ? b : a;
  // The bracket, along the band.
  const line = (x1: number, y1: number, x2: number, y2: number) => page.drawLine({ start: { x: x1, y: y1 }, end: { x: x2, y: y2 }, thickness: thick, color: STAMP });
  const bx = r.x + thick / 2;
  const [b0, b1] = [band.y + thick / 2, band.y + band.h - thick / 2];
  line(bx, b0, bx, b1);
  line(bx, b1, bx + tick, b1);
  line(bx, b0, bx + tick, b0);
  drawMark(page, mark, plan.area, r, plan.center);
  // The lines centered on `mid`, from the first one's capitals to the last one's descenders.
  let base = plan.mid + ((plan.lines.length - 1) * plan.fs * STAMP_TEXT.leading + plan.fs * 0.93) / 2 - plan.fs * 0.72;
  for (const t of plan.lines) {
    page.drawText(t, { x: plan.tx, y: base, size: plan.fs, font: fontOf(t), color: STAMP });
    base -= plan.fs * STAMP_TEXT.leading;
  }
  if (plan.qr) drawQr(page, o.qrUrl!, plan.qr.x, plan.qr.y, plan.qr.w, STAMP);
}

/**
 * A text entry inside its field: on one line at up to 12 points (70% of the field's height, if smaller), or wrapped
 * onto more lines when that sets it larger, and never wider or taller than the field.
 */
function drawEntry(page: PDFPage, value: string, box: Box, font: PDFFont) {
  const w = box.w - 2;
  if (!(w > 0 && box.h > 0)) return;
  const lead = 1.15;
  const top = Math.min(12, box.h * 0.7);
  let size = Math.min(top, w / Math.max(font.widthOfTextAtSize(value, 1), 0.001));
  let lines = [value];
  if (size < 5 && value.includes(" ")) {
    for (let s = top; s > size; s -= 0.25) {
      const ls = wrap(value, font, s, w);
      if (ls.length > 1 && ls.length * s * lead <= box.h * 0.85 && ls.every((l) => font.widthOfTextAtSize(l, s) <= w)) {
        size = s;
        lines = ls;
        break;
      }
    }
  }
  let base = box.y + (box.h - size) / 2 + size * 0.22 + ((lines.length - 1) * size * lead) / 2;
  for (const l of lines) {
    page.drawText(l, { x: box.x + 1, y: base, size, font, color: INK });
    base -= size * lead;
  }
}

/** Woven sine waves across a band: the guilloche of banknotes and diplomas. */
function guilloche(page: PDFPage, x: number, y: number, w: number, h: number, lines = 18, opacity = 0.16) {
  for (let i = 0; i < lines; i++) {
    const phase = (i / lines) * PI * 2;
    const amp = h * (0.18 + 0.22 * dsin(phase * 1.7));
    let d = "";
    for (let t = 0; t <= 160; t++) {
      const px = (t / 160) * w;
      const py = h / 2 + amp * dsin((px / w) * PI * 6 + phase) + h * 0.08 * dsin((px / w) * PI * 23 + phase * 2);
      d += `${t === 0 ? "M" : "L"}${px.toFixed(2)},${(h - py).toFixed(2)} `;
    }
    page.drawSvgPath(d, { x, y: y + h, borderColor: ACCENT, borderWidth: 0.35, borderOpacity: opacity });
  }
}

/** The Attest seal: rosette rings, a ring of text, and a check at the center. */
function seal(page: PDFPage, bold: PDFFont, cx: number, cy: number, r: number) {
  page.drawCircle({ x: cx, y: cy, size: r, borderColor: ACCENT, borderWidth: 1.2, color: rgb(1, 1, 1) });
  page.drawCircle({ x: cx, y: cy, size: r - 3.5, borderColor: ACCENT, borderWidth: 0.4 });
  for (let k = 0; k < 6; k++) {
    let d = "";
    for (let t = 0; t <= 360; t++) {
      const th = (t / 360) * PI * 2;
      const rr = r * 0.6 + r * 0.09 * dsin(th * 18 + (k * PI) / 3);
      d += `${t === 0 ? "M" : "L"}${(rr * dcos(th)).toFixed(2)},${(-rr * dsin(th)).toFixed(2)} `;
    }
    page.drawSvgPath(d, { x: cx, y: cy, borderColor: ACCENT, borderWidth: 0.3, borderOpacity: 0.55 });
  }
  page.drawCircle({ x: cx, y: cy, size: r * 0.42, color: ACCENT });
  page.drawSvgPath(`M ${(-r * 0.17).toFixed(2)} 0 L ${(-r * 0.05).toFixed(2)} ${(r * 0.12).toFixed(2)} L ${(r * 0.19).toFixed(2)} ${(-r * 0.13).toFixed(2)}`, { x: cx, y: cy, borderColor: rgb(1, 1, 1), borderWidth: 2.2 });
  const text = "SEALED BY DATAHUBZ ATTEST  ·  ANCHORED ON HORIZEN  ·  PROVEN ON ZKVERIFY  ·  ";
  const size = r * 0.105;
  const rr = r - 9.5;
  const widths = [...text].map((ch) => bold.widthOfTextAtSize(ch, size));
  const extra = (2 * PI * rr - widths.reduce((a, b) => a + b, 0)) / widths.length;
  let angle = PI / 2;
  [...text].forEach((ch, k) => {
    if (ch.trim()) drawRotated(page, ch, bold, size, cx + rr * dcos(angle), cy + rr * dsin(angle), angle - PI / 2);
    angle -= (widths[k] + extra) / rr;
  });
}

const EVENT_TEXT: Record<string, (who: string) => string> = {
  created: () => "Created by the sender",
  sent: () => "Sent for signature",
  viewed: (w) => `Opened by ${w}`,
  key_ready: (w) => `${w} set up their key`,
  access_granted: (w) => `Document released to ${w}, end-to-end encrypted`,
  signed: (w) => `Signed by ${w} with a passkey only they control`,
  declined: (w) => `Declined by ${w}`,
  reminded: (w) => `Reminder sent to ${w}`,
  completed: () => "Completed: every party signed; the record was anchored",
};

// ---- The signed copy -----------------------------------------------------------------------------------

/** The visible pages of a v3 signed copy: the original with each entry and stamp, then (full) the certificate pages. */
export async function renderV3(input: RenderInputV3): Promise<Uint8Array> {
  if (input.variant === "certificate") return certificateV3(input);
  if (!input.original) throw new Error("The original document is needed to make the signed pages");
  if (input.variant === "full" && !input.trail) throw new Error("The audit trail is needed for the certificate pages");
  // Every document gets a copy. One whose pages can't be reproduced at all (a file that can't be read or decrypted)
  // gets a copy whose first page says so; only an engine running out of room throws.
  try {
    return await signedPages(input, input.original);
  } catch (e) {
    if (resourceError(e)) throw e;
    return unreproducedPages(input, unreadableKind(e));
  }
}

/** The signed pages of the document (and, for the full copy, the certificate pages). */
async function signedPages(input: RenderInputV3, original: Uint8Array): Promise<Uint8Array> {
  const pdf = await openOriginalV3(original);
  if (!(pdf.catalog instanceof PDFDict)) throw new Error("A PDF without a catalog");
  deterministic(pdf);
  // Clean or not, checked as it arrived: a clean document is drawn as it is; one that isn't gets the best protection
  // v3 can give, and the note.
  let clean: boolean;
  try {
    clean = documentProblems(pdf).length === 0;
  } catch (e) {
    if (resourceError(e)) throw e;
    clean = false;
  }
  // What the form fields need (NeedAppearances, the XFA dataset), read before active content goes (XFA among it).
  const fields = clean ? null : fieldEnv(pdf, (st) => {
    const c = contentOf(pdf, st);
    return typeof c === "string" ? null : c;
  });
  stripActiveContent(pdf);
  const { agreement: a, details: d } = input;
  const code = d.verifyCode;
  const certUrl = code ? `${input.appUrl}/v/${fmtCode(code)}` : `${input.appUrl}/a/${a.id}`;
  const signer = new Map(input.signers.map((s) => [s.commitment, s]));
  const text = await pdf.embedFont(StandardFonts.Helvetica);
  const textBold = await pdf.embedFont(StandardFonts.HelveticaBold);
  const noto = notoFonts(pdf, input);

  // Each page's own content, kept to itself; what Attest draws goes on top, on the page as it is shown, in points from
  // its bottom-left.
  const pages = pdf.getPages();
  if (!pages.length) throw new Error("A PDF without pages");
  const shown = pages.map((p) => shownPage(pdf, p));
  if (clean) for (const [i, p] of pages.entries()) isolatePage(pdf, p, shown[i].media);
  else await protectDocument(pdf, pages, shown.map((x) => x.media), noto.regular, fields!);
  // No form fields in the copy: a clean document had none to show, and the rest were drawn into their pages.
  pdf.catalog.delete(PDFName.of("AcroForm"));
  for (const [i, p] of pages.entries()) p.pushOperators(pushGraphicsState(), concatTransformationMatrix(...shown[i].m));
  // Each entry where its signer made it (positions are fractions of the shown page from its top-left), each signature
  // in its stamp.
  const adopted = new Map<string, string>();
  for (const [id, type, pageIndex, fx, fy, fw, fh, who] of d.fields) {
    const raw = input.entries[id];
    const page = pages[pageIndex];
    if (!raw || !page) continue;
    const image = raw.startsWith("data:image/png;base64,");
    const value = image ? raw : printable(raw);
    const { width, height } = shown[pageIndex];
    const box = { x: fx * width, y: height - (fy + fh) * height, w: fw * width, h: fh * height };
    if (type === "signature" || type === "initials") {
      if (type === "signature" && image && !adopted.has(who)) adopted.set(who, value);
      // The stamp stays inside the field, whatever its size.
      const mark = image ? markOf(await pdf.embedPng(value)) : { name: value, font: encodes(textBold, value) ? textBold : await noto.bold() };
      drawStamp(page, box, mark, { initials: type === "initials", code, signedAt: signer.get(who)?.signedAt ?? null, qrUrl: certUrl, font: text, bold: textBold });
    } else {
      // Helvetica covers Western European text; anything else is set in the embedded Noto Sans.
      drawEntry(page, value, box, encodes(text, value) ? text : await noto.regular());
    }
  }
  // A quiet seal line at the foot of every page of the document, as it is shown.
  for (const [i, p] of pages.entries()) {
    const { width } = shown[i];
    p.drawLine({ start: { x: 24, y: 20 }, end: { x: width - 24, y: 20 }, thickness: 0.4, color: HAIR });
    p.drawCircle({ x: 28, y: 11, size: 3, color: ACCENT });
    p.drawText(`Sealed by DataHubz Attest${code ? `  ·  ${fmtCode(code)}` : ""}  ·  verify at ${certUrl}`, { x: 36, y: 8.5, size: 6.5, font: text, color: MUTED });
    if (!clean) p.drawText(NOT_CLEAN_NOTE, { x: 36, y: 14, size: 5, font: text, color: MUTED });
    p.pushOperators(popGraphicsState());
  }
  if (input.variant === "full") await certificatePages(pdf, input, certUrl, adopted, { text, textBold }, noto, !clean);
  return finish(pdf);
}

/**
 * A copy of a document whose pages can't be shown (a file that opens only with a password, is encrypted in a way pdf.js
 * doesn't open, or can't be read): a first page that says so plainly, and that the original is attached exactly as
 * signed and verifies, then (full) the certificate pages.
 */
async function unreproducedPages(input: RenderInputV3, kind: keyof typeof UNREADABLE): Promise<Uint8Array> {
  const pdf = await PDFDocument.create({ updateMetadata: false });
  deterministic(pdf);
  const { agreement: a, details: d } = input;
  const code = d.verifyCode;
  const certUrl = code ? `${input.appUrl}/v/${fmtCode(code)}` : `${input.appUrl}/a/${a.id}`;
  const text = await pdf.embedFont(StandardFonts.Helvetica);
  const textBold = await pdf.embedFont(StandardFonts.HelveticaBold);
  const noto = notoFonts(pdf, input);
  const p = pdf.addPage([612, 792]);
  p.drawText("The signed document", { x: 54, y: 700, size: 18, font: textBold, color: NAVY });
  const why =
    kind === "password"
      ? "This document opens only with a password, so its pages can't be shown in this copy."
      : kind === "unsupported"
        ? "This document's pages can't be shown in this copy: the file is encrypted in a way PDF readers like pdf.js don't open."
        : "This document's pages can't be shown in this copy: the file can't be read.";
  const attached = `The document is attached to this copy exactly as it was signed (original-document.pdf), and it verifies: its fingerprint, ${a.documentSha256}, is the one Attest anchored when the agreement was completed.${kind === "password" ? " Open it with its password to see its pages." : ""}`;
  let y = 670;
  for (const para of [why, attached]) {
    for (const ln of wrap(para, text, 10.5, 504)) {
      p.drawText(ln, { x: 54, y, size: 10.5, font: text, color: BODY });
      y -= 15;
    }
    y -= 6;
  }
  p.drawLine({ start: { x: 24, y: 20 }, end: { x: 612 - 24, y: 20 }, thickness: 0.4, color: HAIR });
  p.drawCircle({ x: 28, y: 11, size: 3, color: ACCENT });
  p.drawText(`Sealed by DataHubz Attest${code ? `  ·  ${fmtCode(code)}` : ""}  ·  verify at ${certUrl}`, { x: 36, y: 8.5, size: 6.5, font: text, color: MUTED });
  const adopted = new Map<string, string>();
  for (const [id, type, , , , , , who] of d.fields) {
    const raw = input.entries[id];
    if (type === "signature" && raw?.startsWith("data:image/png;base64,") && !adopted.has(who)) adopted.set(who, raw);
  }
  if (input.variant === "full") await certificatePages(pdf, input, certUrl, adopted, { text, textBold }, noto, true);
  return finish(pdf);
}

/** Save, with nothing unreachable kept and nothing active left. */
async function finish(pdf: PDFDocument): Promise<Uint8Array> {
  await pdf.flush();
  dropUnreachable(pdf);
  const left = activeContent(pdf);
  if (left.length) throw new Error(`The document still carries active content after cleaning: ${[...new Set(left)].join(", ")}`);
  return pdf.save({ useObjectStreams: false });
}

/**
 * The certificate anyone with the agreement's link can download: the certificate pages alone (each signer's stamp
 * with their name), and how to verify it. No document, entries or audit trail, which are the parties' own.
 */
async function certificateV3(input: RenderInputV3): Promise<Uint8Array> {
  const pdf = await PDFDocument.create({ updateMetadata: false });
  deterministic(pdf);
  const code = input.details.verifyCode;
  const certUrl = code ? `${input.appUrl}/v/${fmtCode(code)}` : `${input.appUrl}/a/${input.agreement.id}`;
  const text = await pdf.embedFont(StandardFonts.Helvetica);
  const textBold = await pdf.embedFont(StandardFonts.HelveticaBold);
  await certificatePages(pdf, input, certUrl, new Map(), { text, textBold }, notoFonts(pdf, input));
  return finish(pdf);
}

async function certificatePages(pdf: PDFDocument, input: RenderInputV3, certUrl: string, adopted: Map<string, string>, std: { text: PDFFont; textBold: PDFFont }, noto: Noto, notClean = false) {
  const { agreement: a, details: d } = input;
  pdf.registerFontkit(fontkit);
  const sans = await pdf.embedFont(input.fonts.sans, { subset: true });
  const bold = await pdf.embedFont(input.fonts.bold, { subset: true });
  // JetBrains Mono's ligatures would merge characters of a fingerprint or link: off.
  const mono = await pdf.embedFont(input.fonts.mono, { subset: true, features: { liga: false, calt: false, dlig: false } });
  const [W, H] = [612, 792];
  const M = 54;
  const footer = (page: PDFPage, label: string) => {
    page.drawLine({ start: { x: M, y: 46 }, end: { x: W - M, y: 46 }, thickness: 0.6, color: HAIR });
    page.drawText(label, { x: M, y: 30, size: 7.5, font: sans, color: MUTED });
    page.drawText(a.id, { x: W - M - mono.widthOfTextAtSize(a.id, 7), y: 30, size: 7, font: mono, color: MUTED });
  };
  const header = (page: PDFPage, kicker: string) => {
    page.drawRectangle({ x: 0, y: H - 128, width: W, height: 128, color: rgb(0.965, 0.969, 0.996) });
    guilloche(page, 0, H - 128, W, 128);
    page.drawLine({ start: { x: 0, y: H - 128 }, end: { x: W, y: H - 128 }, thickness: 0.8, color: ACCENT, opacity: 0.35 });
    page.drawText("DataHubz", { x: M, y: H - 52, size: 13, font: bold, color: INK });
    page.drawText("Attest", { x: M + bold.widthOfTextAtSize("DataHubz ", 13), y: H - 52, size: 13, font: bold, color: ACCENT });
    page.drawText(kicker, { x: M, y: H - 98, size: 22, font: bold, color: NAVY });
  };
  const ordered = d.signers
    .map((c) => input.signers.find((s) => s.commitment === c))
    .filter((s): s is RenderInputV3["signers"][number] => Boolean(s))
    .map((s) => ({ ...s, name: printable(s.name) }));
  // Names and the title in Instrument Sans when it has every glyph they need, in Noto Sans when it doesn't.
  const boldFor = async (t: string) => (covers(bold, t) ? bold : await noto.bold());
  const sansFor = async (t: string) => (covers(sans, t) ? sans : await noto.regular());
  // A title v3 can't print whole isn't printed in part: the certificate names the agreement by its id instead.
  const title = unprintableV3(oneLine(a.title)).length ? `Untitled agreement (title not printable), ${a.id}` : printable(a.title);
  const titleFont = await boldFor(title);

  // ---- The certificate -------------------------------------------------------------------------------
  const p = pdf.addPage([W, H]);
  header(p, "Certificate of completion");
  seal(p, bold, W - M - 50, H - 128 - 6, 52);
  let y = H - 128 - 46;
  for (const ln of wrap(title, titleFont, 15, W - 2 * M - 120)) {
    p.drawText(ln, { x: M, y, size: 15, font: titleFont, color: INK });
    y -= 20;
  }
  y -= 4;
  for (const ln of wrap("Every party signed this document with a passkey only they control. Its signed state was sealed and anchored on a public blockchain, where anyone can check it, forever, without trusting DataHubz.", sans, 9.5, W - 2 * M - 120)) {
    p.drawText(ln, { x: M, y, size: 9.5, font: sans, color: BODY });
    y -= 14;
  }
  // A document that isn't clean: the same note as at the foot of its pages.
  if (notClean) {
    y -= 4;
    for (const ln of wrap(NOT_CLEAN_NOTE, sans, 9.5, W - 2 * M - 120)) {
      p.drawText(ln, { x: M, y, size: 9.5, font: sans, color: INK });
      y -= 14;
    }
  }
  y -= 18;
  const col = (W - 2 * M) / 2;
  const fact = (x: number, top: number, label: string, value: string, isMono = false): number => {
    let yy = top;
    p.drawText(label, { x, y: yy, size: 7.5, font: sans, color: MUTED });
    yy -= 13;
    for (const ln of isMono ? chunk(value, 32) : wrap(value, sans, 10, col - 16)) {
      p.drawText(ln, { x, y: yy, size: isMono ? 8.2 : 10, font: isMono ? mono : sans, color: INK });
      yy -= isMono ? 11 : 13;
    }
    return yy;
  };
  let l = fact(M, y, "Completed", fmtUtc(d.completedAt));
  let r = fact(M + col, y, "Parties", `${ordered.length} signer${ordered.length === 1 ? "" : "s"}, each with a passkey only they control`);
  y = Math.min(l, r) - 10;
  if (d.verifyCode) {
    l = fact(M, y, "Verification code", fmtCode(d.verifyCode));
    r = fact(M + col, y, "On every signature", "A Signed with Attest stamp with this code and a QR code to this certificate");
    y = Math.min(l, r) - 10;
  }
  l = fact(M, y, "Document fingerprint (SHA-256)", a.documentSha256, true);
  r = fact(M + col, y, "Signed-state fingerprint", a.completionHash, true);
  y = Math.min(l, r) - 10;
  l = fact(M, y, "Anchored on Horizen", a.anchorTxHash ?? "Anchoring: a transaction is on its way", Boolean(a.anchorTxHash));
  r = fact(M + col, y, "Zero-knowledge proofs", "Each party can prove they signed, and the date it was completed, without revealing the document: verified on zkVerify");
  y = Math.min(l, r) - 18;

  // Every signature, each in its stamp with the code and a QR code to this certificate, continuing on further pages.
  p.drawLine({ start: { x: M, y }, end: { x: W - M, y }, thickness: 0.6, color: HAIR });
  y -= 22;
  p.drawText("Signatures", { x: M, y, size: 11, font: bold, color: INK });
  y -= 10;
  let sp = p;
  let floor = 190;
  for (const s of ordered) {
    if (y - 54 < floor) {
      sp = pdf.addPage([W, H]);
      header(sp, "Certificate of completion");
      footer(sp, "Certificate of completion, continued.");
      y = H - 128 - 40;
      sp.drawText("Signatures, continued", { x: M, y, size: 11, font: bold, color: INK });
      y -= 10;
      floor = 70;
    }
    const img = adopted.get(s.commitment);
    const nameFont = await boldFor(s.name);
    const mark = img ? markOf(await pdf.embedPng(img)) : { name: s.name, font: encodes(std.textBold, s.name) ? std.textBold : nameFont };
    drawStamp(sp, { x: M, y: y - 42, w: 170, h: 42 }, mark, { initials: false, code: d.verifyCode, signedAt: s.signedAt, qrUrl: certUrl, font: std.text, bold: std.textBold });
    const x2 = M + 190;
    sp.drawText(s.name, { x: x2, y: y - 14, size: 9.5, font: nameFont, color: INK });
    sp.drawText(`Signed ${fmtUtc(s.signedAt)}, with a passkey only they control`, { x: x2, y: y - 27, size: 8.5, font: sans, color: BODY });
    sp.drawCircle({ x: W - M - 6, y: y - 18, size: 6, color: SUCCESS });
    y -= 54;
  }

  drawQr(p, certUrl, W - M - 74, 64, 74);
  p.drawText("Verify live", { x: W - M - 74 - 74, y: 120, size: 9, font: bold, color: INK });
  for (const [i, ln] of wrap("Scan, or open the link, to re-check every signature and the anchor in your own browser.", sans, 7.5, 140).entries()) {
    p.drawText(ln, { x: W - M - 74 - 150, y: 107 - i * 10, size: 7.5, font: sans, color: MUTED });
  }
  p.drawText(certUrl, { x: M, y: 64, size: 7.5, font: mono, color: ACCENT });
  footer(p, "Certificate of completion. To check it without Attest, see the last page.");

  // ---- The audit trail, up to completion ---------------------------------------------------------------
  if (input.variant === "full" && input.trail && input.trail.length > 0) {
    let t = pdf.addPage([W, H]);
    header(t, "Audit trail");
    footer(t, "Audit trail, recorded as each step happened, and anchored with the agreement.");
    let yy = H - 128 - 40;
    t.drawText("Every step of this document until it was completed, in order. Times are in UTC.", { x: M, y: yy, size: 9.5, font: sans, color: BODY });
    yy -= 28;
    for (const [type, at, who] of input.trail) {
      if (yy < 70) {
        t = pdf.addPage([W, H]);
        header(t, "Audit trail");
        footer(t, "Audit trail, continued.");
        yy = H - 128 - 40;
      }
      const line = printable((EVENT_TEXT[type] ?? ((w: string) => `${type} ${w}`))(who ?? "the sender"));
      t.drawCircle({ x: M + 4, y: yy + 3, size: 2.6, color: type === "completed" ? SUCCESS : ACCENT });
      t.drawText(fmtUtc(at), { x: M + 16, y: yy, size: 8, font: mono, color: MUTED });
      t.drawText(line, { x: M + 210, y: yy, size: 9.5, font: await sansFor(line), color: INK });
      yy -= 22;
    }
  }

  // ---- Verify it yourself, without us ---------------------------------------------------------------
  const v = pdf.addPage([W, H]);
  header(v, "Verify it yourself, without us");
  let vy = H - 128 - 40;
  for (const ln of wrap("You don't have to trust DataHubz, or this page. Everything here can be checked with open standards and public infrastructure, even if Attest disappears.", sans, 10.5, W - 2 * M)) {
    v.drawText(ln, { x: M, y: vy, size: 10.5, font: sans, color: INK });
    vy -= 15;
  }
  vy -= 10;
  const steps: [string, string][] = input.variant === "certificate" ? [
    ["With no Attest service", "This certificate carries its own verifier. Open its attachments (in a PDF reader's attachments panel), save attest-verifier.html anywhere, open it in any browser and drop this PDF on it. It checks every step below on your device, reading only the public blockchain, and re-makes these pages from what was signed and anchored to show they are exactly Attest's certificate."],
    ["The document", `The document stays with the parties: Attest never had it. Its SHA-256 is ${a.documentSha256}, the fingerprint every signer's statement names, and each party's signed copy carries it.`],
    ["Each signature", "attest-evidence.json, attached, holds for every signer the exact statement they signed, their passkey's public key, and the WebAuthn signature. Any WebAuthn library checks it: the signature covers the authenticator data and the SHA-256 of the client data, whose challenge is the SHA-256 of the statement."],
    ["The anchor", a.anchorTxHash ? `The evidence holds the exact signed-state text (SHA-256 ${a.completionHash}) and its Merkle path to the root that Horizen transaction ${a.anchorTxHash} recorded, and Attest's own anchor of the agreement, its signatures and these details. Any Horizen node confirms them.` : "The anchoring transaction appears on the live verification page as soon as it confirms."],
    ["The proofs", "Each party can prove they signed, and the date it was completed, with a zero-knowledge proof (Groth16) that reveals nothing else, verified on zkVerify, an independent network."],
    ["The standards", "WebAuthn (W3C) for signatures, SHA-256 (NIST FIPS 180-4) for fingerprints, Merkle trees for anchoring, Groth16 for zero-knowledge proofs. No proprietary format anywhere."],
  ] : [
    ["With no Attest service", "This PDF carries its own verifier. Open its attachments (in a PDF reader's attachments panel), save attest-verifier.html anywhere, open it in any browser and drop this PDF on it. It checks every step below on your device, reading only the public blockchain, and re-makes these pages from what was signed to show they are exactly the signed copy."],
    ["The document", `original-document.pdf, attached, is the document exactly as it was signed: its SHA-256 is ${a.documentSha256}, the fingerprint every signer's statement names.`],
    ["Each signature and entry", "attest-evidence.json, attached, holds for every signer the exact statement they signed, the exact text of their entries (its SHA-256 is in the statement), their passkey's public key, and the WebAuthn signature. Any WebAuthn library checks it: the signature covers the authenticator data and the SHA-256 of the client data, whose challenge is the SHA-256 of the statement."],
    ["The anchor", a.anchorTxHash ? `The evidence holds the exact signed-state text (SHA-256 ${a.completionHash}) and its Merkle path to the root that Horizen transaction ${a.anchorTxHash} recorded, and Attest's own anchor of the agreement, its signatures and these details. Any Horizen node confirms them.` : "The anchoring transaction appears on the live verification page as soon as it confirms."],
    ["The proofs", "Each party can prove they signed, and the date it was completed, with a zero-knowledge proof (Groth16) that reveals nothing else, verified on zkVerify, an independent network."],
    ["The standards", "WebAuthn (W3C) for signatures, SHA-256 (NIST FIPS 180-4) for fingerprints, Merkle trees for anchoring, Groth16 for zero-knowledge proofs. No proprietary format anywhere."],
  ];
  for (const [i, [title, body]] of steps.entries()) {
    v.drawCircle({ x: M + 9, y: vy - 2, size: 9, color: ACCENT });
    v.drawText(String(i + 1), { x: M + 9 - bold.widthOfTextAtSize(String(i + 1), 9) / 2, y: vy - 5, size: 9, font: bold, color: rgb(1, 1, 1) });
    v.drawText(title, { x: M + 28, y: vy - 5, size: 11, font: bold, color: INK });
    vy -= 22;
    for (const ln of wrap(body, sans, 9.2, W - 2 * M - 28)) {
      v.drawText(ln, { x: M + 28, y: vy, size: 9.2, font: sans, color: BODY });
      vy -= 13.5;
    }
    vy -= 12;
  }
  footer(v, "Trust the cryptography, not the company.");
}
