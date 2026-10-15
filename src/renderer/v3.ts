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
  PDFRawStream,
  PDFRef,
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

// ---- The document as the signer saw it ------------------------------------------------------------------
//
// The signer saw each page drawn by pdf.js for print (the field placer and the signing page draw pages that way). A
// copy shows exactly that, with Attest's layer on top, in every reader, or isn't made: a document v3 can't vouch for
// is refused before anyone signs (documentProblemsV3), and renderV3 throws on it rather than make a copy that could
// show something else.
//
// - Content is read as pdf.js reads it (its lexer, its operators, its inline images), from streams decoded with the
//   filters and predictors pdf.js decodes; nothing is dropped or changed. A stream v3 can't decode completely, or whose
//   reading other readers could disagree with, makes the document refused.
// - Each page's content is drawn as one form XObject, which readers draw with its own graphics state. Every content
//   stream a page may run (the page's form, form XObjects, Type 3 glyphs, soft masks, annotation appearances) is then
//   closed off: preceded by as many saves as it could restore beyond its own (pdf.js keeps one stack of saved states
//   for the whole page and lets a form restore states saved outside it), and followed by what ends every state ISO
//   32000-1 lets persist past the end of a content stream that a graphics state restore doesn't end:
//     - a text object (BT without ET, 9.4): ET, which also applies a pending text clip inside the stream;
//     - a current path or a pending clip (8.5.2, 8.5.4: a path is painted, or a clip applied, by the next painting
//       operator, which would be Attest's): n;
//     - marked content (BMC or BDC without EMC, 14.6), optional content included: an EMC for each;
//     - a compatibility section (BX without EX, 7.8.2): an EX for each.
//   The graphics state itself (the transform, the clip, colours, line and text state, the soft mask and the other
//   ExtGState parameters, 8.4) is restored when the form ends. A stream that ends inside an inline image, a string, a
//   hex string, an array or a dictionary is refused: anything appended would be read as part of it.
// - Annotations are drawn as pdf.js draws them for print: each one its print shows (flagged Print, not Hidden), in its
//   order (widgets, then pop-ups, last), from its appearance stream (the one /AS names in a state dictionary), mapped
//   from its BBox and Matrix to its Rect and clipped to it, with its optional content. They become part of the page,
//   under Attest's layer, and every annotation is removed from the copy, with the form fields: no annotation can cover
//   a stamp, and none the signer didn't see can appear. One whose appearance pdf.js would make up itself (no appearance
//   stream, or form fields whose appearances the document asks readers to regenerate) is refused.
// - Optional content whose visibility depends on printing or viewing (Usage with PrintState or ViewState) is refused:
//   the signer saw it as printed, and a reader shows it as viewed.

/** pdf.js's operators and their operand counts (EvaluatorPreprocessor.opMap; negative: up to that many). */
const OPERATORS: Record<string, number> = {
  w: 1, J: 1, j: 1, M: 1, d: 2, ri: 1, i: 1, gs: 1, q: 0, Q: 0, cm: 6, m: 2, l: 2, c: 6, v: 4, y: 4, h: 0, re: 4, S: 0, s: 0, f: 0,
  F: 0, "f*": 0, B: 0, "B*": 0, b: 0, "b*": 0, n: 0, W: 0, "W*": 0, BT: 0, ET: 0, Tc: 1, Tw: 1, Tz: 1, TL: 1, Tf: 2, Tr: 1, Ts: 1,
  Td: 2, TD: 2, Tm: 6, "T*": 0, Tj: 1, TJ: 1, "'": 1, '"': 3, d0: 2, d1: 6, CS: 1, cs: 1, SC: -4, SCN: -33, sc: -4, scn: -33, G: 1,
  g: 1, RG: 3, rg: 3, K: 4, k: 4, sh: 1, BI: 0, ID: 0, EI: 1, Do: 1, MP: 1, DP: 2, BMC: 1, BDC: 2, EMC: 0, BX: 0, EX: 0,
};
/** Every word pdf.js's lexer knows, which it splits a run of characters into ("fQ" is f, then Q). */
const LEXER_WORDS = new Set([...Object.keys(OPERATORS), "BM", "BD", "true", "fa", "fal", "fals", "false", "nu", "nul", "null"]);
const PATH_OPS = new Set(["m", "l", "c", "v", "y", "h", "re"]);
const PAINT_OPS = new Set(["S", "s", "f", "F", "f*", "B", "B*", "b", "b*", "n"]);

const isWhite = (c: number) => c === 0 || c === 9 || c === 10 || c === 12 || c === 13 || c === 32;
const isDelim = (c: number) => c === 40 || c === 41 || c === 60 || c === 62 || c === 91 || c === 93 || c === 123 || c === 125 || c === 47 || c === 37;
const isSpecial = (c: number) => isWhite(c) || isDelim(c);

type Tok =
  | { k: "op"; v: string }
  | { k: "num" | "str" | "hex" | "name" | "lit"; v: string }
  | { k: "[" | "]" | "<<" | ">>" | "{" | "}" | ">" }
  | { k: "eof" };
type Lexed = { tok: Tok; end: number } | { error: string };

/** One token at `i`, exactly as pdf.js's lexer reads it (Lexer.getObj), or why pdf.js would stop reading there. */
function lexAt(b: Uint8Array, i: number): Lexed {
  const n = b.length;
  for (;;) {
    if (i >= n) return { tok: { k: "eof" }, end: n };
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
      if (j >= n || isWhite(ch) || ch === 40 || ch === 60) return { tok: { k: "num", v: "0" }, end: j };
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
    return { tok: { k: "num", v: "" }, end: j };
  }
  if (c === 40) {
    let depth = 1;
    let j = i + 1;
    while (j < n) {
      const x = b[j++];
      if (x === 92) {
        if (j < n) j++;
      } else if (x === 40) depth++;
      else if (x === 41 && --depth === 0) return { tok: { k: "str", v: "" }, end: j };
    }
    return { error: "a string that isn't closed" };
  }
  if (c === 47) {
    let j = i + 1;
    while (j < n && !isSpecial(b[j])) j++;
    return { tok: { k: "name", v: String.fromCharCode(...b.subarray(i + 1, j)) }, end: j };
  }
  if (c === 91) return { tok: { k: "[" }, end: i + 1 };
  if (c === 93) return { tok: { k: "]" }, end: i + 1 };
  if (c === 123) return { tok: { k: "{" }, end: i + 1 };
  if (c === 125) return { tok: { k: "}" }, end: i + 1 };
  if (c === 60) {
    if (b[i + 1] === 60) return { tok: { k: "<<" }, end: i + 2 };
    let j = i + 1;
    while (j < n && b[j] !== 62) j++;
    if (j >= n) return { error: "a hex string that isn't closed" };
    return { tok: { k: "hex", v: "" }, end: j + 1 };
  }
  if (c === 62) return b[i + 1] === 62 ? { tok: { k: ">>" }, end: i + 2 } : { tok: { k: ">" }, end: i + 1 };
  if (c === 41) return { error: "a stray parenthesis, where pdf.js stops reading" };
  // A command: pdf.js reads characters while they make one of its words, or until it has one and the next would end it.
  if ((c < 0x20 || c > 0x7f) && i + 1 < n && b[i + 1] >= 0x20 && b[i + 1] <= 0x7f) return { tok: { k: "op", v: String.fromCharCode(c) }, end: i + 1 };
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
  if (str === "true" || str === "false" || str === "null") return { tok: { k: "lit", v: str }, end: j };
  return { tok: { k: "op", v: str }, end: j };
}

/** What a content stream leaves open at its end, and the most saved states it could restore beyond its own. */
export interface ContentState {
  restores: number;
  text: boolean;
  path: boolean;
  marked: number;
  compat: number;
  /** Why v3 can't vouch for this content (pdf.js and other readers could read it differently), or null. */
  problem: string | null;
}

const E = 0x45, I = 0x49;
/**
 * Where an inline image's data ends (the "EI" after it), found as pdf.js finds it, and only when every reader finds the
 * same end: no "EI" inside the data, and, after the data, "EI" and then what pdf.js's own check accepts.
 */
function inlineImageEnd(b: Uint8Array, dataStart: number, filter: string | null): number | string {
  const n = b.length;
  // pdf.js finds an image's end by its EOD marker for ASCII85 and ASCIIHex data, and by "EI" otherwise; it decodes
  // no other image filter here.
  if (filter && !["A85", "ASCII85Decode", "AHx", "ASCIIHexDecode", "Fl", "FlateDecode", "LZW", "LZWDecode", "RL", "RunLengthDecode"].includes(filter)) return `an inline image encoded with ${filter}`;
  let marker = -1;
  if (filter === "A85" || filter === "ASCII85Decode") {
    for (let k = dataStart; k + 1 < n; k++) if (b[k] === 0x7e && b[k + 1] === 0x3e) { marker = k + 2; break; }
  } else if (filter === "AHx" || filter === "ASCIIHexDecode") {
    for (let k = dataStart; k < n; k++) if (b[k] === 0x3e) { marker = k + 1; break; }
  }
  // pdf.js's default search: E, then I, then a space, line feed or carriage return.
  let state = 0;
  let at = -1;
  for (let k = dataStart; k < n; k++) {
    const ch = b[k];
    if (state === 0) state = ch === E ? 1 : 0;
    else if (state === 1) state = ch === I ? 2 : 0;
    else if (ch === 0x20 || ch === 0x0a || ch === 0x0d) {
      at = k - 2;
      break;
    } else state = 0;
  }
  if (at < 0) return "an inline image without its end";
  for (let k = dataStart; k < at; k++) if (b[k] === E && b[k + 1] === I) return "an inline image whose data contains EI";
  if (marker >= 0) {
    for (let k = marker; k < at; k++) if (!isWhite(b[k])) return "an inline image with data after its end marker";
  } else if (filter === "A85" || filter === "ASCII85Decode" || filter === "AHx" || filter === "ASCIIHexDecode") return "an inline image without its end marker";
  // pdf.js accepts this EI only if the next 15 bytes are text and a command with its operands follows.
  const after = b.subarray(at + 3, at + 3 + 15);
  for (let k = 0; k < after.length; k++) {
    const ch = after[k];
    if (ch === 0 && after[k + 1] !== 0) continue;
    if (ch !== 0x0a && ch !== 0x0d && (ch < 0x20 || ch > 0x7f)) return "an inline image whose end pdf.js reads differently";
  }
  if (after.length) {
    const window = b.subarray(at + 3, at + 3 + 75);
    let p = 0;
    let operands = 0;
    for (;;) {
      const r = lexAt(window, p);
      if ("error" in r || r.tok.k === "eof") return "an inline image whose end pdf.js reads differently";
      p = r.end;
      if (r.tok.k === "op") {
        const count = OPERATORS[r.tok.v];
        if (count === undefined) return "an inline image whose end pdf.js reads differently";
        if (count < 0 ? operands <= -count : operands === count) break;
        operands = 0;
        continue;
      }
      operands++;
    }
  }
  return at;
}

/**
 * Reads a content stream as pdf.js does: what it leaves open at its end, the most saved states it could restore beyond
 * its own (every Q pdf.js reads, glued or not, counts), or why v3 can't vouch for it.
 */
export function readContent(b: Uint8Array): ContentState {
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
      // The image's dictionary, up to ID: names and their values (pdf.js refuses any other key).
      let filter: string | null = null;
      for (;;) {
        const k = lexAt(b, i);
        if ("error" in k) return fail(k.error);
        i = k.end;
        if (k.tok.k === "eof") return fail("an inline image without its data");
        if (k.tok.k === "op" && k.tok.v === "ID") break;
        if (k.tok.k !== "name") return fail("an inline image whose dictionary pdf.js can't read");
        const key = k.tok.v;
        const v = lexAt(b, i);
        if ("error" in v) return fail(v.error);
        i = v.end;
        if (v.tok.k === "eof" || (v.tok.k === "op" && v.tok.v === "ID")) return fail("an inline image whose dictionary pdf.js can't read");
        if (v.tok.k === "[" || v.tok.k === "<<") {
          let depth = 1;
          let first = true;
          while (depth > 0) {
            const y = lexAt(b, i);
            if ("error" in y) return fail(y.error);
            i = y.end;
            if (y.tok.k === "eof") return fail("an inline image whose dictionary pdf.js can't read");
            if (y.tok.k === "[" || y.tok.k === "<<") depth++;
            else if (y.tok.k === "]" || y.tok.k === ">>") depth--;
            else if (first && depth === 1 && y.tok.k === "name" && (key === "F" || key === "Filter")) filter = y.tok.v;
            first = false;
          }
        } else if ((key === "F" || key === "Filter") && v.tok.k === "name") filter = v.tok.v;
      }
      // The data starts after the character that ends "ID".
      const end = inlineImageEnd(b, i + 1, filter);
      if (typeof end === "string") return fail(end);
      i = end + 2;
    }
  }
  if (nest > 0) return fail("an array or a dictionary that isn't closed");
  return s;
}

/** What ends every state a content stream left open (ContentState), appended after it. */
const closing = (s: ContentState) => `${s.text ? "ET\n" : ""}${s.path ? "n\n" : ""}${"EMC\n".repeat(s.marked)}${"EX\n".repeat(s.compat)}`;

const ascii = (s: string) => Uint8Array.from(s, (ch) => ch.charCodeAt(0));
function joined(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((t, p) => t + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}
/** Content closed off: preceded by the saves it could restore beyond its own, followed by what ends what it left open. */
const closedOff = (data: Uint8Array, s: ContentState) =>
  joined([ascii(s.restores ? `${"q ".repeat(s.restores)}\n` : ""), data, ascii(`\n${closing(s)}`)]);
const needsClosing = (s: ContentState) => s.restores > 0 || s.text || s.path || s.marked > 0 || s.compat > 0;

/** The filters pdf.js decodes content with, by every name it accepts. */
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

/**
 * A content stream decoded completely, with every filter and predictor pdf.js decodes content with, or why not: a
 * stream v3 can't decode completely makes the document refused (it never drops or changes content).
 */
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

/**
 * Every other content stream a page may run (forms, Type 3 glyphs, soft masks), read as pdf.js reads it and closed off
 * where it needs to be (rewritten with exactly the content it had). Returns what v3 can't vouch for.
 */
function closeOffContentStreams(pdf: PDFDocument): string[] {
  const ctx = pdf.context;
  const lookup = (x: unknown) => (x instanceof PDFRef ? ctx.lookup(x) : x);
  const run = new Set<PDFRef>();
  const problems: string[] = [];
  for (const [ref, o] of ctx.enumerateIndirectObjects()) {
    const dict = o instanceof PDFDict ? o : o instanceof PDFRawStream ? o.dict : null;
    if (!dict) continue;
    if (o instanceof PDFRawStream && nameIn(pdf, dict.get(PDFName.of("Subtype"))) === "Form") run.add(ref);
    if (nameIn(pdf, dict.get(PDFName.of("Subtype"))) === "Type3") {
      const procs = lookup(dict.get(PDFName.of("CharProcs")));
      if (procs instanceof PDFDict) for (const [, v] of procs.entries()) if (v instanceof PDFRef) run.add(v);
    }
    const mask = lookup(dict.get(PDFName.of("SMask")));
    const group = mask instanceof PDFDict ? mask.get(PDFName.of("G")) : undefined;
    if (group instanceof PDFRef) run.add(group);
    // Optional content shown differently printed and viewed: the signer saw it printed, a reader shows it viewed.
    const usage = lookup(dict.get(PDFName.of("Usage")));
    if (nameIn(pdf, dict.get(PDFName.of("Type"))) === "OCG" && usage instanceof PDFDict) {
      for (const [k, state] of [["Print", "PrintState"], ["View", "ViewState"]]) {
        const u = lookup(usage.get(PDFName.of(k)));
        if (u instanceof PDFDict && u.has(PDFName.of(state))) problems.push("optional content shown differently printed and on screen");
      }
    }
  }
  const skip = new Set(["Filter", "DecodeParms", "Length", "DL"]);
  for (const ref of run) {
    const s = ctx.lookup(ref);
    if (!(s instanceof PDFRawStream)) continue;
    const data = contentOf(pdf, s);
    if (typeof data === "string") {
      problems.push(data);
      continue;
    }
    const state = readContent(data);
    if (state.problem) {
      problems.push(state.problem);
      continue;
    }
    if (!needsClosing(state)) continue;
    const fresh = ctx.flateStream(closedOff(data, state));
    for (const [k, v] of s.dict.entries()) if (!skip.has(k.decodeText())) fresh.dict.set(k, v);
    ctx.assign(ref, fresh);
  }
  return problems;
}

/** The page's own content, as pdf.js reads a page: its streams decoded and joined, or why not. */
function pageContent(pdf: PDFDocument, page: PDFPage): Uint8Array | string {
  const raw = page.node.get(PDFName.of("Contents"));
  const contents = raw instanceof PDFRef ? pdf.context.lookup(raw) : raw;
  if (contents === undefined) return new Uint8Array();
  const parts = contents instanceof PDFArray ? contents.asArray() : [contents];
  const out: Uint8Array[] = [];
  for (const p of parts) {
    const d = contentOf(pdf, p);
    if (typeof d === "string") return d;
    out.push(d);
  }
  return joined(out);
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
  const x = v instanceof PDFRef ? pdf.context.lookup(v) : v;
  if (!(x instanceof PDFArray) || (len !== null && x.size() !== len)) return null;
  const out = x.asArray().map((y) => (y instanceof PDFRef ? pdf.context.lookup(y) : y));
  return out.every((y) => y instanceof PDFNumber) ? out.map((y) => (y as PDFNumber).asNumber()) : null;
}

/**
 * The page's annotations as pdf.js draws them for print, as page content to draw after the page's own (each one a form
 * XObject added to `res`), or what v3 can't vouch for. The annotations themselves are then removed.
 */
function flattenAnnotations(pdf: PDFDocument, page: PDFPage, res: PDFDict, problems: string[]): string {
  const ctx = pdf.context;
  const lookup = (x: unknown) => (x instanceof PDFRef ? ctx.lookup(x) : x);
  const node = page.node;
  const annots = lookup(inherited(pdf, node, "Annots"));
  node.delete(PDFName.of("Annots"));
  if (!(annots instanceof PDFArray)) return "";
  const needAppearances = (() => {
    const form = lookup(pdf.catalog.get(PDFName.of("AcroForm")));
    const na = form instanceof PDFDict ? lookup(form.get(PDFName.of("NeedAppearances"))) : undefined;
    return Boolean(na && (na as { asBoolean?: () => boolean }).asBoolean?.());
  })();
  const all = annots.asArray().map(lookup).filter((a): a is PDFDict => a instanceof PDFDict);
  const kind = (a: PDFDict) => nameIn(pdf, a.get(PDFName.of("Subtype")));
  const ordered = [...all.filter((a) => kind(a) !== "Widget" && kind(a) !== "Popup"), ...all.filter((a) => kind(a) === "Widget"), ...all.filter((a) => kind(a) === "Popup")];
  let out = "";
  const XObject = ctx.obj({});
  const Properties = ctx.obj({});
  for (const a of ordered) {
    const subtype = kind(a);
    const f = lookup(a.get(PDFName.of("F")));
    let flags = f instanceof PDFNumber && Number.isInteger(f.asNumber()) && f.asNumber() > 0 ? f.asNumber() : 0;
    if (flags & 1 && subtype !== null && KNOWN_ANNOTATIONS.has(subtype)) flags ^= 1;
    if (subtype && QUAD_TYPES.has(subtype)) {
      const q = numbers(pdf, a.get(PDFName.of("QuadPoints")), null);
      if (!q || q.length === 0 || q.length % 8) continue;
    }
    // pdf.js prints an annotation flagged Print, and not Hidden or Invisible.
    if (flags === 0 || !(flags & 4) || flags & 2 || flags & 1) continue;
    const r = numbers(pdf, a.get(PDFName.of("Rect")), 4) ?? [0, 0, 0, 0];
    const rect: Rect4 = [Math.min(r[0], r[2]), Math.min(r[1], r[3]), Math.max(r[0], r[2]), Math.max(r[1], r[3])];
    // Its appearance: /AP /N, or the state /AS names in it.
    const ap = lookup(a.get(PDFName.of("AP")));
    let appearance: unknown = ap instanceof PDFDict ? lookup(ap.get(PDFName.of("N"))) : undefined;
    if (appearance instanceof PDFDict) {
      const as = lookup(a.get(PDFName.of("AS")));
      appearance = as instanceof PDFName && appearance.has(as) ? lookup(appearance.get(as)) : undefined;
    }
    const field = subtype === "Widget" ? nameIn(pdf, inherited(pdf, a, "FT")) : null;
    if (subtype === "Widget" && needAppearances && (field === "Tx" || field === "Ch")) {
      problems.push("form fields whose appearances readers are asked to make up");
      continue;
    }
    // A pop-up takes its parent's flags in pdf.js, so whether one with its own appearance prints isn't its own to say.
    if (subtype === "Popup" && appearance instanceof PDFRawStream) {
      problems.push("a pop-up note with its own appearance");
      continue;
    }
    if (!(appearance instanceof PDFRawStream)) {
      // pdf.js draws nothing for a link or a pop-up without an appearance; for anything else it may make one up.
      if (subtype !== "Link" && subtype !== "Popup") problems.push(`a printed ${subtype ?? "annotation"} without an appearance`);
      continue;
    }
    const data = contentOf(pdf, appearance);
    if (typeof data === "string") {
      problems.push(data);
      continue;
    }
    const state = readContent(data);
    if (state.problem) {
      problems.push(state.problem);
      continue;
    }
    const w = rect[2] - rect[0], h = rect[3] - rect[1];
    const bbox = numbers(pdf, appearance.dict.get(PDFName.of("BBox")), 4) ?? [0, 0, w, h];
    const matrix = numbers(pdf, appearance.dict.get(PDFName.of("Matrix")), 6) ?? [1, 0, 0, 1, 0, 0];
    const t = appearanceTransform(rect, bbox, matrix);
    const resources = lookup(appearance.dict.get(PDFName.of("Resources")));
    const k = XObject.keys().length;
    const form = ctx.flateStream(closedOff(data, state), {
      Type: "XObject",
      Subtype: "Form",
      BBox: [-1e9, -1e9, 1e9, 1e9],
      Resources: resources instanceof PDFDict ? resources : ctx.obj({}),
    });
    XObject.set(PDFName.of(`AttestAnnot${k}`), ctx.register(form));
    const oc = a.get(PDFName.of("OC"));
    if (oc !== undefined) Properties.set(PDFName.of(`AttestOC${k}`), oc);
    const nums = (xs: number[]) => xs.map((x) => numberText(x)).join(" ");
    out += `${oc !== undefined ? `/OC /AttestOC${k} BDC\n` : ""}q ${nums([rect[0], rect[1], w, h])} re W n ${nums(t)} cm ${nums(matrix)} cm /AttestAnnot${k} Do Q\n${oc !== undefined ? "EMC\n" : ""}`;
  }
  for (const [key, v] of XObject.entries()) (res.get(PDFName.of("XObject")) as PDFDict).set(key, v);
  if (Properties.keys().length) res.set(PDFName.of("Properties"), Properties);
  return out;
}

/** A number as content streams write it: pdf-lib's own form (no exponent), the same in every engine. */
const numberText = (x: number) => PDFNumber.of(x).toString();

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
 * the CropBox, within the MediaBox, turned by /Rotate, at /UserUnit points to the unit. Fields are fractions of this
 * page from its top-left. `m` maps the shown page, in points from its bottom-left, to the page's own coordinates.
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
 * The page's own content drawn as one form XObject, which readers draw with its own graphics state, closed off (read
 * as pdf.js reads a page: its streams decoded and joined), then the annotations pdf.js prints, drawn as page content:
 * whatever the content leaves changed or open ends with it, and what Attest draws next starts from the page's own
 * state, on top of everything the signer saw. The content's resources stay its own, so it can't name anything Attest
 * adds. What v3 can't vouch for is added to `problems`.
 */
function isolatePage(pdf: PDFDocument, page: PDFPage, media: Rect4, problems: string[]) {
  const ctx = pdf.context;
  const node = page.node;
  const data = pageContent(pdf, page);
  let body: Uint8Array = new Uint8Array();
  if (typeof data === "string") problems.push(data);
  else {
    const state = readContent(data);
    if (state.problem) problems.push(state.problem);
    else body = closedOff(data, state);
  }
  const resources = inherited(pdf, node, "Resources");
  const form = ctx.flateStream(body, {
    Type: "XObject",
    Subtype: "Form",
    BBox: media,
    Resources: resources instanceof PDFDict ? resources : ctx.obj({}),
  });
  const res = ctx.obj({ XObject: { AttestPage: ctx.register(form) } });
  const annotations = flattenAnnotations(pdf, page, res, problems);
  node.set(PDFName.of("Resources"), res);
  node.set(PDFName.of("Contents"), ctx.register(ctx.flateStream(`q /AttestPage Do Q\n${annotations}`)));
}

/**
 * Why v3 can't make a copy of this document that shows exactly what its signer sees, in every reader (empty when it
 * can). The composer refuses such a document before it's sent, the signing page before anyone signs, and renderV3
 * throws on it.
 */
export async function documentProblemsV3(original: Uint8Array): Promise<string[]> {
  let pdf: PDFDocument;
  try {
    pdf = await PDFDocument.load(original, { updateMetadata: false });
  } catch {
    return ["a PDF that can't be read (an encrypted or damaged file)"];
  }
  stripActiveContent(pdf);
  const problems = closeOffContentStreams(pdf);
  for (const p of pdf.getPages()) isolatePage(pdf, p, shownPage(pdf, p).media, problems);
  return [...new Set(problems)];
}

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
  const pdf = await PDFDocument.load(input.original, { updateMetadata: false });
  deterministic(pdf);
  stripActiveContent(pdf);
  const problems = closeOffContentStreams(pdf);
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
  const shown = pages.map((p) => shownPage(pdf, p));
  for (const [i, p] of pages.entries()) isolatePage(pdf, p, shown[i].media, problems);
  // Form fields are drawn as the signer saw them (their widgets flattened above): the copy keeps no fields of its own.
  pdf.catalog.delete(PDFName.of("AcroForm"));
  if (problems.length) throw new Error(`Renderer v3 can't make a copy of this document that shows exactly what its signer saw: ${[...new Set(problems)].join("; ")}`);
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
    p.pushOperators(popGraphicsState());
  }
  if (input.variant === "full") await certificatePages(pdf, input, certUrl, adopted, { text, textBold }, noto);
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

async function certificatePages(pdf: PDFDocument, input: RenderInputV3, certUrl: string, adopted: Map<string, string>, std: { text: PDFFont; textBold: PDFFont }, noto: Noto) {
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
