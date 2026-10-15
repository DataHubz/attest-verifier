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
import { printableV3 } from "./charset-v3";

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

// ---- The document's content, kept to itself ------------------------------------------------------------

const WHITE = new Set([0, 9, 10, 12, 13, 32]);
const DELIMS = new Set([40, 41, 60, 62, 91, 93, 123, 125, 47, 37]);
const regular = (c: number) => !WHITE.has(c) && !DELIMS.has(c);

/**
 * The most graphics states a content stream could restore (Q) beyond the ones it saved itself (q), at any point, as any
 * reader may parse it. Readers that follow the PDF specification never let a form's content restore a state saved
 * outside the form; pdf.js keeps one stack for the whole page and does, so a document ending in "Q Q Q 1 0 0 1 0 -118
 * cm" would move everything drawn after it. Each content stream that could is preceded by this many saves of its own.
 *
 * An upper bound, read as pdf.js's lexer reads: comments, strings, hex strings and names are skipped; every Q in a run
 * of other characters counts as a restore (pdf.js splits "QQQ" and "fQ" into operators), and only a q standing alone
 * counts as a save. After an inline image, whose end readers find in different ways, every Q byte counts and no save
 * does.
 */
export function unbalancedRestores(b: Uint8Array): number {
  const n = b.length;
  let saved = 0;
  let worst = 0;
  const restore = () => {
    saved--;
    if (-saved > worst) worst = -saved;
  };
  let i = 0;
  while (i < n) {
    const c = b[i];
    if (WHITE.has(c)) i++;
    else if (c === 37) while (i < n && b[i] !== 10 && b[i] !== 13) i++;
    else if (c === 40) {
      // A string: nested parentheses, and a backslash escapes the next byte.
      let depth = 1;
      i++;
      while (i < n && depth > 0) {
        const x = b[i++];
        if (x === 92) i++;
        else if (x === 40) depth++;
        else if (x === 41) depth--;
      }
    } else if (c === 60 && b[i + 1] === 60) i += 2;
    else if (c === 60) {
      while (i < n && b[i] !== 62) i++;
      i++;
    } else if (c === 47) {
      i++;
      while (i < n && regular(b[i])) i++;
    } else if (DELIMS.has(c)) i++;
    else {
      let j = i;
      let inline = false;
      while (j < n && regular(b[j])) {
        if (b[j] === 66 && b[j + 1] === 73) inline = true;
        j++;
      }
      if (j - i === 1 && c === 113) saved++;
      else for (let k = i; k < j; k++) if (b[k] === 81) restore();
      if (inline) {
        for (let k = j; k < n; k++) if (b[k] === 81) restore();
        return worst;
      }
      i = j;
    }
  }
  return worst;
}

/** Filters this renderer reads content through (pdf-lib's); content behind any other filter isn't drawn. */
const READABLE_FILTERS = new Set(["FlateDecode", "LZWDecode", "ASCII85Decode", "ASCIIHexDecode", "RunLengthDecode"]);

/**
 * A content stream's operators, as this renderer reads them: all of them, or as many as decode before an error (as
 * pdf.js draws those), or none behind a filter or predictor it doesn't read.
 */
function contentOf(pdf: PDFDocument, v: unknown): { data: Uint8Array; whole: boolean } {
  const s = v instanceof PDFRef ? pdf.context.lookup(v) : v;
  const none = { data: new Uint8Array(), whole: false };
  if (!(s instanceof PDFRawStream)) return none;
  const lookup = (x: unknown) => (x instanceof PDFRef ? pdf.context.lookup(x) : x);
  const filter = lookup(s.dict.get(PDFName.of("Filter")));
  const filters = filter instanceof PDFArray ? filter.asArray().map(lookup) : filter === undefined ? [] : [filter];
  if (!filters.every((f) => f instanceof PDFName && READABLE_FILTERS.has(f.decodeText()))) return none;
  const params = lookup(s.dict.get(PDFName.of("DecodeParms")));
  const predicted = (p: unknown) => {
    const d = lookup(p);
    const pr = d instanceof PDFDict ? lookup(d.get(PDFName.of("Predictor"))) : undefined;
    return pr instanceof PDFNumber && pr.asNumber() > 1;
  };
  if (params instanceof PDFArray ? params.asArray().some(predicted) : predicted(params)) return none;
  let stream: { decode: () => Uint8Array; buffer?: Uint8Array; bufferLength?: number };
  try {
    stream = decodePDFRawStream(s) as unknown as typeof stream;
  } catch {
    return none;
  }
  try {
    return { data: stream.decode(), whole: true };
  } catch {
    return { data: stream.buffer ? stream.buffer.slice(0, stream.bufferLength ?? 0) : new Uint8Array(), whole: false };
  }
}

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
/** Content preceded by as many saves as it could restore beyond its own. */
const guarded = (data: Uint8Array) => {
  const d = unbalancedRestores(data);
  return d ? joined([ascii(`${"q ".repeat(d)}\n`), data]) : data;
};

/**
 * Every other content stream a page's content may run (forms, Type 3 glyphs, soft masks), guarded the same way, so
 * none can restore a state saved outside it in any reader. Content this renderer can't read entirely is replaced by what
 * it read, so what every reader draws is exactly what was checked.
 */
function guardContentStreams(pdf: PDFDocument) {
  const ctx = pdf.context;
  const lookup = (x: unknown) => (x instanceof PDFRef ? ctx.lookup(x) : x);
  const run = new Set<PDFRef>();
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
  }
  const skip = new Set(["Filter", "DecodeParms", "Length", "DL"]);
  for (const ref of run) {
    const s = ctx.lookup(ref);
    if (!(s instanceof PDFRawStream)) continue;
    const { data, whole } = contentOf(pdf, s);
    if (whole && unbalancedRestores(data) === 0) continue;
    const fresh = ctx.flateStream(guarded(data));
    for (const [k, v] of s.dict.entries()) if (!skip.has(k.decodeText())) fresh.dict.set(k, v);
    ctx.assign(ref, fresh);
  }
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
 * The page's own content drawn as one form XObject, which readers draw with its own graphics state: whatever the
 * content leaves changed (an extra restore, a moved coordinate system, invisible or stretched text, a clip, an open
 * string or inline image) ends with the form, and what Attest draws next starts from the page's own state. The content
 * is read as pdf.js reads a page (its streams joined, any that doesn't decode left out) and guarded against pdf.js's
 * shared stack; its resources stay its own, so it can't name anything Attest adds.
 */
function isolatePage(pdf: PDFDocument, page: PDFPage, media: Rect4) {
  const ctx = pdf.context;
  const node = page.node;
  const raw = node.get(PDFName.of("Contents"));
  const contents = raw instanceof PDFRef ? ctx.lookup(raw) : raw;
  const data =
    contents instanceof PDFArray
      ? joined(contents.asArray().map((s) => contentOf(pdf, s)).filter((c) => c.whole).map((c) => c.data))
      : contentOf(pdf, contents).data;
  const res = inherited(pdf, node, "Resources");
  const form = ctx.flateStream(guarded(data), {
    Type: "XObject",
    Subtype: "Form",
    BBox: media,
    Resources: res instanceof PDFDict ? res : ctx.obj({}),
  });
  node.set(PDFName.of("Resources"), ctx.obj({ XObject: { AttestPage: ctx.register(form) } }));
  node.set(PDFName.of("Contents"), ctx.register(ctx.flateStream("q /AttestPage Do Q\n")));
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
  guardContentStreams(pdf);
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
  for (const [i, p] of pages.entries()) {
    isolatePage(pdf, p, shown[i].media);
    p.pushOperators(pushGraphicsState(), concatTransformationMatrix(...shown[i].m));
  }
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
  const title = printable(a.title);
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
