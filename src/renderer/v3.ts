// Attest signed copy renderer v3 ("attest.render.v3"). Shared, byte for byte, with the open verifier
// (DataHubz/attest-verifier, src/renderer/v3.ts): a verifier re-makes a signed copy's visible pages from what was
// signed and compares them with the copy. Frozen: a change to what it draws is a new renderer version.
//
// v3 is v2 with one change, in how entries are drawn: everything Attest draws for an entry stays inside the field the
// sender placed. A signature's stamp is laid out within its field (v2 grew a smaller one to 120 by 30 points about its
// center, over the document around it, and set its label and code along the field's top and bottom edges, where the
// document's own lines and labels often are); its parts keep clear of the edges, sit along the bottom of the field as
// a signature sits on its line, and shrink or leave out the stamp's own text in a small field. A text entry wraps or
// shrinks until it fits. Agreements whose completion details name v2 keep v2, unchanged.
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
  PDFRef,
  StandardFonts,
  beginText,
  clip,
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
  fonts: { sans: Uint8Array; bold: Uint8Array; mono: Uint8Array };
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
const STAMP_TEXT = { max: 5, min: 3.4, leading: 1.22 };

/** Where a stamp's parts go: its text (its lines, their size, left edge and middle), the signature's area, and the QR code. */
interface StampPlan { lines: string[]; fs: number; tx: number; mid: number; area: Box; center: boolean; qr: Box | null }

/**
 * The "Signed with Attest" stamp, entirely inside the field the sender placed: a bracket, the signature (an image, or
 * the signer's name), the label, the verification code and the signing day, and a QR code to the certificate. Initials
 * get an "Attest" stamp with the code, and no day or QR code.
 *
 * Everything keeps clear of the field's edges: a tenth of its height (at most 3 points) above and below, and 3% of its
 * width (at most 3 points) at the sides. The bracket, the signature and the text share a band along the bottom of what
 * is left, as a signature sits on its line, which leaves free the top 28% (at most 9 points), where a label above the
 * field often reaches into it. Only the QR code may rise above the band: it is as tall as the field allows within its
 * edges (at most 30 points, and a quarter of its width), centered on the band when it fits in it; one under 12 points,
 * too fine for a phone's camera, is left out.
 *
 * Side by side, the signature comes first, then the text, then the QR code. In a field too tall for that, the text and
 * the QR code go above the signature, when that keeps more of the text with the signature at least 80% as large, or the
 * same text with the signature a quarter larger. The text is as large as fits, at most 5 points and within 36% of the
 * room beside the QR code (initials: 58% of the field); a field too small for it at 3.4 points leaves out the label,
 * then the day, then the code, which the foot of every page carries with the link to verify.
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
  // The text: the label, the code and the day, leaving out lines until it fits at 3.4 points or more.
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
  // A QR code under 12 points has modules too fine for a phone's camera: the field's room goes to the signature.
  const scannable = (q: number) => (q >= 12 ? q : 0);
  // Side by side: the signature, the text, and the QR code as tall as the field allows.
  const side = (): StampPlan => {
    const q = sign && o.qrUrl ? scannable(Math.min(r.h, r.w * 0.25, 30)) : 0;
    const left = r.w - qrGap(q);
    let t = text(band.h, left * (sign ? 0.36 : 0.58));
    // The signature always keeps room: in a field too narrow for both, the text is left out.
    if (left - widest(t.lines, t.fs) - Math.max(2, t.fs) - inset < Math.max(left * 0.2, 4)) t = { lines: [], fs: 0 };
    const tw = widest(t.lines, t.fs);
    const gap = t.lines.length ? Math.max(2, t.fs) : 0;
    const area = { x: r.x + inset, y: band.y + thick, w: left - tw - gap - inset, h: band.h - 2 * thick };
    // The QR code centered on the band when it fits in it, or rising from the band's bottom.
    const qy = q <= band.h ? band.y + (band.h - q) / 2 : r.y;
    return { ...t, tx: r.x + left - tw, mid: band.y + band.h / 2, area, center: !sign, qr: q ? { x: r.x + r.w - q, y: qy, w: q, h: q } : null };
  };
  // Stacked: the text and the QR code above, the signature below.
  const stack = (): StampPlan => {
    const lower = band.h * 0.55;
    const gapV = Math.max(1.5, band.h * 0.05);
    const upper = band.h - lower - gapV;
    const q = sign && o.qrUrl ? scannable(Math.min(upper, r.w * 0.3, 30)) : 0;
    const t = text(upper, r.w - inset - qrGap(q));
    const mid = band.y + lower + gapV + upper / 2;
    const area = { x: r.x + inset, y: band.y + thick, w: r.w - inset, h: lower - thick };
    return { ...t, tx: r.x + inset, mid, area, center: !sign, qr: q ? { x: r.x + r.w - q, y: mid - q / 2, w: q, h: q } : null };
  };
  const a = side();
  const b = stack();
  // Stacked when that keeps more of the text with the signature at least 80% as large, or the same text (no smaller)
  // with the signature a quarter larger.
  const [ma, mb] = [markSize(mark, a.area).h, markSize(mark, b.area).h];
  const plan = (b.lines.length > a.lines.length && mb >= ma * 0.8) || (b.lines.length === a.lines.length && b.fs >= a.fs * 0.9 && mb > ma * 1.25) ? b : a;
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
  const { agreement: a, details: d } = input;
  const code = d.verifyCode;
  const certUrl = code ? `${input.appUrl}/v/${fmtCode(code)}` : `${input.appUrl}/a/${a.id}`;
  const signer = new Map(input.signers.map((s) => [s.commitment, s]));
  const text = await pdf.embedFont(StandardFonts.Helvetica);
  const textBold = await pdf.embedFont(StandardFonts.HelveticaBold);
  let unicode: PDFFont | null = null;
  const unicodeFont = async () => {
    if (!unicode) {
      pdf.registerFontkit(fontkit);
      unicode = await pdf.embedFont(input.fonts.sans, { subset: true });
    }
    return unicode;
  };

  // Each entry where its signer made it (positions are fractions from the top-left), each signature in its stamp.
  const pages = pdf.getPages();
  const adopted = new Map<string, string>();
  for (const [id, type, pageIndex, fx, fy, fw, fh, who] of d.fields) {
    const value = input.entries[id];
    const page = pages[pageIndex];
    if (!value || !page) continue;
    const { width, height } = page.getSize();
    const box = { x: fx * width, y: height - (fy + fh) * height, w: fw * width, h: fh * height };
    if (type === "signature" || type === "initials") {
      const image = value.startsWith("data:image/png;base64,");
      if (type === "signature" && image && !adopted.has(who)) adopted.set(who, value);
      // The stamp stays inside the field, whatever its size.
      const mark = image ? markOf(await pdf.embedPng(value)) : { name: value, font: encodes(textBold, value) ? textBold : await unicodeFont() };
      drawStamp(page, box, mark, { initials: type === "initials", code, signedAt: signer.get(who)?.signedAt ?? null, qrUrl: certUrl, font: text, bold: textBold });
    } else {
      // Helvetica covers Western European text; anything else is set in the embedded Instrument Sans.
      drawEntry(page, value, box, encodes(text, value) ? text : await unicodeFont());
    }
  }
  // A quiet seal line at the foot of every page of the document.
  for (const p of pages) {
    const { width } = p.getSize();
    p.drawLine({ start: { x: 24, y: 20 }, end: { x: width - 24, y: 20 }, thickness: 0.4, color: HAIR });
    p.drawCircle({ x: 28, y: 11, size: 3, color: ACCENT });
    p.drawText(`Sealed by DataHubz Attest${code ? `  ·  ${fmtCode(code)}` : ""}  ·  verify at ${certUrl}`, { x: 36, y: 8.5, size: 6.5, font: text, color: MUTED });
  }
  if (input.variant === "full") await certificatePages(pdf, input, certUrl, adopted, { text, textBold });
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
  await certificatePages(pdf, input, certUrl, new Map(), { text, textBold });
  return finish(pdf);
}

async function certificatePages(pdf: PDFDocument, input: RenderInputV3, certUrl: string, adopted: Map<string, string>, std: { text: PDFFont; textBold: PDFFont }) {
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
  const ordered = d.signers.map((c) => input.signers.find((s) => s.commitment === c)).filter((s): s is RenderInputV3["signers"][number] => Boolean(s));

  // ---- The certificate -------------------------------------------------------------------------------
  const p = pdf.addPage([W, H]);
  header(p, "Certificate of completion");
  seal(p, bold, W - M - 50, H - 128 - 6, 52);
  let y = H - 128 - 46;
  for (const ln of wrap(a.title, bold, 15, W - 2 * M - 120)) {
    p.drawText(ln, { x: M, y, size: 15, font: bold, color: INK });
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
  r = fact(M + col, y, "Zero-knowledge proofs", "Each party can prove they signed, and when, without revealing the document: verified on zkVerify");
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
    const mark = img ? markOf(await pdf.embedPng(img)) : { name: s.name, font: encodes(std.textBold, s.name) ? std.textBold : bold };
    drawStamp(sp, { x: M, y: y - 42, w: 170, h: 42 }, mark, { initials: false, code: d.verifyCode, signedAt: s.signedAt, qrUrl: certUrl, font: std.text, bold: std.textBold });
    const x2 = M + 190;
    sp.drawText(s.name, { x: x2, y: y - 14, size: 9.5, font: bold, color: INK });
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
      const line = (EVENT_TEXT[type] ?? ((w: string) => `${type} ${w}`))(who ?? "the sender");
      t.drawCircle({ x: M + 4, y: yy + 3, size: 2.6, color: type === "completed" ? SUCCESS : ACCENT });
      t.drawText(fmtUtc(at), { x: M + 16, y: yy, size: 8, font: mono, color: MUTED });
      t.drawText(line, { x: M + 210, y: yy, size: 9.5, font: sans, color: INK });
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
    ["With no Attest service", "This certificate carries its own verifier. Open its attachments (any PDF reader lists them), save attest-verifier.html anywhere, open it in any browser and drop this PDF on it. It checks every step below on your device, reading only the public blockchain, and re-makes these pages from what was signed and anchored to show they are exactly Attest's certificate."],
    ["The document", `The document stays with the parties: Attest never had it. Its SHA-256 is ${a.documentSha256}, the fingerprint every signer's statement names, and each party's signed copy carries it.`],
    ["Each signature", "attest-evidence.json, attached, holds for every signer the exact statement they signed, their passkey's public key, and the WebAuthn signature. Any WebAuthn library checks it: the signature covers the authenticator data and the SHA-256 of the client data, whose challenge is the SHA-256 of the statement."],
    ["The anchor", a.anchorTxHash ? `The evidence holds the exact signed-state text (SHA-256 ${a.completionHash}) and its Merkle path to the root that Horizen transaction ${a.anchorTxHash} recorded, and Attest's own anchor of the agreement, its signatures and these details. Any Horizen node confirms them.` : "The anchoring transaction appears on the live verification page as soon as it confirms."],
    ["The proofs", "Each party can prove they signed, and when, with a zero-knowledge proof (Groth16) that reveals nothing else, verified on zkVerify, an independent network."],
    ["The standards", "WebAuthn (W3C) for signatures, SHA-256 (NIST FIPS 180-4) for fingerprints, Merkle trees for anchoring, Groth16 for zero-knowledge proofs. No proprietary format anywhere."],
  ] : [
    ["With no Attest service", "This PDF carries its own verifier. Open its attachments (any PDF reader lists them), save attest-verifier.html anywhere, open it in any browser and drop this PDF on it. It checks every step below on your device, reading only the public blockchain, and re-makes these pages from what was signed to show they are exactly the signed copy."],
    ["The document", `original-document.pdf, attached, is the document exactly as it was signed: its SHA-256 is ${a.documentSha256}, the fingerprint every signer's statement names.`],
    ["Each signature and entry", "attest-evidence.json, attached, holds for every signer the exact statement they signed, the exact text of their entries (its SHA-256 is in the statement), their passkey's public key, and the WebAuthn signature. Any WebAuthn library checks it: the signature covers the authenticator data and the SHA-256 of the client data, whose challenge is the SHA-256 of the statement."],
    ["The anchor", a.anchorTxHash ? `The evidence holds the exact signed-state text (SHA-256 ${a.completionHash}) and its Merkle path to the root that Horizen transaction ${a.anchorTxHash} recorded, and Attest's own anchor of the agreement, its signatures and these details. Any Horizen node confirms them.` : "The anchoring transaction appears on the live verification page as soon as it confirms."],
    ["The proofs", "Each party can prove they signed, and when, with a zero-knowledge proof (Groth16) that reveals nothing else, verified on zkVerify, an independent network."],
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
