// Renderer v3: what pdf.js draws for a form field, so a signed copy shows every value the signer saw.
//
// pdf.js (6.4.299, as the signing page opens documents: print, enableXfa false, its own standard fonts) draws a field's
// value itself when the field has no appearance of its own and the form asks readers to make appearances
// (NeedAppearances), or when the value comes from the form's XFA dataset; it then generates the appearance from the
// field's default appearance (DA): its font and size (or a size fitted to the field), comb and multiline layout,
// alignment, and the border and background of its MK dictionary. A checkbox or radio button whose value names no
// appearance of its own gets pdf.js's own check or disc. This file follows pdf.js's code step for step
// (WidgetAnnotation, TextWidgetAnnotation, ChoiceWidgetAnnotation, ButtonWidgetAnnotation, the font metrics it reads in
// PartialEvaluator.translateFont and Font, and its XFA DatasetReader), so the content it generates is the content pdf.js
// generates, operator for operator, and the copy flattens it. Where pdf.js draws with a font of the browser's own (a
// value the field's font can't encode), the copy draws the value with a font it embeds, and the document is marked as
// not reproduced exactly. A byte-identical copy lives in DataHubz/attest-verifier (src/renderer/fields-v3.ts).
//
// Its code follows pdf.js's (Copyright Mozilla Foundation, Apache License 2.0), rewritten over pdf-lib's objects, with
// no built-in newer than ES2020 (Math.sumPrecise, which pdf.js uses, is summed here), so every engine computes the same.
import { PDFArray, PDFBool, PDFDict, PDFHexString, PDFName, PDFNumber, PDFRawStream, PDFRef, PDFString, type PDFContext, type PDFDocument, type PDFObject } from "pdf-lib";
import { stringBytes } from "./decrypt-v3";
import { XFA_MAX_DEPTH, xfaTextContent } from "./xfa-text-v3";
import { BASIC_METRICS, DINGBATS_UNICODE, ENCODINGS, GLYPHS_UNICODE, METRICS, NON_STD_FONT_MAP, SERIF_FONTS, STANDARD_FILE_METRICS, STANDARD_TYPE1_FILES, STD_FONT_MAP, SYMBOLS_FONTS } from "./fonts-data-v3";

// ---- pdf.js's helpers ----------------------------------------------------------------------------------------------

const LINE_FACTOR = 1.35;
const LINE_DESCENT_FACTOR = 0.35;
const BASELINE_FACTOR = LINE_DESCENT_FACTOR / LINE_FACTOR;

/** numberToString (core_utils.js). */
export function numberToString(value: number): string {
  if (Number.isInteger(value)) return value.toString();
  const rounded = Math.round(value * 100);
  if (rounded % 100 === 0) return (rounded / 100).toString();
  return rounded % 10 === 0 ? value.toFixed(1) : value.toFixed(2);
}
/** escapeString (core_utils.js). */
const escapeString = (str: string) => str.replace(/([()\\\n\r])/g, (m) => (m === "\n" ? "\\n" : m === "\r" ? "\\r" : `\\${m}`));
/** escapePDFName (core_utils.js). */
function escapePDFName(str: string): string {
  const buffer: string[] = [];
  let start = 0;
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    if (c < 0x21 || c > 0x7e || c === 0x23 || c === 0x28 || c === 0x29 || c === 0x3c || c === 0x3e || c === 0x5b || c === 0x5d || c === 0x7b || c === 0x7d || c === 0x2f || c === 0x25) {
      if (start < i) buffer.push(str.substring(start, i));
      buffer.push(`#${c.toString(16).padStart(2, "0")}`);
      start = i + 1;
    }
  }
  if (buffer.length === 0) return str;
  if (start < str.length) buffer.push(str.substring(start));
  return buffer.join("");
}
const latin1 = (b: Uint8Array) => {
  let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return s;
};
const PDF_TRANSLATE: number[] = (() => {
  const t = new Array(256).fill(0);
  [0x2d8, 0x2c7, 0x2c6, 0x2d9, 0x2dd, 0x2db, 0x2da, 0x2dc].forEach((v, i) => (t[0x18 + i] = v));
  [0x2022, 0x2020, 0x2021, 0x2026, 0x2014, 0x2013, 0x192, 0x2044, 0x2039, 0x203a, 0x2212, 0x2030, 0x201e, 0x201c, 0x201d, 0x2018, 0x2019, 0x201a, 0x2122, 0xfb01, 0xfb02, 0x141, 0x152, 0x160, 0x178, 0x17d, 0x131, 0x142, 0x153, 0x161, 0x17e, 0, 0x20ac].forEach((v, i) => (t[0x80 + i] = v));
  return t;
})();
/** stringToPDFString (string_utils.js): a PDF text string, from its bytes as a string of char codes. */
function stringToPDFString(str: string): string {
  if (str[0] >= "\xEF") {
    let encoding: string | null = null;
    if (str[0] === "\xFE" && str[1] === "\xFF") {
      encoding = "utf-16be";
      if (str.length % 2 === 1) str = str.slice(0, -1);
    } else if (str[0] === "\xFF" && str[1] === "\xFE") {
      encoding = "utf-16le";
      if (str.length % 2 === 1) str = str.slice(0, -1);
    } else if (str[0] === "\xEF" && str[1] === "\xBB" && str[2] === "\xBF") encoding = "utf-8";
    if (encoding) {
      try {
        const decoded = new TextDecoder(encoding, { fatal: true }).decode(Uint8Array.from(str, (c) => c.charCodeAt(0) & 0xff));
        return !decoded.includes("\x1b") ? decoded : decoded.replace(/\x1b[^\x1b]*(?:\x1b|$)/g, "");
      } catch {
        // pdf.js warns and reads it as PDFDocEncoding.
      }
    }
  }
  const buf: string[] = [];
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if (code === 0x1b) {
      while (++i < str.length && str.charCodeAt(i) !== 0x1b) {}
      continue;
    }
    const t = PDF_TRANSLATE[code];
    buf.push(t ? String.fromCharCode(t) : str.charAt(i));
  }
  return buf.join("");
}
/** stringToUTF8String (decodeURIComponent of escape), as pdf.js reads XFA. */
function stringToUTF8String(str: string): string {
  return decodeURIComponent((globalThis as unknown as { escape(s: string): string }).escape(str));
}
/** The colour of a DA or MK colour array, as pdf.js converts it (ColorSpaceUtils gray, rgb or cmyk into a Uint8ClampedArray). */
function rgbOf(values: number[], into: Uint8ClampedArray): void {
  if (values.length === 1) into[0] = into[1] = into[2] = values[0] * 255;
  else if (values.length === 3) {
    into[0] = values[0] * 255;
    into[1] = values[1] * 255;
    into[2] = values[2] * 255;
  } else if (values.length === 4) {
    const [c, m, y, k] = values;
    into[0] = 255 + c * (-4.387332384609988 * c + 54.48615194189176 * m + 18.82290502165302 * y + 212.25662451639585 * k + -285.2331026137004) + m * (1.7149763477362134 * m - 5.6096736904047315 * y + -17.873870861415444 * k - 5.497006427196366) + y * (-2.5217340131683033 * y - 21.248923337353073 * k + 17.5119270841813) + k * (-21.86122147463605 * k - 189.48180835922747);
    into[1] = 255 + c * (8.841041422036149 * c + 60.118027045597366 * m + 6.871425592049007 * y + 31.159100130055922 * k + -79.2970844816548) + m * (-15.310361306967817 * m + 17.575251261109482 * y + 131.35250912493976 * k - 190.9453302588951) + y * (4.444339102852739 * y + 9.8632861493405 * k - 24.86741582555878) + k * (-20.737325471181034 * k - 187.80453709719578);
    into[2] = 255 + c * (0.8842522430003296 * c + 8.078677503112928 * m + 30.89978309703729 * y - 0.23883238689178934 * k + -14.183576799673286) + m * (10.49593273432072 * m + 63.02378494754052 * y + 50.606957656360734 * k - 112.23884253719248) + y * (0.03296041114873217 * y + 115.60384449646641 * k + -193.58209356861505) + k * (-22.33816807309886 * k - 180.12613974708367);
  }
}
/** getPdfColor (default_appearance.js). */
function getPdfColor(color: Uint8ClampedArray, isFill: boolean): string {
  if (color[0] === color[1] && color[1] === color[2]) return `${numberToString(color[0] / 255)} ${isFill ? "g" : "G"}`;
  return Array.from(color, (c) => numberToString(c / 255)).join(" ") + ` ${isFill ? "rg" : "RG"}`;
}
/** getRotationMatrix (core_utils.js). */
function rotationMatrix(rotation: number, width: number, height: number): number[] {
  switch (rotation) {
    case 90:
      return [0, 1, -1, 0, width, 0];
    case 180:
      return [-1, 0, 0, -1, width, height];
    case 270:
      return [0, -1, 1, 0, 0, height];
    default:
      return [1, 0, 0, 1, 0, 0];
  }
}
/**
 * Math.sumPrecise, as pdf.js sums glyph widths: the exact sum, rounded once (Shewchuk's partials, then a correctly
 * rounded total, as Python's math.fsum), in plain arithmetic so every engine gets the same number.
 */
export function sumPrecise(values: number[]): number {
  if (values.length === 0) return -0;
  const partials: number[] = [];
  for (let x of values) {
    let i = 0;
    for (let y of partials) {
      if (Math.abs(x) < Math.abs(y)) [x, y] = [y, x];
      const hi = x + y;
      const lo = y - (hi - x);
      if (lo !== 0) partials[i++] = lo;
      x = hi;
    }
    partials.length = i;
    partials.push(x);
  }
  let n = partials.length;
  let hi = 0;
  if (n > 0) {
    hi = partials[--n];
    let lo = 0;
    while (n > 0) {
      const x = hi;
      const y = partials[--n];
      hi = x + y;
      const yr = hi - x;
      lo = y - yr;
      if (lo !== 0) break;
    }
    if (n > 0 && ((lo < 0 && partials[n - 1] < 0) || (lo > 0 && partials[n - 1] > 0))) {
      const y = lo * 2;
      const x = hi + y;
      const yr = x - hi;
      if (y === yr) hi = x;
    }
  }
  return hi;
}

/** Whether pdf.js's bidi() finds a string right to left. */
function isRtl(str: string): boolean {
  let numBidi = 0;
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    if ((c >= 0x0590 && c <= 0x05f4) || (c >= 0x0600 && c <= 0x06ff && c !== 0x061d) || (c >= 0x0700 && c <= 0x08ac) || (c >= 0xfb50 && c <= 0xfdff) || (c >= 0xfe70 && c <= 0xfeff)) {
      // Arabic: pdf.js's arabicTypes give AN, AL, ET, CS, ON or NSM; only AN and AL count, with R.
      if (c >= 0x0600 && c <= 0x06ff) {
        const k = c & 0xff;
        const an = (k <= 0x05) || (k >= 0x60 && k <= 0x69) || k === 0x6b || k === 0x6c || k === 0xdd;
        const al = !an && !(k === 0x06 || k === 0x07 || k === 0x09 || k === 0x0a || k === 0x0c || k === 0x0e || k === 0x0f || (k >= 0x10 && k <= 0x1a) || (k >= 0x4b && k <= 0x5f) || k === 0x6a || k === 0x70 || (k >= 0xd6 && k <= 0xdc) || k === 0xde || (k >= 0xdf && k <= 0xe4) || k === 0xe7 || k === 0xe8 || (k >= 0xea && k <= 0xed) || (k >= 0xf0 && k <= 0xf9));
        if (an || al) numBidi++;
      } else numBidi++;
    }
  }
  if (numBidi === 0) return false;
  return !(numBidi / str.length < 0.3 && str.length > 4);
}

// ---- The content lexer, as pdf.js reads a DA string --------------------------------------------------------------

type Tok = { k: "num"; v: number } | { k: "name"; v: string } | { k: "op"; v: string } | { k: "str"; v: string } | { k: "other" };
const WHITE = (c: number) => c === 0x20 || c === 0x0a || c === 0x0d || c === 0x09 || c === 0x0c || c === 0x00;
const DELIM = (c: number) => c === 0x28 || c === 0x29 || c === 0x3c || c === 0x3e || c === 0x5b || c === 0x5d || c === 0x7b || c === 0x7d || c === 0x2f || c === 0x25;
function* tokens(s: string): Generator<Tok> {
  let i = 0;
  const n = s.length;
  while (i < n) {
    const c = s.charCodeAt(i);
    if (WHITE(c)) { i++; continue; }
    if (c === 0x25) { while (i < n && s[i] !== "\n" && s[i] !== "\r") i++; continue; }
    if (c === 0x2f) {
      let j = i + 1, name = "";
      while (j < n && !WHITE(s.charCodeAt(j)) && !DELIM(s.charCodeAt(j))) {
        if (s[j] === "#" && /^[0-9A-Fa-f]{2}$/.test(s.slice(j + 1, j + 3))) { name += String.fromCharCode(parseInt(s.slice(j + 1, j + 3), 16)); j += 3; continue; }
        name += s[j++];
      }
      i = j;
      yield { k: "name", v: name };
      continue;
    }
    if ((c >= 0x30 && c <= 0x39) || c === 0x2b || c === 0x2d || c === 0x2e) {
      let j = i, sign = 1;
      if (s[j] === "-") { sign = -1; j++; if (s[j] === "-") j++; } else if (s[j] === "+") j++;
      let base = 0, divideBy = 0, digits = 0;
      for (; j < n; j++) {
        const d = s.charCodeAt(j);
        if (d >= 0x30 && d <= 0x39) { base = base * 10 + (d - 0x30); if (divideBy) divideBy *= 10; digits++; } else if (d === 0x2e) { if (divideBy) break; divideBy = 1; } else break;
      }
      i = j;
      yield digits ? { k: "num", v: sign * (divideBy ? base / divideBy : base) } : { k: "num", v: 0 };
      continue;
    }
    if (c === 0x28) {
      let depth = 1, j = i + 1;
      for (; j < n && depth; j++) { if (s[j] === "\\") j++; else if (s[j] === "(") depth++; else if (s[j] === ")") depth--; }
      i = j;
      yield { k: "str", v: "" };
      continue;
    }
    if (DELIM(c)) { i++; yield { k: "other" }; continue; }
    let j = i;
    while (j < n && !WHITE(s.charCodeAt(j)) && !DELIM(s.charCodeAt(j))) j++;
    yield { k: "op", v: s.slice(i, j) };
    i = j;
  }
}
const DA_OPS: Record<string, number> = { Tf: 2, g: 1, rg: 3, k: 4, q: 0, Q: 0, G: 1, RG: 3, K: 4, cs: 1, sc: -4, scn: -33, CS: 1, SC: -4, SCN: -33, BT: 0, ET: 0, Td: 2, Tm: 6, cm: 6, w: 1, re: 4, f: 0, S: 0, n: 0, BMC: 1, EMC: 0, Tj: 1, TL: 1, Tc: 1, Tw: 1, Tz: 1, Ts: 1, Tr: 1, gs: 1 };

/** parseDefaultAppearance: the font name, size and colour of a DA string. */
export function parseDefaultAppearance(da: string): { fontName: string; fontSize: number; fontColor: Uint8ClampedArray } {
  const result = { fontName: "", fontSize: 0, fontColor: new Uint8ClampedArray(3) };
  let args: Tok[] = [];
  const pending: Tok[] = [];
  let depth = 0;
  for (const t of tokens(da)) {
    if (t.k !== "op") { args.push(t); if (args.length > 33) break; continue; }
    const count = DA_OPS[t.v];
    if (count === undefined) continue;
    let a = args;
    args = [];
    if (count >= 0 && a.length !== count) {
      while (a.length > count) pending.push(a.shift()!);
      while (a.length < count && pending.length) a.unshift(pending.pop()!);
      if (a.length < count) continue;
    }
    if (t.v === "q") { depth++; continue; }
    if (t.v === "Q") { if (depth > 0) depth--; continue; }
    if (depth !== 0) continue;
    const nums = a.map((x) => (x.k === "num" ? x.v : NaN));
    if (t.v === "Tf") {
      if (a[0].k === "name") result.fontName = a[0].v;
      if (a[1].k === "num" && a[1].v > 0) result.fontSize = a[1].v;
    } else if (t.v === "rg" || t.v === "g" || t.v === "k") rgbOf(nums, result.fontColor);
  }
  return result;
}

// ---- XFA dataset values ------------------------------------------------------------------------------------------

type XNode = { name: string; value?: string; children: XNode[] | null; parent: XNode | null };
/** pdf.js's SimpleXMLParser (with its entity rules), keeping only what DatasetReader reads. */
function parseXml(s: string, stopAt: string | null): XNode | null {
  const resolve = (t: string) => t.replace(/&(?:#x([^;&]+)|#([^;&]+)|([^;&]+));/g, (all, hex, dec, entity) => {
    if (hex || dec) {
      const code = hex ? parseInt(hex, 16) : parseInt(dec, 10);
      return code >= 0 && code <= 0x10ffff ? String.fromCodePoint(code) : all;
    }
    return ({ lt: "<", gt: ">", amp: "&", quot: '"', apos: "'" } as Record<string, string>)[entity] ?? `&${entity};`;
  });
  const isWs = (c: string) => c === " " || c === "\n" || c === "\r" || c === "\t";
  let fragment: XNode[] = [];
  const stack: XNode[][] = [];
  let found: XNode | null = null;
  let i = 0;
  const fail = () => null;
  while (i < s.length) {
    let j = i;
    if (s[i] === "<") {
      j++;
      const c2 = s[j];
      if (c2 === "/") {
        j++;
        const q = s.indexOf(">", j);
        if (q < 0) return stopAt ? found : fail();
        const name = s.substring(j, q);
        fragment = stack.pop() || [];
        const last = fragment[fragment.length - 1];
        if (last) {
          for (const ch of last.children ?? []) ch.parent = last;
          if (stopAt && name === stopAt) return last;
        }
        j = q + 1;
      } else if (c2 === "?") {
        j++;
        let p = j;
        while (p < s.length && !isWs(s[p]) && s[p] !== ">" && s[p] !== "?" && s[p] !== "/") p++;
        while (p < s.length && isWs(s[p])) p++;
        while (p < s.length && (s[p] !== "?" || s[p + 1] !== ">")) p++;
        if (s.substring(p, p + 2) !== "?>") return stopAt ? found : fail();
        j = p + 2;
      } else if (c2 === "!") {
        if (s.substring(j + 1, j + 3) === "--") {
          const q = s.indexOf("-->", j + 3);
          if (q < 0) return stopAt ? found : fail();
          j = q + 3;
        } else if (s.substring(j + 1, j + 8) === "[CDATA[") {
          const q = s.indexOf("]]>", j + 8);
          if (q < 0) return stopAt ? found : fail();
          fragment.push({ name: "#text", value: s.substring(j + 8, q), children: null, parent: null });
          j = q + 3;
        } else if (s.substring(j + 1, j + 8) === "DOCTYPE") {
          const q2 = s.indexOf("[", j + 8);
          let q = s.indexOf(">", j + 8);
          if (q < 0) return stopAt ? found : fail();
          let complex = false;
          if (q2 > 0 && q > q2) {
            q = s.indexOf("]>", j + 8);
            if (q < 0) return stopAt ? found : fail();
            complex = true;
          }
          j = q + (complex ? 2 : 1);
        } else return stopAt ? found : fail();
      } else {
        // An element: its name, then attributes (skipped as pdf.js parses them), then > or />.
        let p = j;
        while (p < s.length && !isWs(s[p]) && s[p] !== ">" && s[p] !== "/") p++;
        const name = s.substring(j, p);
        while (p < s.length && isWs(s[p])) p++;
        let bad = false;
        while (p < s.length && s[p] !== ">" && s[p] !== "/" && s[p] !== "?") {
          while (p < s.length && isWs(s[p])) p++;
          while (p < s.length && !isWs(s[p]) && s[p] !== "=") p++;
          while (p < s.length && isWs(s[p])) p++;
          if (s[p] !== "=") { bad = true; break; }
          p++;
          while (p < s.length && isWs(s[p])) p++;
          const q = s[p];
          if (q !== '"' && q !== "'") { bad = true; break; }
          const end = s.indexOf(q, ++p);
          if (end < 0) { bad = true; break; }
          p = end + 1;
          while (p < s.length && isWs(s[p])) p++;
        }
        if (bad) return stopAt ? found : fail();
        let closed = false;
        if (s.substring(p, p + 2) === "/>") closed = true;
        else if (s.substring(p, p + 1) !== ">") return stopAt ? found : fail();
        const node: XNode = { name, children: [], parent: null };
        fragment.push(node);
        if (!closed) {
          stack.push(fragment);
          fragment = node.children!;
        }
        j = p + (closed ? 2 : 1);
      }
    } else {
      while (j < s.length && s[j] !== "<") j++;
      const text = resolve(s.substring(i, j));
      if (![...text].every((c) => isWs(c))) fragment.push({ name: "#text", value: text, children: null, parent: null });
    }
    i = j;
  }
  if (stopAt) return found;
  return fragment[0] ?? null;
}
/** The signing viewer's bounded SimpleDOMNode.textContent, with no partial value on failure. */
function textContent(n: XNode): string {
  return xfaTextContent(n, (x) => x.children, (x) => x.value);
}
/** SimpleDOMNode.searchNode. */
function searchNode(root: XNode, paths: { name: string; pos: number }[], pos: number): XNode | null {
  // The viewer's worker enforces the same path limit before its recursive search.
  if (paths.length > XFA_MAX_DEPTH) throw new RangeError("XFA path nesting limit exceeded");
  if (pos >= paths.length) return root;
  const component = paths[pos];
  if (component.name.startsWith("#") && pos < paths.length - 1) return searchNode(root, paths, pos + 1);
  const stack: [XNode, number][] = [];
  let node = root;
  for (;;) {
    if (component.name === node.name) {
      if (component.pos === 0) {
        const res = searchNode(node, paths, pos + 1);
        if (res !== null) return res;
      } else if (stack.length === 0) return null;
      else {
        const [parent] = stack.pop()!;
        let siblingPos = 0;
        for (const child of parent.children!) {
          if (component.name === child.name) {
            if (siblingPos === component.pos) return searchNode(child, paths, pos + 1);
            siblingPos++;
          }
        }
        return searchNode(node, paths, pos + 1);
      }
    }
    if (node.children && node.children.length > 0) {
      stack.push([node, 0]);
      node = node.children[0];
    } else if (stack.length === 0) return null;
    else {
      while (stack.length !== 0) {
        const [parent, current] = stack.pop()!;
        const next = current + 1;
        if (next < parent.children!.length) {
          stack.push([parent, next]);
          node = parent.children![next];
          break;
        }
      }
      if (stack.length === 0) return null;
    }
  }
}
const decodeXfaString = (s: string) => {
  try {
    return stringToUTF8String(s);
  } catch {
    return s;
  }
};
/** pdf.js's DatasetReader over the form's XFA, or null when pdf.js has none. */
function datasetReader(pdf: PDFDocument, acroForm: PDFDict, decode: (s: PDFRawStream) => Uint8Array | null): ((path: string) => string | string[]) | null {
  const look = (v: unknown) => (v instanceof PDFRef ? pdf.context.lookup(v) : v);
  const xfa = look(acroForm.get(PDFName.of("XFA")));
  const entries = new Map<string, PDFRawStream | null>(["xdp:xdp", "template", "datasets", "config", "connectionSet", "localeSet", "stylesheet", "/xdp:xdp"].map((e) => [e, null]));
  if (xfa instanceof PDFRawStream) {
    const d = decode(xfa);
    if (!d || !d.length) return null;
    entries.set("xdp:xdp", xfa);
  } else {
    if (!(xfa instanceof PDFArray) || xfa.size() === 0) return null;
    const items = xfa.asArray();
    for (let i = 0; i < items.length; i += 2) {
      let name: string;
      if (i === 0) name = "xdp:xdp";
      else if (i === items.length - 2) name = "/xdp:xdp";
      else {
        const n = items[i];
        name = n instanceof PDFString || n instanceof PDFHexString ? latin1(stringBytes(n)) : "";
      }
      if (!entries.has(name)) continue;
      const data = look(items[i + 1]);
      if (!(data instanceof PDFRawStream)) continue;
      const bytes = decode(data);
      if (!bytes || !bytes.length) continue;
      entries.set(name, data);
    }
  }
  for (const key of ["datasets", "xdp:xdp"]) {
    const stream = entries.get(key);
    if (!stream) continue;
    let str: string;
    try {
      str = stringToUTF8String(latin1(decode(stream) ?? new Uint8Array()));
    } catch {
      return null;
    }
    const node = key === "datasets" ? parseXml(str, null) : parseXml(str, "xfa:datasets");
    // pdf.js reads a datasets packet's document element, and has no dataset at all when it can't parse one.
    if (key === "datasets" && !node) return null;
    return (path: string) => {
      if (!node || !path) return "";
      const paths = path.split(".").map((c) => {
        const m = /^(.+)\[(\d+)\]$/.exec(c);
        return m ? { name: m[1], pos: parseInt(m[2], 10) } : { name: c, pos: 0 };
      });
      const found = searchNode(node, paths, 0);
      if (!found) return "";
      const first = found.children?.[0];
      return first?.name === "value" ? (found.children ?? []).map((c) => decodeXfaString(textContent(c))) : decodeXfaString(textContent(found));
    };
  }
  return null;
}

// ---- Fonts, as pdf.js measures them -----------------------------------------------------------------------------

const table = (s: string, conv: (v: string) => number) => new Map(s.split(";").map((e) => { const k = e.lastIndexOf(":"); return [e.slice(0, k), conv(e.slice(k + 1))] as [string, number]; }));
let glyphsUnicodeCache: Map<string, number> | null = null;
const glyphsUnicode = () => (glyphsUnicodeCache ??= table(GLYPHS_UNICODE, (v) => parseInt(v, 16)));
const strTable = (s: string) => new Map(s.split(";").map((e) => { const k = e.indexOf(":"); return [e.slice(0, k), e.slice(k + 1)] as [string, string]; }));
let stdMapCache: Map<string, string> | null = null, nonStdMapCache: Map<string, string> | null = null;
const stdFontMap = () => (stdMapCache ??= strTable(STD_FONT_MAP));
const nonStdFontMap = () => (nonStdMapCache ??= strTable(NON_STD_FONT_MAP));
const serifFonts = new Set(SERIF_FONTS.split(";"));
const symbolsFonts = new Set(SYMBOLS_FONTS.split(";"));
const encodingCache = new Map<string, string[]>();
const encoding = (name: string) => {
  let e = encodingCache.get(name);
  if (!e) encodingCache.set(name, (e = ENCODINGS[name].split(" ")));
  return e;
};
const normalizeFontName = (name: string) => name.replace(/[,_]/g, "-").replace(/\s/g, "");
const standardFontName = (name: string) => stdFontMap().get(normalizeFontName(name));
const isSerifFont = (base: string) => {
  const w = base.split("-", 1)[0];
  return serifFonts.has(w) || /serif/i.test(w);
};
const metricsCache = new Map<string, Map<string, number> | number>();
/** getBaseFontMetrics. */
function baseFontMetrics(name: string): { defaultWidth: number; widths: Map<string, number> } {
  let fontName = normalizeFontName(name);
  fontName = stdFontMap().get(fontName) || fontName;
  const key = METRICS[fontName] !== undefined ? fontName : isSerifFont(name) ? "Times-Roman" : "Helvetica";
  let m = metricsCache.get(key);
  if (m === undefined) metricsCache.set(key, (m = /^\d+$/.test(METRICS[key]) ? Number(METRICS[key]) : table(METRICS[key], Number)));
  return typeof m === "number" ? { defaultWidth: m, widths: new Map() } : { defaultWidth: 0, widths: m };
}
/** getUnicodeForGlyph. */
function unicodeForGlyph(name: string): number {
  const u = glyphsUnicode().get(name);
  if (u !== undefined) return u;
  if (!name) return -1;
  if (name[0] === "u") {
    const len = name.length;
    let hex: string;
    if (len === 7 && name[1] === "n" && name[2] === "i") hex = name.substring(3);
    else if (len >= 5 && len <= 7) hex = name.substring(1);
    else return -1;
    if (hex === hex.toUpperCase()) {
      const v = parseInt(hex, 16);
      if (v >= 0) return v;
    }
  }
  return -1;
}

/** A ToUnicode CMap's map (pdf.js CMapFactory over a stream: bfchar and bfrange), in pdf.js's order, or null. */
function readToUnicode(bytes: Uint8Array): Map<number, string> | null {
  const s = latin1(bytes);
  const toks: ({ k: "str"; v: string } | { k: "num"; v: number } | { k: "cmd"; v: string } | { k: "name"; v: string })[] = [];
  for (let i = 0; i < s.length; ) {
    const c = s[i];
    if (/\s/.test(c)) { i++; continue; }
    if (c === "%") { while (i < s.length && s[i] !== "\n" && s[i] !== "\r") i++; continue; }
    if (c === "<" && s[i + 1] !== "<") {
      const end = s.indexOf(">", i);
      if (end < 0) break;
      toks.push({ k: "str", v: latin1(hexBytesOf(s.slice(i + 1, end))) });
      i = end + 1;
      continue;
    }
    if (c === "[" || c === "]") { toks.push({ k: "cmd", v: c }); i++; continue; }
    if (c === "/") { let j = i + 1; while (j < s.length && !/[\s/<>\[\]()%{}]/.test(s[j])) j++; toks.push({ k: "name", v: s.slice(i + 1, j) }); i = j; continue; }
    if (/[0-9+\-.]/.test(c)) { let j = i + 1; while (j < s.length && /[0-9.]/.test(s[j])) j++; toks.push({ k: "num", v: Number(s.slice(i, j)) }); i = j; continue; }
    let j = i;
    while (j < s.length && !/[\s/<>\[\]()%{}]/.test(s[j])) j++;
    if (j === i) j++;
    toks.push({ k: "cmd", v: s.slice(i, j) });
    i = j;
  }
  const map = new Map<number, string>();
  const strToInt = (x: string) => { let a = 0; for (let i = 0; i < x.length; i++) a = (a << 8) | x.charCodeAt(i); return a >>> 0; };
  let identity = false;
  for (let t = 0; t < toks.length; t++) {
    const tok = toks[t];
    if (tok.k === "name" && tok.v === "Identity-H" && toks[t + 1]?.k === "cmd" && toks[t + 1].v === "usecmap") identity = true;
    if (tok.k !== "cmd") continue;
    if (tok.v === "endcmap") break;
    if (tok.v === "beginbfchar") {
      for (t++; t < toks.length; t += 2) {
        const a = toks[t], b = toks[t + 1];
        if (a.k === "cmd" && a.v === "endbfchar") break;
        if (a.k !== "str" || !b || b.k !== "str") return null;
        map.set(strToInt(a.v), b.v);
      }
    } else if (tok.v === "beginbfrange") {
      for (t++; t < toks.length; ) {
        const a = toks[t];
        if (a.k === "cmd" && a.v === "endbfrange") break;
        const b = toks[t + 1], d = toks[t + 2];
        if (a.k !== "str" || !b || b.k !== "str" || !d) return null;
        let low = strToInt(a.v);
        const high = strToInt(b.v);
        if (d.k === "str" || d.k === "num") {
          let dst = d.k === "num" ? String.fromCharCode(d.v) : d.v;
          const last = dst.length - 1;
          while (low <= high) {
            map.set(low++, dst);
            const next = dst.charCodeAt(last) + 1;
            if (next > 0xff) { dst = dst.substring(0, last - 1) + String.fromCharCode(dst.charCodeAt(last - 1) + 1) + "\x00"; continue; }
            dst = dst.substring(0, last) + String.fromCharCode(next);
          }
          t += 3;
        } else if (d.k === "cmd" && d.v === "[") {
          let k = t + 3;
          while (k < toks.length && !(toks[k].k === "cmd" && toks[k].v === "]")) {
            const x = toks[k];
            if (low <= high) map.set(low++, x.k === "str" ? x.v : x.k === "num" ? String.fromCharCode(x.v) : "");
            k++;
          }
          t = k + 1;
        } else return null;
      }
    }
  }
  if (identity && map.size === 0) return null;
  // readToUnicode: each entry's bytes as UTF-16BE.
  const out = new Map<number, string>();
  for (const [code, token] of map) {
    let tk = token;
    if (tk.length % 2 !== 0) tk = "\u0000" + tk;
    const chars: number[] = [];
    for (let k = 0; k < tk.length; k += 2) {
      const w1 = (tk.charCodeAt(k) << 8) | tk.charCodeAt(k + 1);
      if ((w1 & 0xf800) !== 0xd800) { chars.push(w1); continue; }
      k += 2;
      const w2 = (tk.charCodeAt(k) << 8) | tk.charCodeAt(k + 1);
      chars.push(((w1 & 0x3ff) << 10) + (w2 & 0x3ff) + 0x10000);
    }
    out.set(code, String.fromCodePoint(...chars));
  }
  return out;
}
function hexBytesOf(raw: string): Uint8Array {
  const out: number[] = [];
  let first = -1;
  for (const ch of raw) {
    const d = parseInt(ch, 16);
    if (Number.isNaN(d)) continue;
    if (first < 0) first = d;
    else { out.push((first << 4) | d); first = -1; }
  }
  if (first >= 0) out.push(first << 4);
  return Uint8Array.from(out);
}

/** A font as pdf.js measures it for a field's appearance. */
export interface FieldFont {
  /** pdf.js's ErrorFont: nothing it draws shows. */
  error: boolean;
  /** Font.encodeString: buffers of char codes and of characters it can't encode, in turn. */
  encode(str: string): string[];
  /** The width of each char code in a string (a glyph's width, or the default). */
  width(code: number): number;
  unicode(code: number): string;
  ascent: number;
  descent: number;
  /** Whether this font is measured exactly as pdf.js measures it. */
  exact: boolean;
  /** Bytes per char code: 1 for a simple font, 2 for a composite one (Identity). */
  step: number;
}

/** TrueType hhea ascent and descent over head unitsPerEm, as Font.checkAndRepair reads them, or null when it can't. */
function trueTypeMetrics(b: Uint8Array): [number, number] | null {
  if (b.length < 12) return null;
  const tag = latin1(b.subarray(0, 4));
  if (tag !== "\x00\x01\x00\x00" && tag !== "true") return null;
  const n = (b[4] << 8) | b[5];
  const tables = new Map<string, [number, number]>();
  for (let i = 0; i < n; i++) {
    const at = 12 + 16 * i;
    if (at + 16 > b.length) return null;
    const t = latin1(b.subarray(at, at + 4));
    const off = ((b[at + 8] << 24) | (b[at + 9] << 16) | (b[at + 10] << 8) | b[at + 11]) >>> 0;
    const len = ((b[at + 12] << 24) | (b[at + 13] << 16) | (b[at + 14] << 8) | b[at + 15]) >>> 0;
    if (len > 0) tables.set(t, [off, len]);
  }
  const head = tables.get("head"), hhea = tables.get("hhea");
  if (!head || !hhea || !tables.get("maxp") || tables.get("CFF ") || !tables.get("loca") || !tables.get("glyf")) return null;
  if (head[0] + 20 > b.length || hhea[0] + 8 > b.length) return null;
  const unitsPerEm = (b[head[0] + 18] << 8) + b[head[0] + 19];
  const s16 = (o: number) => { const v = (b[o] << 8) + b[o + 1]; return v & 0x8000 ? v - 0x10000 : v; };
  return [s16(hhea[0] + 4) / unitsPerEm, s16(hhea[0] + 6) / unitsPerEm];
}

const ERROR_FONT: FieldFont = { error: true, encode: (s) => [s], width: () => 0, unicode: (c) => String.fromCharCode(c), ascent: NaN, descent: NaN, exact: true, step: 1 };
/** The char codes of a string of bytes in a font (one or two bytes each), with where each starts and ends. */
const codesOf = (font: FieldFont, text: string): [number, number, number][] => {
  const out: [number, number, number][] = [];
  for (let i = 0; i < text.length; i += font.step) out.push([font.step === 2 ? (text.charCodeAt(i) << 8) | (text.charCodeAt(i + 1) || 0) : text.charCodeAt(i), i, Math.min(i + font.step, text.length)]);
  return out;
};

/** pdf.js's fallback font (PartialEvaluator.fallbackFontDict), as a font dictionary of the copy. */
export const FALLBACK_FONT = { Type: "Font", Subtype: "Type1", BaseFont: "Helvetica", Encoding: "WinAnsiEncoding" } as const;

/** A simple font (Type1, TrueType, MMType1) as pdf.js's translateFont and Font make it; a composite font approximately. */
function loadFont(pdf: PDFDocument, dict: PDFDict, decode: (s: PDFRawStream) => Uint8Array | null): FieldFont {
  const ctx = pdf.context;
  const look = (v: unknown) => (v instanceof PDFRef ? ctx.lookup(v) : v);
  const get = (d: PDFDict, k: string) => look(d.get(PDFName.of(k)));
  const nameOf = (v: unknown) => (v instanceof PDFName ? v.decodeText() : undefined);
  const numOf = (v: unknown) => (v instanceof PDFNumber ? v.asNumber() : undefined);
  const subtype = nameOf(get(dict, "Subtype"));
  if (!subtype) return ERROR_FONT;
  let exact = true;
  let fdict = dict;
  let composite = false;
  if (subtype === "Type0") {
    const df = get(dict, "DescendantFonts");
    const d0 = df instanceof PDFArray ? look(df.get(0)) : df;
    if (!(d0 instanceof PDFDict) || !nameOf(get(d0, "Subtype"))) return ERROR_FONT;
    fdict = d0;
    composite = true;
    exact = false;
  }
  const type = nameOf(get(fdict, "Subtype"))!;
  if (type === "Type3") exact = false;
  const firstChar = Number.isInteger(numOf(get(fdict, "FirstChar"))) ? numOf(get(fdict, "FirstChar"))! : 0;
  const descriptor = get(fdict, "FontDescriptor");
  const toUnicodeObj = get(fdict, "ToUnicode") ?? get(dict, "ToUnicode");
  let name: string;
  let file: Uint8Array | null = null;
  let internal: string | null = null;
  let flags: number;
  let ascent: number | undefined, descent: number | undefined;
  let widthsByGlyph: Map<string, number> | null = null, defaultWidthStd = 0;
  if (!(descriptor instanceof PDFDict)) {
    if (composite || type === "Type3") return ERROR_FONT;
    const base = nameOf(get(fdict, "BaseFont"));
    if (!base) return ERROR_FONT;
    name = normalizeFontName(base);
    const m = baseFontMetrics(name);
    widthsByGlyph = m.widths;
    defaultWidthStd = m.defaultWidth;
    const w = name.split("-", 1)[0];
    flags = (isSerifFont(w) ? 2 : 0) | (m.defaultWidth && !m.widths.size ? 1 : 0) | (symbolsFonts.has(w) ? 4 : 32);
    internal = standardFontName(name) ?? null;
  } else {
    let fontName = nameOf(get(descriptor, "FontName"));
    const fn = get(descriptor, "FontName");
    if (fn instanceof PDFString || fn instanceof PDFHexString) fontName = latin1(stringBytes(fn));
    const baseFont = nameOf(get(dict, "BaseFont"));
    if (fontName !== baseFont) {
      const known = (n: string) => { const f = normalizeFontName(n); return stdFontMap().has(f) || nonStdFontMap().has(f) || serifFonts.has(f) || symbolsFonts.has(f); };
      if (fontName && baseFont && (baseFont.startsWith(fontName) || (!known(fontName) && known(baseFont)))) fontName = undefined;
      fontName ||= baseFont;
    }
    if (!fontName) return ERROR_FONT;
    name = fontName;
    for (const k of ["FontFile", "FontFile2", "FontFile3"]) {
      const f = get(descriptor, k);
      if (f !== undefined) {
        if (f instanceof PDFRawStream) file = decode(f);
        if (!file || !file.length) file = null;
        break;
      }
    }
    if (!file && type !== "Type3") internal = standardFontName(name) ?? null;
    const a = numOf(get(descriptor, "Ascent")), d = numOf(get(descriptor, "Descent"));
    ascent = a;
    descent = d;
    const fl = numOf(get(descriptor, "Flags"));
    flags = Number.isInteger(fl) ? fl! : 0;
  }
  // extractDataStructures: the encoding.
  const differences = new Map<number, string>();
  let baseEncodingName: string | null = null;
  const encodingObj = fdict.has(PDFName.of("Encoding")) ? get(fdict, "Encoding") : undefined;
  if (fdict.has(PDFName.of("Encoding"))) {
    if (encodingObj instanceof PDFDict) {
      baseEncodingName = nameOf(get(encodingObj, "BaseEncoding")) ?? null;
      const diffs = get(encodingObj, "Differences");
      if (diffs instanceof PDFArray) {
        let index = 0;
        for (const raw of diffs.asArray()) {
          const x = look(raw);
          if (x instanceof PDFNumber) index = x.asNumber();
          else if (x instanceof PDFName) differences.set(index++, x.decodeText());
          else return ERROR_FONT;
        }
      }
    } else if (encodingObj instanceof PDFName) baseEncodingName = encodingObj.decodeText();
    if (baseEncodingName !== "MacRomanEncoding" && baseEncodingName !== "MacExpertEncoding" && baseEncodingName !== "WinAnsiEncoding") baseEncodingName = null;
  }
  const isInternal = !!internal;
  const nonEmbedded = !file || isInternal;
  const isSymbolsName = symbolsFonts.has(name);
  if (baseEncodingName && nonEmbedded && isSymbolsName) baseEncodingName = null;
  let defaultEncoding: string[];
  if (baseEncodingName) defaultEncoding = encoding(baseEncodingName);
  else {
    let symbolic = !!(flags & 4);
    const nonsymbolic = !!(flags & 32);
    if (type === "TrueType" && symbolic && nonsymbolic && differences.size) symbolic = false;
    let e = "StandardEncoding";
    if (type === "TrueType" && !nonsymbolic) e = "WinAnsiEncoding";
    if (symbolic || isSymbolsName) {
      e = "MacRomanEncoding";
      if (nonEmbedded) {
        if (/Symbol/i.test(name)) e = "SymbolSetEncoding";
        else if (/Dingbats/i.test(name)) e = "ZapfDingbatsEncoding";
        else if (/Wingdings/i.test(name)) e = "WinAnsiEncoding";
      }
    }
    defaultEncoding = encoding(e);
    if (file && !isInternal && type !== "TrueType") exact = false; // an embedded Type1 or CFF font's own encoding
  }
  const hasEncoding = !!baseEncodingName || differences.size > 0;
  // _simpleFontToUnicode.
  const simpleToUnicode = (forceGlyphs = false): Map<number, string> => {
    const map = new Map<number, string>();
    const e = defaultEncoding.slice();
    for (const [code, g] of differences) if (g !== ".notdef") e[code] = g;
    const gu = glyphsUnicode();
    for (const key in e) {
      const code = +key;
      let g = e[code];
      if (g === "" || g === undefined) continue;
      const u0 = gu.get(g);
      if (u0 !== undefined) { map.set(code, String.fromCharCode(u0)); continue; }
      let c = 0;
      switch (g[0]) {
        case "G": if (g.length === 3) c = parseInt(g.substring(1), 16); break;
        case "g": if (g.length === 5) c = parseInt(g.substring(1), 16); break;
        case "C": case "c":
          if (g.length >= 3 && g.length <= 4) {
            const cs = g.substring(1);
            if (forceGlyphs) { c = parseInt(cs, 16); break; }
            c = +cs;
            if (Number.isNaN(c) && Number.isInteger(parseInt(cs, 16))) return simpleToUnicode(true);
          }
          break;
        case "u": { const u = unicodeForGlyph(g); if (u !== -1) c = u; break; }
        default:
          if (g === "f_h" || g === "f_t" || g === "T_h") { map.set(code, g.replace(/_/g, "")); continue; }
      }
      if (c > 0 && c <= 0x10ffff && Number.isInteger(c)) {
        if (baseEncodingName && c === code) {
          const be = encoding(baseEncodingName);
          if ((g = be[code])) { map.set(code, String.fromCharCode(gu.get(g) as number)); continue; }
        }
        map.set(code, String.fromCodePoint(c));
      }
    }
    return map;
  };
  let toUnicode: Map<number, string>;
  let identity: [number, number] | null = null;
  const fromCMap = toUnicodeObj instanceof PDFRawStream ? (() => { const b = decode(toUnicodeObj); return b ? readToUnicode(b) : null; })() : null;
  if (toUnicodeObj instanceof PDFName && toUnicodeObj.decodeText() === "Identity-H") identity = [0, 0xffff];
  else if (toUnicodeObj instanceof PDFName) exact = false;
  if (identity) toUnicode = new Map();
  else if (fromCMap && fromCMap.size) {
    toUnicode = fromCMap;
    if (!composite && hasEncoding) for (const [k, v] of simpleToUnicode()) if (!toUnicode.has(k)) toUnicode.set(k, v);
  } else if (!composite) toUnicode = simpleToUnicode();
  else { identity = [firstChar, 0xffff]; toUnicode = new Map(); exact = false; }
  if (file && !isInternal && type === "TrueType" && !(fromCMap && fromCMap.size) && !hasEncoding) exact = false; // adjustTrueTypeToUnicode
  // extractWidths.
  const widths = new Map<number, number>();
  let defaultWidth = 0;
  if (composite) {
    const dw = numOf(get(fdict, "DW"));
    defaultWidth = typeof dw === "number" ? Math.ceil(dw) : 1000;
    const w = get(fdict, "W");
    if (w instanceof PDFArray) {
      const items = w.asArray().map(look);
      for (let i = 0; i < items.length; i++) {
        let start = numOf(items[i++]);
        if (!Number.isInteger(start)) break;
        const code = items[i];
        if (code instanceof PDFArray) {
          for (const c of code.asArray()) { const v = numOf(look(c)); if (typeof v === "number") widths.set(start!, v); start!++; }
        } else if (code instanceof PDFNumber && Number.isInteger(code.asNumber())) {
          const v = numOf(items[++i]);
          if (typeof v !== "number") continue;
          for (let j = start!; j <= code.asNumber(); j++) widths.set(j, v);
        } else break;
      }
    }
  } else {
    const w = get(fdict, "Widths");
    if (w instanceof PDFArray) {
      let j = firstChar;
      for (const raw of w.asArray()) {
        const v = numOf(look(raw));
        if (typeof v === "number") widths.set(j, v);
        j++;
      }
      if (descriptor instanceof PDFDict) {
        const mw = numOf(get(descriptor, "MissingWidth"));
        defaultWidth = typeof mw === "number" ? mw : 0;
      } else defaultWidth = defaultWidthStd;
    } else {
      const byGlyph = widthsByGlyph ?? (nameOf(get(fdict, "BaseFont")) ? baseFontMetrics(nameOf(get(fdict, "BaseFont"))!).widths : null);
      if (descriptor instanceof PDFDict) defaultWidth = nameOf(get(fdict, "BaseFont")) ? baseFontMetrics(nameOf(get(fdict, "BaseFont"))!).defaultWidth : 0;
      else defaultWidth = defaultWidthStd;
      if (byGlyph) {
        for (let code = 0; code < 256; code++) {
          const v = (differences.has(code) && byGlyph.get(differences.get(code)!)) || (code in defaultEncoding && byGlyph.get(defaultEncoding[code]));
          if (v) widths.set(code, v);
        }
      }
    }
  }
  // Font: ascent and descent.
  let asc = typeof ascent === "number" ? ascent / 1000 : NaN;
  let desc = typeof descent === "number" ? descent / 1000 : NaN;
  const fallbackMetrics = () => {
    let fn = normalizeFontName(name);
    fn = stdFontMap().get(fn) || nonStdFontMap().get(fn) || fn;
    const m = BASIC_METRICS[fn];
    if (m) {
      if (isNaN(asc)) asc = typeof m[0] === "number" ? m[0] / 1000 : NaN;
      if (isNaN(desc)) desc = typeof m[1] === "number" ? m[1] / 1000 : NaN;
    }
  };
  if (internal) {
    const fm = STANDARD_FILE_METRICS[internal];
    if (fm) {
      asc = fm[0] / fm[2];
      desc = fm[1] / fm[2];
    } else if (!STANDARD_TYPE1_FILES.includes(internal)) exact = false;
  } else if (file) {
    const head = latin1(file.subarray(0, 4));
    const isTT = head === "\x00\x01\x00\x00" || head === "true";
    const isOtto = head === "OTTO";
    const isT1 = (file[0] === 0x25 && file[1] === 0x21) || (file[0] === 0x80 && file[1] === 0x01);
    const isCff = !isTT && !isOtto && !isT1 && file[0] >= 1 && file[3] >= 1 && file[3] <= 4;
    if (isTT) {
      const m = trueTypeMetrics(file);
      if (m) [asc, desc] = m;
      else { exact = false; fallbackMetrics(); }
    } else if (isOtto || isT1 || isCff) {
      // Converted with the descriptor's ascent and descent, but with the font program's own FontMatrix (widths scaled
      // by it) and built-in encoding (codes mapped by it), which aren't read here.
      exact = false;
    } else {
      // A collection, or a file pdf.js may not read (it then draws with its fallback for the font's name).
      exact = false;
      fallbackMetrics();
    }
  } else fallbackMetrics();
  return {
    error: false,
    exact,
    step: composite ? 2 : 1,
    ascent: asc,
    descent: desc,
    width: (code) => {
      const w = widths.get(code);
      return typeof w === "number" ? w : defaultWidth;
    },
    unicode: (code) => (identity ? String.fromCharCode(code) : toUnicode.get(code) || String.fromCharCode(code)),
    encode(str) {
      const buffers: string[] = [];
      const cur: string[] = [];
      const errors = () => buffers.length % 2 === 1;
      const charCodeOf = (u: number): number => {
        if (identity) return Number.isInteger(u) && u >= identity[0] && u <= identity[1] ? u : -1;
        const v = String.fromCodePoint(u);
        for (const [code, entry] of toUnicode) if (entry === v) return code;
        return -1;
      };
      for (let i = 0; i < str.length; i++) {
        const u = str.codePointAt(i)!;
        if (u > 0xffff) i++;
        const code = charCodeOf(u);
        if (code !== -1) {
          if (errors()) { buffers.push(cur.join("")); cur.length = 0; }
          if (composite) cur.push(String.fromCharCode((code >> 8) & 0xff), String.fromCharCode(code & 0xff));
          else cur.push(String.fromCharCode(code & 0xff));
          continue;
        }
        if (!errors()) { buffers.push(cur.join("")); cur.length = 0; }
        cur.push(String.fromCodePoint(u));
      }
      buffers.push(cur.join(""));
      return buffers;
    },
  };
}

// ---- Fields ------------------------------------------------------------------------------------------------------

/** What pdf.js draws for a widget when printing: its own appearance stream, one it generates, or nothing. */
export type FieldDrawing =
  | { kind: "stored"; stream: PDFRawStream; missingFonts?: string[] }
  | { kind: "default-checked"; content: string; width: number; height: number }
  | { kind: "generated"; content: string; resources: PDFDict; matrix: number[]; width: number; height: number; fallbackFont: string | null; exact: boolean; unencodable?: { lines: string[]; fontSize: number; alignment: number; multiline: boolean; comb: boolean } }
  | { kind: "none" };

export interface FieldEnv {
  acroForm: PDFDict | null;
  needAppearances: boolean;
  xfa: ((path: string) => string | string[]) | null;
  fonts: Map<unknown, FieldFont>;
  decode: (s: PDFRawStream) => Uint8Array | null;
}

/** What the fields of a document need: its AcroForm, NeedAppearances, its XFA dataset. */
export function fieldEnv(pdf: PDFDocument, decode: (s: PDFRawStream) => Uint8Array | null): FieldEnv {
  const look = (v: unknown) => (v instanceof PDFRef ? pdf.context.lookup(v) : v);
  const af = look(pdf.catalog.get(PDFName.of("AcroForm")));
  const acroForm = af instanceof PDFDict ? af : null;
  const na = acroForm ? look(acroForm.get(PDFName.of("NeedAppearances"))) : undefined;
  let xfa: FieldEnv["xfa"] = null;
  try {
    xfa = acroForm ? datasetReader(pdf, acroForm, decode) : null;
  } catch {
    xfa = null;
  }
  return { acroForm, needAppearances: na instanceof PDFBool && na.asBoolean(), xfa, fonts: new Map(), decode };
}

/** What pdf.js draws for this widget annotation when it prints it. */
export function fieldDrawing(pdf: PDFDocument, dict: PDFDict, env: FieldEnv): FieldDrawing {
  const ctx = pdf.context;
  const look = (v: unknown) => (v instanceof PDFRef ? ctx.lookup(v) : v);
  const nameOf = (v: unknown) => (v instanceof PDFName ? v.decodeText() : undefined);
  const strOf = (v: unknown) => (v instanceof PDFString || v instanceof PDFHexString ? latin1(stringBytes(v)) : undefined);
  /** getInheritableProperty. */
  const inherited = (key: string): unknown => {
    const seen = new Set<unknown>();
    for (let d: unknown = dict; d instanceof PDFDict && !seen.has(d); d = look(d.get(PDFName.of("Parent")))) {
      seen.add(d);
      const v = look(d.get(PDFName.of(key)));
      if (v !== undefined) return v;
    }
    return undefined;
  };
  /** _decodeFormValue. */
  const decodeValue = (v: unknown): string | string[] | null => {
    if (v instanceof PDFArray) {
      const arr = v.asArray().map((x) => decodeValue(look(x))).filter((x): x is string => x !== null && !Array.isArray(x));
      return arr.length > 0 ? arr : null;
    }
    if (v instanceof PDFName) return v.decodeText();
    const s = strOf(v);
    return s !== undefined ? stringToPDFString(s) : null;
  };
  // setAppearance.
  const apDict = look(dict.get(PDFName.of("AP")));
  let appearance: PDFRawStream | null = null;
  const n = apDict instanceof PDFDict ? look(apDict.get(PDFName.of("N"))) : undefined;
  if (n instanceof PDFRawStream) appearance = n;
  else if (n instanceof PDFDict) {
    const as = look(dict.get(PDFName.of("AS")));
    if (as instanceof PDFName) {
      const a = look(n.get(as));
      if (a instanceof PDFRawStream) appearance = a;
    }
  }
  const stored = (): FieldDrawing => (appearance ? { kind: "stored", stream: appearance } : { kind: "none" });
  const ft = nameOf(inherited("FT"));
  if (ft !== "Tx" && ft !== "Ch" && ft !== "Btn") return stored();
  // Rect, width and height.
  const rectArr = look(dict.get(PDFName.of("Rect")));
  const r = rectArr instanceof PDFArray && rectArr.size() === 4 && rectArr.asArray().every((x) => look(x) instanceof PDFNumber) ? rectArr.asArray().map((x) => (look(x) as PDFNumber).asNumber()) : [0, 0, 0, 0];
  const rect = [Math.min(r[0], r[2]), Math.min(r[1], r[3]), Math.max(r[0], r[2]), Math.max(r[1], r[3])];
  const width = rect[2] - rect[0], height = rect[3] - rect[1];
  // MK: colours and rotation.
  const mk = look(dict.get(PDFName.of("MK")));
  const colour = (key: string): Uint8ClampedArray | null => {
    if (!(mk instanceof PDFDict)) return null;
    const a = look(mk.get(PDFName.of(key)));
    if (!(a instanceof PDFArray)) return null;
    const vals = a.asArray().map((x) => { const v = look(x); return v instanceof PDFNumber ? v.asNumber() : NaN; });
    if (vals.length === 0) return null;
    if (vals.length !== 1 && vals.length !== 3 && vals.length !== 4) return null;
    const c = new Uint8ClampedArray(3);
    rgbOf(vals, c);
    return c;
  };
  const borderColor = colour("BC"), backgroundColor = colour("BG");
  let rotation = 0;
  {
    const raw = mk instanceof PDFDict ? look(mk.get(PDFName.of("R"))) : look(dict.get(PDFName.of("Rotate")));
    let angle = raw instanceof PDFNumber ? raw.asNumber() : 0;
    if (Number.isInteger(angle) && angle !== 0) {
      angle %= 360;
      if (angle < 0) angle += 360;
      if (angle % 90 === 0) rotation = angle;
    }
  }
  // setBorderStyle (only its width is drawn).
  let borderWidth = 1;
  {
    const bs = look(dict.get(PDFName.of("BS")));
    const setWidth = (w: unknown) => {
      if (w instanceof PDFName) { borderWidth = 0; return; }
      if (w instanceof PDFNumber) {
        let v = w.asNumber();
        if (v > 0) {
          const maxW = (rect[2] - rect[0]) / 2, maxH = (rect[3] - rect[1]) / 2;
          if (maxW > 0 && maxH > 0 && (v > maxW || v > maxH)) v = 1;
        }
        borderWidth = v;
      }
    };
    if (dict.has(PDFName.of("BS"))) {
      if (bs instanceof PDFDict) {
        const t = look(bs.get(PDFName.of("Type")));
        if (!t || nameOf(t) === "Border") setWidth(look(bs.get(PDFName.of("W"))));
      }
    } else if (dict.has(PDFName.of("Border"))) {
      const arr = look(dict.get(PDFName.of("Border")));
      if (arr instanceof PDFArray) {
        if (arr.size() >= 3) setWidth(look(arr.get(2)));
        else if (arr.size() === 0) borderWidth = 0;
      }
    } else borderWidth = 0;
  }
  const colours = (): string => {
    if (!backgroundColor && !borderColor) return "";
    const re = rotation === 0 || rotation === 180 ? `0 0 ${width} ${height} re` : `0 0 ${height} ${width} re`;
    let str = "";
    if (backgroundColor) str = `${getPdfColor(backgroundColor, true)} ${re} f `;
    if (borderColor) str += `${borderWidth || 1} w ${getPdfColor(borderColor, false)} ${re} S `;
    return str;
  };
  // The field's value: V (inherited), else the XFA dataset's by the widget's own T, else DV.
  const rawV = inherited("V");
  let fieldValue: unknown = decodeValue(rawV);
  const defaultValue = decodeValue(inherited("DV"));
  let hasValueFromXFA = false;
  let fv: unknown = rawV;
  if (rawV === undefined && env.xfa) {
    const t = strOf(look(dict.get(PDFName.of("T"))));
    const path = t !== undefined ? stringToPDFString(t) : "";
    if (path) {
      hasValueFromXFA = true;
      fieldValue = fv = env.xfa(path);
    }
  }
  if (fv === undefined && defaultValue !== null) fieldValue = defaultValue;
  const ffRaw = inherited("Ff");
  const ff = ffRaw instanceof PDFNumber && Number.isInteger(ffRaw.asNumber()) && ffRaw.asNumber() >= 0 ? ffRaw.asNumber() : 0;
  const has = (bit: number) => !!(ff & (1 << (bit - 1)));

  if (ft === "Btn") return buttonDrawing(pdf, dict, n, appearance, fieldValue, defaultValue, has, width, height);

  // Text and choice fields.
  const daRaw = inherited("DA") ?? (env.acroForm ? look(env.acroForm.get(PDFName.of("DA"))) : undefined);
  let da = strOf(daRaw) ?? "";
  let daData = parseDefaultAppearance(da);
  const localResources = inherited("DR");
  const acroRes = env.acroForm ? look(env.acroForm.get(PDFName.of("DR"))) : undefined;
  const apRes = appearance ? look(appearance.dict.get(PDFName.of("Resources"))) : undefined;
  const merged = mergeResources(ctx, [localResources, apRes, acroRes]);
  const password = has(14);
  let value: string;
  let combo = false, options: { exportValue: string | null; displayValue: string | null }[] = [];
  if (ft === "Tx") {
    if (look(dict.get(PDFName.of("PMD"))) !== undefined || dict.has(PDFName.of("PMD"))) return { kind: "none" };
    if (typeof fieldValue !== "string") fieldValue = "";
    if (password) return stored();
  } else {
    const indices = look(dict.get(PDFName.of("I")));
    const hasIndices = indices instanceof PDFArray && indices.size() > 0;
    const opts = inherited("Opt");
    if (opts instanceof PDFArray) {
      options = opts.asArray().map((o) => {
        const x = look(o);
        if (x instanceof PDFArray) return { exportValue: decodeValue(look(x.get(0))) as string | null, displayValue: decodeValue(look(x.get(1))) as string | null };
        return { exportValue: decodeValue(x) as string | null, displayValue: decodeValue(x) as string | null };
      });
    }
    if (!hasIndices) {
      if (typeof fieldValue === "string") fieldValue = [fieldValue];
      else fieldValue ||= [];
    } else {
      const vals: (string | null)[] = [];
      for (const raw of (indices as PDFArray).asArray()) {
        const i = look(raw);
        const k = i instanceof PDFNumber ? i.asNumber() : NaN;
        if (Number.isInteger(k) && k >= 0 && k < options.length) vals.push(options[k].exportValue);
      }
      fieldValue = vals;
    }
    const fvArr = fieldValue as (string | null)[];
    if (options.length === 0 && fvArr.length > 0) options = fvArr.map((v) => ({ exportValue: v, displayValue: v }));
    combo = has(18);
    if (combo && password) return stored();
    if (!combo) return listBoxDrawing(pdf, env, dict, appearance, options, fvArr, da, daData, merged, rotation, width, height);
  }
  // WidgetAnnotation._getAppearance.
  if (!env.needAppearances && (!hasValueFromXFA || appearance)) return stored();
  const cols = colours();
  const colourOnly = `/Tx BMC q ${cols}Q EMC`;
  const generated = (content: string, extra: Partial<Extract<FieldDrawing, { kind: "generated" }>> = {}): FieldDrawing => {
    if (!da) return { kind: "none" };
    return { kind: "generated", content, resources: merged, matrix: rotationMatrix(rotation, width, height), width, height, fallbackFont: null, exact: true, ...extra };
  };
  let v: unknown = fieldValue;
  if (!v) return generated(colourOnly);
  if (Array.isArray(v) && v.length === 1) v = v[0];
  if (typeof v !== "string") return { kind: "none" };
  value = v.trimEnd();
  if (combo) {
    const option = options.find(({ exportValue }) => value === exportValue);
    value = option?.displayValue || value;
  }
  if (value === "") return generated(colourOnly);
  const multiLine = ft === "Tx" && has(13);
  const maxLenRaw = inherited("MaxLen");
  const maxLen = maxLenRaw instanceof PDFNumber && Number.isInteger(maxLenRaw.asNumber()) && maxLenRaw.asNumber() >= 0 ? maxLenRaw.asNumber() : 0;
  const comb = ft === "Tx" && has(25) && !multiLine && !password && !has(21) && maxLen !== 0;
  const getAlign = (q: unknown) => (q instanceof PDFNumber && Number.isInteger(q.asNumber()) && q.asNumber() >= 0 && q.asNumber() <= 2 ? q.asNumber() : null);
  const alignment = ft === "Tx" ? getAlign(inherited("Q")) ?? getAlign(env.acroForm ? look(env.acroForm.get(PDFName.of("Q"))) : undefined) ?? null : null;
  let lineCount = -1;
  let lines: string[];
  if (multiLine) {
    lines = value.split(/\r\n?|\n/).map((l) => l.normalize("NFC"));
    lineCount = lines.length;
  } else lines = [value.replace(/\r\n?|\n/, "").normalize("NFC")];
  let totalWidth = width, totalHeight = height;
  if (rotation === 90 || rotation === 270) [totalWidth, totalHeight] = [totalHeight, totalWidth];
  if (!da) {
    da = "/Helvetica 0 Tf 0 g";
    daData = parseDefaultAppearance(da);
  }
  if (!daData.fontSize && (totalWidth <= 4 || totalHeight <= 2)) return generated(colourOnly);
  const { font, fallbackFont } = fieldFont(pdf, env, daData.fontName, merged);
  const encodedLines: string[] = [];
  let encodingError = false;
  for (const line of lines) {
    const e = font.encode(line);
    if (e.length > 1) encodingError = true;
    encodedLines.push(e.join(""));
  }
  // _getTextWidth: the glyphs' widths summed exactly (an error font has none).
  const textWidth = (text: string) => sumPrecise(font.error ? [] : codesOf(font, text).map(([code]) => font.width(code))) / 1000;
  // pdf.js draws nothing with a font it can't load (its ErrorFont), only the field's colours.
  if (font.error) return generated(colourOnly);
  if (encodingError) {
    // pdf.js draws these with a font of the browser's own (FakeUnicodeFont): the copy draws the value with Noto Sans.
    return { kind: "generated", content: "", resources: merged, matrix: rotationMatrix(rotation, width, height), width, height, fallbackFont, exact: false, unencodable: { lines, fontSize: daData.fontSize, alignment: alignment ?? 0, multiline: multiLine, comb } };
  }
  // _computeFontSize.
  let fontSize = daData.fontSize;
  let defaultAppearance = da;
  const roundTwo = (x: number) => Math.floor(x * 100) / 100;
  const hAvail = totalHeight - 2, wAvail = totalWidth - 4;
  let numberOfLines = Math.round(hAvail / ((fontSize || 12) * LINE_FACTOR));
  if (!fontSize) {
    if (lineCount === -1) {
      fontSize = roundTwo(Math.min(hAvail / LINE_FACTOR, wAvail / textWidth(value)));
      numberOfLines = 1;
    } else {
      const cached = value.split(/\r\n?|\n/).map((l) => font.encode(l).join(""));
      const tooBig = (fsize: number) => {
        let total = 0;
        for (const line of cached) {
          total += splitLine(line, font, fsize, wAvail).length * fsize;
          if (total > hAvail) return true;
        }
        return false;
      };
      numberOfLines = Math.max(numberOfLines, lineCount);
      const sizeFor = (k: number) => roundTwo(hAvail / k / LINE_FACTOR);
      if (hAvail > 0 && tooBig(sizeFor(numberOfLines))) {
        let low = numberOfLines, high = 2 * numberOfLines;
        while (tooBig(sizeFor(high))) { low = high; high *= 2; }
        while (high - low > 1) {
          const mid = Math.floor((low + high) / 2);
          if (tooBig(sizeFor(mid))) low = mid;
          else high = mid;
        }
        numberOfLines = high;
      }
      fontSize = sizeFor(numberOfLines);
    }
    defaultAppearance = `/${escapePDFName(daData.fontName)} ${fontSize} Tf ${getPdfColor(daData.fontColor, true)}`;
  }
  const lineHeight = hAvail / numberOfLines;
  let descent = font.descent;
  descent = isNaN(descent) ? BASELINE_FACTOR * lineHeight : Math.max(BASELINE_FACTOR * lineHeight, Math.abs(descent) * fontSize);
  const vPadding = Math.min(Math.floor((totalHeight - fontSize) / 2), 1);
  let fontAscent = font.ascent, fontDescent = font.descent;
  if (isNaN(fontAscent) || isNaN(fontDescent) || (!fontAscent && !fontDescent)) {
    fontAscent = LINE_FACTOR - LINE_DESCENT_FACTOR;
    fontDescent = LINE_DESCENT_FACTOR;
  } else fontDescent = Math.abs(fontDescent);
  const vShift = (totalHeight - (fontAscent + fontDescent) * fontSize) / 2 + fontDescent * fontSize;
  const renderText = (text: string, prev: { shift: number }, hPad: number, vPad: number, align: number | null) => {
    let shift: number;
    if (align === 1) shift = (totalWidth - textWidth(text) * fontSize) / 2;
    else if (align === 2) shift = totalWidth - textWidth(text) * fontSize - hPad;
    else shift = hPad;
    const s = numberToString(shift - prev.shift);
    prev.shift = shift;
    return `${s} ${numberToString(vPad)} Td (${escapeString(text)}) Tj`;
  };
  const exact = font.exact;
  if (multiLine) {
    const buf: string[] = [];
    const prev = { shift: 0 };
    for (let i = 0; i < encodedLines.length; i++) {
      const chunks = splitLine(encodedLines[i], font, fontSize, totalWidth - 4);
      for (let j = 0; j < chunks.length; j++) {
        const vs = i === 0 && j === 0 ? -vPadding - (lineHeight - descent) : -lineHeight;
        buf.push(renderText(chunks[j], prev, 2, vs, alignment));
      }
    }
    return generated(`/Tx BMC q ${cols}BT ${defaultAppearance} 1 0 0 1 0 ${numberToString(totalHeight)} Tm ${buf.join("\n")} ET Q EMC`, { exact, fallbackFont });
  }
  if (comb) {
    const combWidth = totalWidth / maxLen;
    const text = encodedLines[0];
    const cells = font.error ? [] : codesOf(font, text).map(([, s0, e0]) => ({ glyph: text.substring(s0, e0), width: textWidth(text.substring(s0, e0)) * fontSize }));
    if (isRtl(lines[0])) cells.reverse();
    const tw = combWidth * cells.length;
    let hShift = 0;
    if (alignment === 1) hShift += Math.floor((totalWidth - tw) / (2 * combWidth)) * combWidth;
    else if (alignment === 2) hShift += totalWidth - tw;
    const buf: string[] = [];
    let previous = 0;
    for (let i = 0; i < cells.length; i++) {
      const { glyph, width: gw } = cells[i];
      const shift = i === 0 ? (combWidth - gw) / 2 : combWidth + (previous - gw) / 2;
      buf.push(`${numberToString(shift)} 0 Td (${escapeString(glyph)}) Tj`);
      previous = gw;
    }
    return generated(`/Tx BMC q ${cols}BT ${defaultAppearance} 1 0 0 1 ${numberToString(hShift)} ${numberToString(vShift)} Tm ${buf.join(" ")} ET Q EMC`, { exact, fallbackFont });
  }
  if (alignment === 0 || (alignment !== null && alignment > 2)) {
    return generated(`/Tx BMC q ${cols}BT ${defaultAppearance} 1 0 0 1 ${numberToString(2)} ${numberToString(vShift)} Tm (${escapeString(encodedLines[0])}) Tj ET Q EMC`, { exact, fallbackFont });
  }
  const rendered = renderText(encodedLines[0], { shift: 0 }, 2, vShift, alignment);
  return generated(`/Tx BMC q ${cols}BT ${defaultAppearance} 1 0 0 1 0 0 Tm ${rendered} ET Q EMC`, { exact, fallbackFont });
}

/** TextWidgetAnnotation._splitLine. */
function splitLine(line: string, font: FieldFont, fontSize: number, width: number): string[] {
  const glyphs = font.error ? [] : codesOf(font, line);
  if (glyphs.length <= 1) return [line];
  const scale = fontSize / 1000;
  const chunks: string[] = [];
  let lastSpaceStart = -1, lastSpaceEnd = -1, lastSpacePos = -1, startChunk = 0, currentWidth = 0;
  for (let i = 0; i < glyphs.length; i++) {
    const [code, start, end] = glyphs[i];
    const gw = font.width(code) * scale;
    if (font.unicode(code) === " ") {
      if (currentWidth + gw > width) {
        chunks.push(line.substring(startChunk, start));
        startChunk = start;
        currentWidth = gw;
        lastSpaceStart = -1;
        lastSpacePos = -1;
      } else {
        currentWidth += gw;
        lastSpaceStart = start;
        lastSpaceEnd = end;
        lastSpacePos = i;
      }
    } else if (currentWidth + gw > width) {
      if (lastSpaceStart !== -1) {
        chunks.push(line.substring(startChunk, lastSpaceEnd));
        startChunk = lastSpaceEnd;
        i = lastSpacePos + 1;
        lastSpaceStart = -1;
        currentWidth = 0;
      } else {
        chunks.push(line.substring(startChunk, start));
        startChunk = start;
        currentWidth = gw;
      }
    } else currentWidth += gw;
  }
  if (startChunk < line.length) chunks.push(line.substring(startChunk));
  return chunks;
}

/** Dict.merge with mergeSubDicts: the first dictionary with a key wins; sub-dictionaries merge, first entry winning. */
function mergeResources(ctx: PDFContext, dicts: unknown[]): PDFDict {
  const look = (v: unknown) => (v instanceof PDFRef ? ctx.lookup(v) : v);
  const props = new Map<string, PDFObject[]>();
  for (const d0 of dicts) {
    const d = look(d0);
    if (!(d instanceof PDFDict)) continue;
    for (const [k, v] of d.entries()) {
      const key = k.decodeText();
      const list = props.get(key) ?? [];
      props.set(key, list);
      if (list.length && !(look(v) instanceof PDFDict)) continue;
      list.push(v);
    }
  }
  const out = ctx.obj({}) as PDFDict;
  for (const [key, values] of props) {
    if (values.length === 1 || !(look(values[0]) instanceof PDFDict)) {
      out.set(PDFName.of(key), values[0]);
      continue;
    }
    const sub = ctx.obj({}) as PDFDict;
    for (const v of values) {
      const d = look(v) as PDFDict;
      for (const [k, x] of d.entries()) if (!sub.has(k)) sub.set(k, x);
    }
    if (sub.keys().length) out.set(PDFName.of(key), sub);
  }
  return out;
}

/** The font pdf.js finds for a DA font name in the field's resources (or its fallback, Helvetica), and the name the copy must add it under when it isn't there. */
function fieldFont(pdf: PDFDocument, env: FieldEnv, fontName: string, resources: PDFDict): { font: FieldFont; fallbackFont: string | null } {
  const look = (v: unknown) => (v instanceof PDFRef ? pdf.context.lookup(v) : v);
  const fonts = look(resources.get(PDFName.of("Font")));
  const raw = fonts instanceof PDFDict && fontName ? fonts.get(PDFName.of(fontName)) : undefined;
  const dict = look(raw);
  if (dict instanceof PDFDict) {
    const key = raw instanceof PDFRef ? raw : dict;
    let f = env.fonts.get(key);
    if (!f) env.fonts.set(key, (f = loadFont(pdf, dict, env.decode)));
    return { font: f, fallbackFont: null };
  }
  let f = env.fonts.get("fallback");
  if (!f) env.fonts.set("fallback", (f = loadFont(pdf, pdf.context.obj(FALLBACK_FONT as never) as unknown as PDFDict, env.decode)));
  // pdf.js falls back to Helvetica when the font isn't there; the copy gives it the same font under the DA's name, so
  // every reader draws it (pdf.js the same as its fallback).
  return { font: f, fallbackFont: fontName || null };
}

/** ChoiceWidgetAnnotation._getAppearance for a list box (only under NeedAppearances). */
function listBoxDrawing(pdf: PDFDocument, env: FieldEnv, dict: PDFDict, appearance: PDFRawStream | null, options: { exportValue: string | null; displayValue: string | null }[], value: (string | null)[], da: string, daData: ReturnType<typeof parseDefaultAppearance>, merged: PDFDict, rotation: number, width: number, height: number): FieldDrawing {
  void dict;
  if (!env.needAppearances) return appearance ? { kind: "stored", stream: appearance } : { kind: "none" };
  let totalWidth = width, totalHeight = height;
  if (rotation === 90 || rotation === 270) [totalWidth, totalHeight] = [totalHeight, totalWidth];
  const lineCount = options.length;
  const indices: number[] = [];
  for (let i = 0; i < lineCount; i++) if (value.includes(options[i].exportValue)) indices.push(i);
  if (!da) {
    da = "/Helvetica 0 Tf 0 g";
    daData = parseDefaultAppearance(da);
  }
  const { font, fallbackFont } = fieldFont(pdf, env, daData.fontName, merged);
  const textWidth = (text: string | null) => {
    if (text === null) throw new Error("no text");
    return sumPrecise(font.error ? [] : codesOf(font, text).map(([code]) => font.width(code))) / 1000;
  };
  // pdf.js draws nothing with a font it can't load (its ErrorFont).
  if (font.error) return { kind: "none" };
  try {
    let defaultAppearance = da;
    let fontSize = daData.fontSize;
    if (!fontSize) {
      const lh = (totalHeight - 1) / lineCount;
      let lw = -1;
      let widest: string | null = null;
      for (const { displayValue } of options) {
        const w = textWidth(displayValue);
        if (w > lw) { lw = w; widest = displayValue; }
      }
      fontSize = Math.floor(Math.min(lh / LINE_FACTOR, (totalWidth - 4) / textWidth(widest)) * 100) / 100;
      defaultAppearance = `/${escapePDFName(daData.fontName)} ${fontSize} Tf ${getPdfColor(daData.fontColor, true)}`;
    }
    const lineHeight = fontSize * LINE_FACTOR;
    const vPadding = (lineHeight - fontSize) / 2;
    const visible = Math.floor(totalHeight / lineHeight);
    let first = 0;
    if (indices.length > 0) {
      let lo = indices[0], hi = indices[0];
      for (const k of indices) {
        if (k < lo) lo = k;
        if (k > hi) hi = k;
      }
      first = Math.min(Math.max(hi - visible + 1, 0), lo);
    }
    const end = Math.min(first + visible + 1, lineCount);
    const buf = ["/Tx BMC q", `1 1 ${totalWidth} ${totalHeight} re W n`];
    if (indices.length) {
      buf.push("0.600006 0.756866 0.854904 rg");
      for (const index of indices) if (first <= index && index < end) buf.push(`1 ${totalHeight - (index - first + 1) * lineHeight} ${totalWidth} ${lineHeight} re f`);
    }
    buf.push("BT", defaultAppearance, `1 0 0 1 0 ${totalHeight} Tm`);
    const prev = { shift: 0 };
    for (let i = first; i < end; i++) {
      const text = options[i].displayValue as string;
      textWidth(text);
      const shift = 2;
      const s = numberToString(shift - prev.shift);
      prev.shift = shift;
      buf.push(`${s} ${numberToString(-lineHeight + (i === first ? vPadding : 0))} Td (${escapeString(text)}) Tj`);
    }
    buf.push("ET Q EMC");
    return { kind: "generated", content: buf.join("\n"), resources: merged, matrix: rotationMatrix(rotation, width, height), width, height, fallbackFont, exact: font.exact };
  } catch {
    return { kind: "none" };
  }
}

/** ButtonWidgetAnnotation when printing: its appearance for AS, else the one its value names (or pdf.js's own check or disc). */
function buttonDrawing(pdf: PDFDocument, dict: PDFDict, n: unknown, appearance: PDFRawStream | null, fieldValue0: unknown, defaultValue: unknown, has: (bit: number) => boolean, width: number, height: number): FieldDrawing {
  void defaultValue;
  const ctx = pdf.context;
  const look = (v: unknown) => (v instanceof PDFRef ? ctx.lookup(v) : v);
  const isRadio = has(16), isPush = has(17);
  if (isPush || appearance) return appearance ? { kind: "stored", stream: appearance } : { kind: "none" };
  const normal = n instanceof PDFDict ? n : null;
  let fieldValue: unknown = fieldValue0;
  const decode = (v: unknown): string | null => {
    if (v instanceof PDFName) return v.decodeText();
    if (v instanceof PDFString || v instanceof PDFHexString) return stringToPDFString(latin1(stringBytes(v)));
    return null;
  };
  const opt = (() => {
    const seen = new Set<unknown>();
    for (let d: unknown = dict; d instanceof PDFDict && !seen.has(d); d = look(d.get(PDFName.of("Parent")))) {
      seen.add(d);
      const o = look(d.get(PDFName.of("Opt")));
      if (o !== undefined) return o;
    }
    return undefined;
  })();
  const onStateOf = (d: unknown): string | null => {
    const ap = d instanceof PDFDict ? look(d.get(PDFName.of("AP"))) : undefined;
    const nn = ap instanceof PDFDict ? look(ap.get(PDFName.of("N"))) : undefined;
    if (!(nn instanceof PDFDict)) return null;
    for (const k of nn.keys()) if (k.decodeText() !== "Off") return k.decodeText();
    return null;
  };
  // _getOptInfo and _getExportValue.
  const optInfo = (onState: string | null) => {
    if (!(opt instanceof PDFArray)) return null;
    const items = opt.asArray();
    const stateToIndex = new Map<string, number>();
    let currentIndex: number | null = null;
    const parent = look(dict.get(PDFName.of("Parent")));
    const kids = parent instanceof PDFDict ? look(parent.get(PDFName.of("Kids"))) : undefined;
    if (kids instanceof PDFArray) {
      for (let i = 0; i < Math.min(kids.size(), items.length); i++) {
        const kid = look(kids.get(i));
        if (!(kid instanceof PDFDict)) continue;
        if (kid === dict) currentIndex = i;
        const s = onStateOf(kid);
        if (typeof s === "string" && !stateToIndex.has(s)) stateToIndex.set(s, i);
      }
    } else if (items.length === 1 && typeof onState === "string") {
      currentIndex = 0;
      stateToIndex.set(onState, 0);
    }
    return { currentIndex, items, stateToIndex };
  };
  const forIndex = (index: number | null, items: PDFObject[]) => {
    if (index !== null && Number.isInteger(index) && index >= 0 && index < items.length) {
      const v = decode(look(items[index]));
      if (typeof v === "string") return v;
    }
    return null;
  };
  const exportOf = (state: unknown, info: ReturnType<typeof optInfo>, onState: string | null): unknown => {
    if (!info || typeof state !== "string" || state === "Off") return state;
    if (state === onState) {
      const v = forIndex(info.currentIndex, info.items);
      if (v !== null) return v;
    }
    if (info.stateToIndex.has(state)) {
      const v = forIndex(info.stateToIndex.get(state)!, info.items);
      if (v !== null) return v;
    }
    const index = parseInt(state, 10);
    return Number.isInteger(index) && String(index) === state ? forIndex(index, info.items) || state : state;
  };
  const defaultChecked = (type: "check" | "disc"): FieldDrawing => {
    const fontSize = Math.min(width, height) * 0.8;
    const m = type === "check" ? { w: 0.755 * fontSize, h: 0.705 * fontSize, ch: "3" } : { w: 0.791 * fontSize, h: 0.705 * fontSize, ch: "l" };
    return { kind: "default-checked", content: `q BT /PdfJsZaDb ${fontSize} Tf 0 g ${numberToString((width - m.w) / 2)} ${numberToString((height - m.h) / 2)} Td (${m.ch}) Tj ET Q`, width, height };
  };
  if (!isRadio) {
    // _processCheckBox.
    const as = decode(look(dict.get(PDFName.of("AS"))));
    if (typeof as === "string") fieldValue = as;
    const yes = fieldValue !== null && fieldValue !== "Off" ? fieldValue : "Yes";
    let exportValues: unknown[] = normal ? normal.keys().map((k) => k.decodeText()) : [];
    if (exportValues.length === 0) exportValues = ["Off", yes];
    else if (exportValues.length === 1) {
      if (exportValues[0] === "Off") exportValues.push(yes);
      else exportValues.unshift("Off");
    } else if (exportValues.includes(yes)) exportValues = ["Off", yes];
    else exportValues = ["Off", exportValues.find((x) => x !== "Off")];
    const onState = exportValues[1] as string;
    const info = optInfo(onState);
    const exportValue = exportOf(onState, info, onState);
    if (!exportValues.includes(fieldValue) && fieldValue !== exportValue) fieldValue = "Off";
    fieldValue = exportOf(fieldValue, info, onState);
    const on = normal ? look(normal.get(PDFName.of(String(onState)))) : undefined;
    const off = normal ? look(normal.get(PDFName.of("Off"))) : undefined;
    if (fieldValue === exportValue) return on instanceof PDFRawStream ? { kind: "stored", stream: on } : defaultChecked("check");
    return off instanceof PDFRawStream ? { kind: "stored", stream: off } : { kind: "none" };
  }
  // _processRadioButton.
  let buttonValue: unknown = null;
  const parent = look(dict.get(PDFName.of("Parent")));
  if (parent instanceof PDFDict) {
    const pv = look(parent.get(PDFName.of("V")));
    if (pv instanceof PDFName) fieldValue = pv.decodeText();
  }
  if (!(normal instanceof PDFDict)) return { kind: "none" };
  let onState: string | null = null;
  for (const k of normal.keys()) if (k.decodeText() !== "Off") { onState = k.decodeText(); break; }
  const info = optInfo(onState);
  buttonValue = exportOf(onState, info, onState);
  fieldValue = exportOf(fieldValue, info, onState);
  const on = onState !== null ? look(normal.get(PDFName.of(onState))) : undefined;
  const off = look(normal.get(PDFName.of("Off")));
  if (fieldValue === buttonValue) return on instanceof PDFRawStream ? { kind: "stored", stream: on } : defaultChecked("disc");
  return off instanceof PDFRawStream ? { kind: "stored", stream: off } : { kind: "none" };
}
