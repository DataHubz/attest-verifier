// Renderer v3: the document renderer v3 draws, made from exactly what pdf.js read.
//
// pdfjs-v3.ts reads the original as the signing page's pdf.js reads it (its cross-reference, decryption and page tree).
// This file turns that into the pdf-lib document every part of v3 works on: each object reachable from the trailer,
// as pdf.js fetched it (an object that pdf.js can't fetch becomes null, as pdf.js reads a missing one), with its
// strings and streams decrypted, and a page tree with exactly pdf.js's pages, in its order. Each page carries, as its
// own entries, what pdf.js gives it (the Resources it merges from the page and its ancestors, its MediaBox and CropBox,
// its Rotate and UserUnit, the Annots it inherits), so no reader of the copy can find anything else by walking a tree.
// A byte-identical copy lives in DataHubz/attest-verifier (src/renderer/open-v3.ts).

import { PDFArray, PDFBool, PDFCatalog, PDFContext, PDFDict, PDFDocument, PDFHexString, PDFName, PDFNull, PDFNumber, PDFObject, PDFPageLeaf, PDFPageTree, PDFRawStream, PDFRef } from "pdf-lib";
import { UnreadablePdf } from "./decrypt-v3";
import { CIRCULAR_REF, Dict, EOF, Name, PStream, Ref, Stream, inheritableProperty, isEngineError, jsNumber, loadLikePdfjs, type PValue, type PdfjsDocument, type XRef } from "./pdfjs-v3";

const LETTER: [number, number, number, number] = [0, 0, 612, 792];
type Rect = [number, number, number, number];

/** isNumberArray(arr, 4), then Util.normalizeRect. */
function normalRect(v: PValue): Rect | null {
  if (!Array.isArray(v) || v.length !== 4 || !v.every((x) => typeof x === "number")) return null;
  const r = v.slice() as Rect;
  if (r[0] > r[2]) [r[0], r[2]] = [r[2], r[0]];
  if (r[1] > r[3]) [r[1], r[3]] = [r[3], r[1]];
  return r;
}

/** What pdf.js's Page gives a page: its boxes, rotation, unit, resources and annotations (each may throw, as there). */
function pageGeometry(dict: Dict) {
  const box = (name: string): Rect | null => {
    const b = normalRect(inheritableProperty(dict, name, true));
    return b && b[2] - b[0] > 0 && b[3] - b[1] > 0 ? b : null;
  };
  const mediaBox = box("MediaBox") ?? LETTER;
  const cropBox = box("CropBox");
  const r = inheritableProperty(dict, "Rotate", false);
  // pdf.js's arithmetic on whatever /Rotate holds, then the viewport's own "% 360".
  let n = jsNumber((r as never) || 0);
  if (n % 90 !== 0) n = 0;
  else if (n >= 360) n %= 360;
  else if (n < 0) n = ((n % 360) + 360) % 360;
  const rotate = ((n % 360) + 360) % 360;
  const uu = dict.get("UserUnit");
  const userUnit = typeof uu === "number" && uu > 0 ? uu : 1;
  const resources = inheritableProperty(dict, "Resources", false);
  const annots = inheritableProperty(dict, "Annots", false);
  return { mediaBox, cropBox, rotate, userUnit, resources: resources instanceof Dict ? resources : null, annots: Array.isArray(annots) ? annots : null };
}

/** pdf.js's objects as pdf-lib's, each indirect object once (by its number), what can't be fetched as null. */
class Converter {
  readonly refs = new Map<number, PDFRef | null>();
  private queue: { num: number; value: PValue }[] = [];
  constructor(readonly ctx: PDFContext, readonly xref: XRef) {}
  /** The pdf-lib ref for a pdf.js ref, fetching and queuing the object the first time, or null when pdf.js can't fetch it. */
  ref(r: Ref): PDFRef | typeof PDFNull {
    if (this.refs.has(r.num)) {
      const known = this.refs.get(r.num);
      // Another generation of a number already read: pdf.js's cache gives the same object (or the same failure).
      return known ?? PDFNull;
    }
    let value: PValue;
    try {
      value = this.xref.fetch(r);
    } catch (e) {
      if (isEngineError(e)) throw e;
      value = null;
    }
    if (value === null || value === undefined || value === CIRCULAR_REF || value === EOF || typeof value === "number" && Number.isNaN(value)) {
      this.refs.set(r.num, null);
      return PDFNull;
    }
    const ref = PDFRef.of(r.num, 0);
    this.refs.set(r.num, ref);
    this.queue.push({ num: r.num, value });
    return ref;
  }
  /** Every queued object converted and assigned. */
  drain(make: (num: number, value: PValue) => PDFObject | null) {
    while (this.queue.length) {
      const { num, value } = this.queue.shift()!;
      const obj = make(num, value) ?? this.convert(value);
      this.ctx.assign(PDFRef.of(num, 0), obj);
    }
  }
  /** One value, its arrays and dictionaries converted without recursion. */
  convert(value: PValue): PDFObject {
    const ctx = this.ctx;
    type Task = { from: PValue; set: (o: PDFObject) => void };
    let root: PDFObject = PDFNull;
    const tasks: Task[] = [{ from: value, set: (o) => (root = o) }];
    while (tasks.length) {
      const { from, set } = tasks.pop()!;
      if (from instanceof Ref) set(this.ref(from));
      else if (typeof from === "number") set(Number.isFinite(from) ? PDFNumber.of(from) : PDFNull);
      else if (typeof from === "string") set(hexString(from));
      else if (typeof from === "boolean") set(from ? PDFBool.True : PDFBool.False);
      else if (from instanceof Name) set(nameOf(from.name));
      else if (Array.isArray(from)) {
        const arr = PDFArray.withContext(ctx);
        set(arr);
        // Each element's slot is reserved now and filled when its task runs.
        for (let i = 0; i < from.length; i++) arr.push(PDFNull);
        for (let i = from.length - 1; i >= 0; i--) tasks.push({ from: from[i], set: (o) => arr.set(i, o) });
      } else if (from instanceof Dict) {
        const dict = ctx.obj({}) as PDFDict;
        set(dict);
        const entries = [...from.map.entries()];
        // Keys keep their order: each is set now, its value filled in when its task runs.
        for (const [k] of entries) dict.set(nameOf(k), PDFNull);
        for (let i = entries.length - 1; i >= 0; i--) {
          const [k, v] = entries[i];
          if (v === undefined) {
            dict.delete(nameOf(k));
            continue;
          }
          tasks.push({ from: v, set: (o) => dict.set(nameOf(k), o) });
        }
      } else if (from instanceof PStream) set(this.stream(from));
      else set(PDFNull);
    }
    return root;
  }
  /** A stream: its dictionary converted, its bytes decrypted as pdf.js decrypts them (a first Crypt filter applied and dropped). */
  stream(s: PStream): PDFRawStream {
    const dict = this.convert(s.dict) as PDFDict;
    let contents = s.raw;
    if (s.cryptFirst && s.cipher) {
      try {
        const filter = s.dict.get("F", "Filter");
        const params = s.dict.get("DP", "DecodeParms");
        const first = Array.isArray(params) ? this.xref.fetchIfRef(params[0]) : params;
        const name = first instanceof Dict ? first.get("Name") : null;
        contents = s.cipher.createStream(new Stream(s.raw, 0, s.raw.length, s.dict), s.raw.length, name instanceof Name ? name : new Name("Identity")).getBytes();
        const fkey = s.dict.has("F") ? "F" : "Filter";
        const pkey = s.dict.has("DP") ? "DP" : "DecodeParms";
        if (Array.isArray(filter) && filter.length > 1) {
          const fa = dict.get(PDFName.of(fkey));
          if (fa instanceof PDFArray) fa.remove(0);
          const pa = dict.get(PDFName.of(pkey));
          if (pa instanceof PDFArray && pa.size() > 0) pa.remove(0);
        } else {
          dict.delete(PDFName.of(fkey));
          dict.delete(PDFName.of(pkey));
        }
      } catch (e) {
        if (isEngineError(e)) throw e;
      }
    }
    return PDFRawStream.of(dict, contents);
  }
}

/** A name as pdf-lib keeps it: PDFName.of decodes "#xx", so a "#" pdf.js read is given as "#23". */
export const nameOf = (name: string) => PDFName.of(name.replace(/#/g, "#23"));
/** A string's bytes as a hex string. */
export function hexString(s: string): PDFHexString {
  let hex = "";
  for (let i = 0; i < s.length; i++) {
    const b = s.charCodeAt(i) & 0xff;
    hex += (b < 16 ? "0" : "") + b.toString(16).toUpperCase();
  }
  return PDFHexString.of(hex);
}

/** The original as the signing page's pdf.js showed it, as v3 draws it; UnreadablePdf when pdf.js couldn't show its pages. */
export async function openOriginalV3(bytes: Uint8Array): Promise<PDFDocument> {
  const loaded = loadLikePdfjs(bytes);
  if ("unreadable" in loaded) throw new UnreadablePdf(loaded.unreadable);
  return toPdfLib(loaded);
}

function toPdfLib(doc: PdfjsDocument): PDFDocument {
  // Every page the signing page asks for must load (pdf.js's GetPage reads its rotation, unit and view too), or it
  // shows nothing at all.
  const pages: { dict: Dict; ref: Ref | null; g: ReturnType<typeof pageGeometry> }[] = [];
  for (const p of doc.pages) {
    if ("error" in p) throw new UnreadablePdf("damaged");
    try {
      pages.push({ dict: p.dict, ref: p.ref, g: pageGeometry(p.dict) });
    } catch (e) {
      if (isEngineError(e)) throw e;
      throw new UnreadablePdf("damaged");
    }
  }
  if (!pages.length) throw new UnreadablePdf("damaged");
  const ctx = PDFContext.create();
  const conv = new Converter(ctx, doc.xref);
  // Each page under its own number (the first time pdf.js shows it), so whatever refers to it refers to the page.
  const pageRef: (PDFRef | null)[] = pages.map((p) => {
    if (!p.ref || conv.refs.has(p.ref.num)) return null;
    const ref = PDFRef.of(p.ref.num, 0);
    conv.refs.set(p.ref.num, ref);
    return ref;
  });
  const catalogs: PDFCatalog[] = [];
  const make = (num: number, value: PValue): PDFObject | null => {
    void num;
    if (!(value instanceof Dict) || value !== doc.root) return null;
    const catalog = PDFCatalog.fromMapWithContext(new Map(), ctx);
    const converted = conv.convert(value) as PDFDict;
    for (const [k, v] of converted.entries()) catalog.set(k, v);
    // Every reader finds the catalog by its type, which pdf.js doesn't need.
    catalog.set(PDFName.of("Type"), PDFName.of("Catalog"));
    catalogs.push(catalog);
    return catalog;
  };
  const leaves: PDFPageLeaf[] = [];
  for (const p of pages) {
    const converted = conv.convert(stripTree(p.dict)) as PDFDict;
    const leaf = PDFPageLeaf.fromMapWithContext(new Map(), ctx);
    for (const [k, v] of converted.entries()) leaf.set(k, v);
    leaf.set(PDFName.of("Type"), PDFName.of("Page"));
    const g = p.g;
    leaf.set(PDFName.of("Resources"), g.resources ? conv.convert(g.resources) : ctx.obj({}));
    leaf.set(PDFName.of("MediaBox"), ctx.obj(g.mediaBox));
    if (g.cropBox) leaf.set(PDFName.of("CropBox"), ctx.obj(g.cropBox));
    else leaf.delete(PDFName.of("CropBox"));
    if (g.rotate) leaf.set(PDFName.of("Rotate"), PDFNumber.of(g.rotate));
    else leaf.delete(PDFName.of("Rotate"));
    if (g.userUnit !== 1) leaf.set(PDFName.of("UserUnit"), PDFNumber.of(g.userUnit));
    else leaf.delete(PDFName.of("UserUnit"));
    if (g.annots) leaf.set(PDFName.of("Annots"), conv.convert(g.annots));
    else leaf.delete(PDFName.of("Annots"));
    leaves.push(leaf);
  }
  const rootRaw = doc.trailer.getRaw("Root");
  const rootRef = rootRaw instanceof Ref ? conv.ref(rootRaw) : null;
  const infoRaw = doc.trailer.getRaw("Info");
  const info = infoRaw === undefined ? undefined : conv.convert(infoRaw);
  const idRaw = doc.trailer.getRaw("ID");
  const id = idRaw === undefined ? undefined : conv.convert(idRaw instanceof Ref ? doc.xref.fetchIfRef(idRaw) : idRaw);
  conv.drain(make);
  // New objects take numbers past every number the document refers to, so nothing it names becomes something Attest
  // adds.
  let largest = 0;
  for (const num of conv.refs.keys()) if (num > largest) largest = num;
  for (const [ref] of ctx.enumerateIndirectObjects()) if (ref.objectNumber > largest) largest = ref.objectNumber;
  ctx.largestObjectNumber = largest;
  const treeRef = ctx.nextRef();
  let catalogRef: PDFRef;
  if (rootRef instanceof PDFRef && catalogs.length) catalogRef = rootRef;
  else {
    const catalog = make(0, doc.root) as PDFCatalog;
    conv.drain(make);
    catalogRef = ctx.register(catalog);
  }
  for (const c of catalogs) c.set(PDFName.of("Pages"), treeRef);
  const kids: PDFRef[] = [];
  for (const [i, leaf] of leaves.entries()) {
    leaf.set(PDFName.of("Parent"), treeRef);
    const ref = pageRef[i] ?? ctx.nextRef();
    ctx.assign(ref, leaf);
    kids.push(ref);
  }
  const tree = PDFPageTree.fromMapWithContext(new Map(), ctx);
  tree.set(PDFName.of("Type"), PDFName.of("Pages"));
  tree.set(PDFName.of("Kids"), ctx.obj(kids));
  tree.set(PDFName.of("Count"), PDFNumber.of(kids.length));
  ctx.assign(treeRef, tree);
  // The trailer: the catalog, the document information and the file identifiers; never the encryption.
  ctx.trailerInfo.Root = catalogRef;
  if (info instanceof PDFRef) ctx.trailerInfo.Info = info;
  if (id instanceof PDFArray) ctx.trailerInfo.ID = id;
  const Doc = PDFDocument as unknown as new (context: PDFContext, ignoreEncryption: boolean, updateMetadata: boolean) => PDFDocument;
  return new Doc(ctx, true, false);
}

/** A page dictionary without the entries a tree node has (its own are set from pdf.js's view of it). */
function stripTree(dict: Dict): Dict {
  const d = new Dict(dict.xref);
  for (const [k, v] of dict.map) if (k !== "Parent" && k !== "Kids" && k !== "Count") d.set(k, v);
  return d;
}
