// Renderer v3: a content stream as pdf.js runs it, written back as content every reader reads the same way.
//
// For a document that isn't clean, the copy carries none of the document's content bytes as they were. Each content
// stream (a page's, a form's, a pattern's, a Type 3 glyph's, a soft mask's, an annotation's appearance) is decoded the
// way pdf.js decodes it (a page's streams joined, one that fails to decode left out whole; a single stream read up to
// where its decoding fails), read with pdf.js's lexer and parser, and run through pdf.js's EvaluatorPreprocessor (its
// operators and operand counts, unknown operators skipped, operands carried over as it carries them) and the checks
// pdf.js's evaluator makes before it adds an operator (operators it drops, and the ones that stop it reading the
// stream). What pdf.js ran is then written back: every number as the digits pdf.js read it from, every string as hex,
// every name escaped, inline images with their data hex-encoded (so no reader looks for their end), and the stream
// closed off (the saves it restores beyond its own matched before it, and after it whatever it leaves open: a path, a
// text object, marked content, saved states). No pending path, unclosed string, unbalanced marked content or save can
// reach what follows it, and nothing depends on how a reader recovers from an error. A byte-identical copy lives in
// DataHubz/attest-verifier (src/renderer/content-v3.ts).

import { PDFArray, PDFBool, PDFDict, PDFName, PDFNull, PDFNumber, PDFRawStream, PDFRef, PDFHexString, PDFString, type PDFDocument, type PDFObject } from "pdf-lib";
import { stringBytes } from "./decrypt-v3";
import { Cmd, Dict, EOF, PdfjsError, InlineImage, Lexer, Name, NullStream, Parser, Ref, Stream, StreamsSequenceStream, applyFilters, isCmd, isEngineError, type BaseStream, type KnownCommands, type PValue } from "./pdfjs-v3";

/** A number in content, with the digits pdf.js read it from (so writing them back reads the same number in pdf.js). */
export class Num {
  constructor(readonly value: number, readonly text: string) {}
}

// EvaluatorPreprocessor.opMap: each operator's operand count (variable: up to that many); null entries are words the
// lexer knows but which aren't operators.
type OpSpec = { numArgs: number; variableArgs: boolean } | null;
const op = (numArgs: number, variableArgs = false): OpSpec => ({ numArgs, variableArgs });
export const OP_MAP: Record<string, OpSpec> = {
  w: op(1), J: op(1), j: op(1), M: op(1), d: op(2), ri: op(1), i: op(1), gs: op(1), q: op(0), Q: op(0), cm: op(6),
  m: op(2), l: op(2), c: op(6), v: op(4), y: op(4), h: op(0), re: op(4), S: op(0), s: op(0), f: op(0), F: op(0), "f*": op(0),
  B: op(0), "B*": op(0), b: op(0), "b*": op(0), n: op(0), W: op(0), "W*": op(0), BT: op(0), ET: op(0), Tc: op(1), Tw: op(1),
  Tz: op(1), TL: op(1), Tf: op(2), Tr: op(1), Ts: op(1), Td: op(2), TD: op(2), Tm: op(6), "T*": op(0), Tj: op(1), TJ: op(1),
  "'": op(1), '"': op(3), d0: op(2), d1: op(6), CS: op(1), cs: op(1), SC: op(4, true), SCN: op(33, true), sc: op(4, true),
  scn: op(33, true), G: op(1), g: op(1), RG: op(3), rg: op(3), K: op(4), k: op(4), sh: op(1), BI: op(0), ID: op(0), EI: op(1),
  Do: op(1), MP: op(1), DP: op(2), BMC: op(1), BDC: op(2), EMC: op(0), BX: op(0), EX: op(0),
  BM: null, BD: null, true: null, fa: null, fal: null, fals: null, false: null, nu: null, nul: null, null: null,
};
// prototype-free lookups, as pdf.js makes its map with Object.create(null).
const KNOWN: KnownCommands = Object.assign(Object.create(null), OP_MAP);
const PATH_OPS = new Set(["m", "l", "c", "v", "y", "h", "re", "S", "s", "f", "F", "f*", "B", "B*", "b", "b*", "n"]);

class ContentLexer extends Lexer {
  getObj(): PValue {
    const v = super.getObj();
    if (typeof v === "number") {
      const t = this.lastNumber!;
      const text = t.point < 0 ? t.digits : `${t.digits.slice(0, t.point)}.${t.digits.slice(t.point)}`;
      return new Num(v, (t.sign < 0 ? "-" : "") + text) as unknown as PValue;
    }
    return v;
  }
}
const isIntNum = (v: unknown): v is Num => v instanceof Num && Number.isInteger(v.value);

/** pdf.js's Parser, over content: numbers as Num (their integer checks made on the values). */
class ContentParser extends Parser {
  intOf(v: PValue): number | null {
    return isIntNum(v) ? (v as unknown as Num).value : null;
  }
}

/** One operator as pdf.js's preprocessor gives it: its name and operands (null when it has none). */
export type Op = { cmd: string; args: PValue[] | null };

/**
 * EvaluatorPreprocessor.read over a stream: each operator in turn, until the end or until pdf.js stops reading (an
 * error reading the stream, too many operands, too many path operators without theirs). `stopped` says whether it
 * stopped early.
 */
export function* preprocess(stream: BaseStream): Generator<Op, { stopped: boolean }, void> {
  let parser: ContentParser;
  try {
    parser = new ContentParser({ lexer: new ContentLexer(stream, KNOWN), xref: null });
  } catch (e) {
    if (isEngineError(e)) throw e;
    return { stopped: true };
  }
  const nonProcessedArgs: PValue[] = [];
  let isPathOp = false;
  let numInvalidPathOps = 0;
  for (;;) {
    let args: PValue[] | null = null;
    let produced: Op | null = null;
    try {
      for (;;) {
        const obj = parser.getObj();
        if (obj instanceof Cmd) {
          const cmd = obj.cmd;
          const spec = OP_MAP[cmd];
          if (!spec) continue;
          const numArgs = spec.numArgs;
          let argsLength = args !== null ? args.length : 0;
          if (!isPathOp) numInvalidPathOps = 0;
          isPathOp = PATH_OPS.has(cmd);
          if (!spec.variableArgs) {
            if (argsLength !== numArgs) {
              while (argsLength > numArgs) {
                nonProcessedArgs.push(args!.shift()!);
                argsLength--;
              }
              while (argsLength < numArgs && nonProcessedArgs.length !== 0) {
                if (args === null) args = [];
                args.unshift(nonProcessedArgs.pop()!);
                argsLength++;
              }
            }
            if (argsLength < numArgs) {
              if (isPathOp && ++numInvalidPathOps > 10) throw new Error(`Invalid command ${cmd}`);
              if (args !== null) args.length = 0;
              continue;
            }
          }
          produced = { cmd, args };
          break;
        }
        if (obj === EOF) return { stopped: false };
        if (obj !== null) {
          if (args === null) args = [];
          args.push(obj);
          if (args.length > 33) throw new Error("Too many arguments");
        }
      }
    } catch (e) {
      if (isEngineError(e)) throw e;
      return { stopped: true };
    }
    yield produced!;
  }
}

/** A content stream's bytes as pdf.js decodes them, from pdf-lib's stream (its filters, read lazily). */
export type Decoder = (stream: unknown) => BaseStream | null;

/**
 * A page's content as pdf.js reads it (Page.getContentStream): one stream read through its filters (nothing, if it's an
 * image stream), or several joined, each one that fails to decode left out whole.
 */
export function pageContent(contents: unknown, decode: Decoder, isArray: boolean, items: unknown[]): BaseStream {
  if (!isArray) {
    const s = decode(contents);
    return s && !s.isImageStream ? s : new NullStream();
  }
  const streams: BaseStream[] = [];
  for (const it of items) {
    const s = decode(it);
    if (s) streams.push(s);
  }
  return new StreamsSequenceStream(streams);
}


// ---- Writing content back ----------------------------------------------------------------------------------------

const hex2 = (b: number) => (b < 16 ? "0" : "") + b.toString(16).toUpperCase();
/** A name every reader reads the same way: anything but printable ASCII other than delimiters and "#" escaped. */
export function writeName(name: string): string {
  let out = "/";
  for (let i = 0; i < name.length; i++) {
    const c = name.charCodeAt(i) & 0xff;
    const regular = c > 0x20 && c < 0x7f && c !== 0x23 && !"()<>[]{}/%".includes(String.fromCharCode(c));
    out += regular ? String.fromCharCode(c) : `#${hex2(c)}`;
  }
  return out;
}
export function writeHex(bytes: string | Uint8Array): string {
  let out = "<";
  if (typeof bytes === "string") for (let i = 0; i < bytes.length; i++) out += hex2(bytes.charCodeAt(i) & 0xff);
  else for (let i = 0; i < bytes.length; i++) out += hex2(bytes[i]);
  return out + ">";
}
/**
 * An operand written back. A command pdf.js read inside an array or a dictionary (not an operand of any operator pdf.js
 * runs) is written as a name that names nothing, which every place pdf.js reads one treats as it treats the command.
 */
export function writeValue(v: PValue | Num): string {
  const out: string[] = [];
  const stack: (PValue | Num | { close: string })[] = [v];
  while (stack.length) {
    const x = stack.pop()!;
    if (x && typeof x === "object" && "close" in (x as object) && !(x instanceof Dict) && !Array.isArray(x)) {
      out.push((x as { close: string }).close);
      continue;
    }
    const value = x as PValue;
    if (value instanceof Num) out.push(value.text);
    else if (typeof value === "number") out.push(String(value));
    else if (typeof value === "string") out.push(writeHex(value));
    else if (value instanceof Name) out.push(writeName(value.name));
    else if (typeof value === "boolean") out.push(value ? "true" : "false");
    else if (value === null || value === undefined) out.push("null");
    else if (value instanceof Ref) out.push(`${value.num} ${value.gen} R`);
    else if (value instanceof Cmd) out.push(writeName(`\u0000${value.cmd}`));
    else if (Array.isArray(value)) {
      out.push("[");
      stack.push({ close: "]" });
      for (let i = value.length - 1; i >= 0; i--) stack.push(value[i]);
    } else if (value instanceof Dict) {
      out.push("<<");
      stack.push({ close: ">>" });
      const entries = [...value.map.entries()];
      for (let i = entries.length - 1; i >= 0; i--) {
        stack.push(entries[i][1]);
        stack.push(new Name(entries[i][0]));
      }
    } else out.push("null");
  }
  return out.join(" ");
}

/**
 * An inline image written back: its dictionary as pdf.js read it, with ASCIIHex put first among its filters (F, DP)
 * and its data, the bytes pdf.js took for it, hex-encoded, so every reader finds where it ends at its ">".
 */
export function writeInlineImage(img: InlineImage): string {
  const entries: string[] = [];
  const d = img.dict;
  const filter = d.has("F") ? d.getRaw("F") : d.getRaw("Filter");
  const parms = d.has("DP") ? d.getRaw("DP") : d.getRaw("DecodeParms");
  for (const [k, v] of d.map) {
    if (k === "F" || k === "Filter" || k === "DP" || k === "DecodeParms") continue;
    entries.push(`${writeName(k)} ${writeValue(v)}`);
  }
  const filters: PValue[] = filter === undefined ? [] : Array.isArray(filter) ? filter : [filter];
  const hasParms = parms !== undefined;
  const parmList: PValue[] = !hasParms ? [] : Array.isArray(parms) ? parms : [parms];
  entries.push(`/F ${writeValue([new Name("AHx"), ...filters])}`);
  if (hasParms) entries.push(`/DP ${writeValue([null, ...parmList])}`);
  return `BI ${entries.join(" ")} ID\n${writeHex(img.data).slice(1, -1)}>\nEI`;
}

export const isNum = (v: unknown): v is Num => v instanceof Num;
/** isNumberArray(args, null) on what the preprocessor gives (Num stands for a number). */
const allNumbers = (args: PValue[] | null) => args !== null && args.every((a) => a instanceof Num);

// ---- pdf-lib's objects, as pdf.js's ------------------------------------------------------------------------------

/** A pdf-lib value as pdf.js's parser would have made it (refs resolved where pdf.js resolves them: here, always). */
export function toPdfjs(pdf: PDFDocument, v: unknown, depth = 0): PValue {
  if (depth > 64) return null;
  if (v instanceof PDFRef) return toPdfjs(pdf, pdf.context.lookup(v), depth + 1);
  if (v instanceof PDFNumber) return v.asNumber();
  if (v instanceof PDFName) return new Name(v.decodeText());
  if (v instanceof PDFString || v instanceof PDFHexString) {
    const b = stringBytes(v);
    let out = "";
    for (let i = 0; i < b.length; i++) out += String.fromCharCode(b[i]);
    return out;
  }
  if (v instanceof PDFBool) return v.asBoolean();
  if (v instanceof PDFArray) return v.asArray().map((x) => toPdfjs(pdf, x, depth + 1));
  if (v instanceof PDFDict) {
    const d = new Dict(null);
    for (const [k, x] of v.entries()) d.set(k.decodeText(), toPdfjs(pdf, x, depth + 1));
    return d;
  }
  return null;
}
/** A content operand as pdf-lib's (for looking up what optional content an inline dictionary names). */
export function toPdfLib(pdf: PDFDocument, v: PValue, depth = 0): PDFObject {
  const ctx = pdf.context;
  if (depth > 64) return PDFNull;
  if (v instanceof Num) return PDFNumber.of(v.value);
  if (typeof v === "number") return PDFNumber.of(v);
  if (typeof v === "string") return PDFHexString.of(writeHex(v).slice(1, -1));
  if (v instanceof Name) return PDFName.of(v.name.replace(/#/g, "#23"));
  if (typeof v === "boolean") return v ? PDFBool.True : PDFBool.False;
  if (v instanceof Ref) return PDFRef.of(v.num, 0);
  if (Array.isArray(v)) {
    const a = PDFArray.withContext(ctx);
    for (const x of v) a.push(toPdfLib(pdf, x, depth + 1));
    return a;
  }
  if (v instanceof Dict) {
    const d = ctx.obj({}) as PDFDict;
    for (const [k, x] of v.map) d.set(PDFName.of(k.replace(/#/g, "#23")), toPdfLib(pdf, x, depth + 1));
    return d;
  }
  return PDFNull;
}

/** A stream's bytes through its filters, as pdf.js decodes them (lazily: an error surfaces where pdf.js meets it). */
export function decodeLikePdfjs(pdf: PDFDocument, v: unknown): BaseStream | null {
  const s = v instanceof PDFRef ? pdf.context.lookup(v) : v;
  if (!(s instanceof PDFRawStream)) return null;
  const dict = new Dict(null);
  for (const key of ["F", "Filter", "DP", "DecodeParms"]) {
    const x = s.dict.get(PDFName.of(key));
    if (x !== undefined) dict.set(key, toPdfjs(pdf, x));
  }
  const base = new Stream(s.contents, 0, s.contents.length, dict);
  try {
    return applyFilters({ fetchIfRef: (x) => x, cipher: null }, base, dict, s.contents.length);
  } catch (e) {
    if (isEngineError(e)) throw e;
    // pdf.js's parser throws for a filter that isn't a name: the stream can't be read at all.
    return new NullStream();
  }
}

// ---- Running content as pdf.js runs it, and writing it back -----------------------------------------------------

type State = { font: boolean; tr: PValue | Num };
type Ancestors = { s: PDFRawStream; up: Ancestors | null } | null;
const inChain = (a: Ancestors, s: PDFRawStream) => {
  for (let k = a; k; k = k.up) if (k.s === s) return true;
  return false;
};
const STREAM_KEYS = new Set(["Filter", "DecodeParms", "Length", "DL", "F", "FFilter", "FDecodeParms"]);
const TEXT_SHOWING = new Set(["Tj", "TJ", "'", '"']);
const PAINTING = new Set(["S", "s", "f", "F", "f*", "B", "B*", "b", "b*"]);
const PATH_BUILDING = new Set(["m", "l", "c", "v", "y", "h", "re"]);

/** A request, from a stream being written, for another it runs: a form (with its caller's state), a mask group, a pattern, glyphs. */
type Child = { stream: PDFRawStream; ref: PDFRef | null; resources: unknown; state: State; ancestors: Ancestors; kind: "form" | "fresh"; reply: (name: string | null) => void };

/**
 * Writes back every content stream of a document that isn't clean, as pdf.js runs it (see the top of this file), with
 * what pdf.js hid by optional content taken out: inside marked content pdf.js hides, a path ends unpainted, text is
 * shown in the invisible rendering mode (so it still moves the text position, as in pdf.js), and images, shadings,
 * inline images and forms are left out. Forms are written once for each state they're run in that changes them (the
 * font and text rendering mode they inherit, and the forms that would draw themselves, which pdf.js skips).
 */
export class Rewriter {
  /** Each form's writing, by the context it was written in; the first is put in the form's place. */
  private written = new Map<PDFRawStream, { key: string; bytes: Uint8Array; name: Map<PDFDict, string> }[]>();
  private placed = new Map<PDFRawStream, Uint8Array>();
  private clones = 0;
  private budget = 50000;
  /** Whether a content stream needed more writings than v3 makes (it then reuses the first): v3 can't match pdf.js exactly. */
  inexact = false;
  constructor(private pdf: PDFDocument, private visible: (oc: unknown) => boolean) {}
  private lookup(v: unknown) {
    return v instanceof PDFRef ? this.pdf.context.lookup(v) : v;
  }
  private sub(res: unknown, kind: string): PDFDict | null {
    const r = this.lookup(res);
    const d = r instanceof PDFDict ? this.lookup(r.get(PDFName.of(kind))) : undefined;
    return d instanceof PDFDict ? d : null;
  }
  /** A page's content: its streams joined as pdf.js joins them. */
  page(contents: unknown, resources: unknown): Uint8Array {
    const raw = this.lookup(contents);
    const items = raw instanceof PDFArray ? raw.asArray() : [];
    const stream = pageContent(raw, (x) => decodeLikePdfjs(this.pdf, x), raw instanceof PDFArray, items);
    return this.run(stream, resources, { font: false, tr: new Num(0, "0") }, null);
  }
  /** A stream drawn on its own (an annotation's appearance, a field's generated appearance), from a fresh state. */
  standalone(stream: PDFRawStream | Uint8Array, resources: unknown): Uint8Array {
    const s = stream instanceof Uint8Array ? new Stream(stream) : decodeLikePdfjs(this.pdf, stream) ?? new NullStream();
    return this.run(s, resources, { font: false, tr: new Num(0, "0") }, stream instanceof PDFRawStream ? { s: stream, up: null } : null);
  }
  /** Runs one stream and every stream it runs, depth first as pdf.js does, without recursion. */
  private run(stream: BaseStream, resources: unknown, state: State, ancestors: Ancestors): Uint8Array {
    let result: Uint8Array = new Uint8Array(0);
    const stack: Generator<Child, Uint8Array, void>[] = [this.write(stream, resources, state, ancestors)];
    const replies: ((r: Uint8Array) => void)[] = [(r) => (result = r)];
    while (stack.length) {
      const g = stack[stack.length - 1];
      const step = g.next();
      if (step.done) {
        stack.pop();
        replies.pop()!(step.value);
        continue;
      }
      const child = step.value;
      // A form whose writing for this context is known, or a stream already written (glyphs, patterns, masks).
      const key = this.contextKey(child);
      const done = this.written.get(child.stream)?.find((w) => w.key === key);
      if (done && child.kind === "form") {
        child.reply(this.nameFor(child, done.bytes));
        continue;
      }
      if (child.kind === "fresh" && this.written.has(child.stream)) {
        child.reply(null);
        continue;
      }
      if (--this.budget < 0) {
        this.inexact = true;
        child.reply(this.written.has(child.stream) ? this.nameFor(child, this.written.get(child.stream)![0].bytes) : null);
        continue;
      }
      const decoded = decodeLikePdfjs(this.pdf, child.stream) ?? new NullStream();
      const res = child.kind === "form" ? child.stream.dict.get(PDFName.of("Resources")) ?? child.resources : child.stream.dict.get(PDFName.of("Resources")) ?? child.resources;
      stack.push(this.write(decoded, res, child.state, { s: child.stream, up: child.ancestors }));
      replies.push((bytes) => {
        const list = this.written.get(child.stream) ?? [];
        if (!this.written.has(child.stream)) this.written.set(child.stream, list);
        list.push({ key, bytes, name: new Map() });
        if (!this.placed.has(child.stream)) this.place(child.stream, bytes, res);
        child.reply(child.kind === "form" ? this.nameFor(child, bytes) : null);
      });
    }
    return result;
  }
  private contextKey(c: Child): string {
    if (c.kind === "fresh") return "fresh";
    const t = c.state.tr instanceof Num ? c.state.tr.text : writeValue(c.state.tr);
    // The ancestors matter only when the form runs one of them (pdf.js then skips that call): the chain's identity.
    let chain = "";
    for (let k = c.ancestors, n = 0; k && n < 64; k = k.up, n++) chain += ":" + (this.ids.get(k.s) ?? this.idOf(k.s));
    return `${c.state.font ? 1 : 0}|${t}|${this.idOf(this.lookup(c.resources))}|${this.cyclic.has(c.stream) ? chain : ""}`;
  }
  private ids = new Map<unknown, number>();
  private idOf(x: unknown) {
    let id = this.ids.get(x);
    if (id === undefined) this.ids.set(x, (id = this.ids.size + 1));
    return id;
  }
  /** Streams whose writing skipped a call to one of their ancestors (their writing depends on who runs them). */
  private cyclic = new Set<PDFRawStream>();
  /** The name a caller uses for a form's writing: the form's own if it's the one in its place, else a copy's. */
  private nameFor(c: Child, bytes: Uint8Array): string | null {
    const placed = this.placed.get(c.stream);
    if (!placed || sameBytes(placed, bytes)) return null;
    const res = this.lookup(c.resources);
    const list = this.written.get(c.stream)!;
    const entry = list.find((w) => sameBytes(w.bytes, bytes))!;
    const owner = res instanceof PDFDict ? res : null;
    if (owner && entry.name.has(owner)) return entry.name.get(owner)!;
    const ctx = this.pdf.context;
    const copy = this.streamWith(c.stream, bytes, c.stream.dict.get(PDFName.of("Resources")) ?? c.resources);
    const name = `AttestF${++this.clones}`;
    let xo = owner ? this.lookup(owner.get(PDFName.of("XObject"))) : undefined;
    if (owner && !(xo instanceof PDFDict)) {
      xo = ctx.obj({});
      owner.set(PDFName.of("XObject"), xo as PDFDict);
    }
    if (xo instanceof PDFDict) xo.set(PDFName.of(name), ctx.register(copy));
    if (owner) entry.name.set(owner, name);
    return name;
  }
  private streamWith(s: PDFRawStream, bytes: Uint8Array, resources: unknown): PDFRawStream {
    const ctx = this.pdf.context;
    const fresh = ctx.flateStream(bytes);
    for (const [k, v] of s.dict.entries()) if (!STREAM_KEYS.has(k.decodeText())) fresh.dict.set(k, v);
    if (resources !== undefined && !s.dict.has(PDFName.of("Resources"))) fresh.dict.set(PDFName.of("Resources"), resources as PDFObject);
    return fresh;
  }
  /** A stream's first writing put in its place (every object that refers to it gets it). */
  private place(s: PDFRawStream, bytes: Uint8Array, resources: unknown) {
    this.placed.set(s, bytes);
    const ctx = this.pdf.context;
    if (!this.refsOf) {
      this.refsOf = new Map();
      for (const [ref, o] of ctx.enumerateIndirectObjects()) {
        if (!(o instanceof PDFRawStream)) continue;
        const list = this.refsOf.get(o) ?? [];
        list.push(ref);
        this.refsOf.set(o, list);
      }
    }
    const fresh = this.streamWith(s, bytes, resources);
    for (const ref of this.refsOf.get(s) ?? []) ctx.assign(ref, fresh);
    this.replaced.add(fresh);
  }
  private refsOf: Map<PDFRawStream, PDFRef[]> | null = null;
  private replaced = new Set<PDFRawStream>();
  /** Every other content stream in the document, written from a fresh state (no stream of the document stays as it was). */
  finish(streams: PDFRawStream[]) {
    for (const s of streams) {
      if (this.written.has(s) || this.replaced.has(s)) continue;
      const bytes = this.run(decodeLikePdfjs(this.pdf, s) ?? new NullStream(), s.dict.get(PDFName.of("Resources")), { font: false, tr: new Num(0, "0") }, { s, up: null });
      this.written.set(s, [{ key: "fresh", bytes, name: new Map() }]);
      this.place(s, bytes, undefined);
    }
  }
  /** One stream: pdf.js's operators, checked as its evaluator checks them, written back, closed off. */
  private *write(stream: BaseStream, resources: unknown, init: State, ancestors: Ancestors): Generator<Child, Uint8Array, void> {
    const out: string[] = [];
    let state: State = { ...init };
    const saved: State[] = [];
    let excess = 0;
    const marked: boolean[] = [];
    let inText = false;
    let pathPending = false;
    const hidden = () => marked.includes(false);
    const line = (args: PValue[] | null, cmd: string) => out.push((args && args.length ? args.map(writeValue).join(" ") + " " : "") + cmd);
    const gen = preprocess(stream);
    for (;;) {
      const step = gen.next();
      if (step.done) break;
      const { cmd, args } = step.value;
      const a = args ?? [];
      switch (cmd) {
        case "q":
          saved.push({ ...state });
          line(null, "q");
          continue;
        case "Q":
          if (saved.length) state = saved.pop()!;
          else excess++;
          line(null, "Q");
          continue;
        case "Tf": {
          state.font = true;
          line(a, "Tf");
          const font = a[0] instanceof Name ? this.lookup(this.sub(resources, "Font")?.get(PDFName.of(a[0].name))) : undefined;
          if (font instanceof PDFDict && this.lookup(font.get(PDFName.of("Subtype"))) instanceof PDFName && (this.lookup(font.get(PDFName.of("Subtype"))) as PDFName).decodeText() === "Type3") {
            const procs = this.lookup(font.get(PDFName.of("CharProcs")));
            if (procs instanceof PDFDict) {
              for (const [, v] of procs.entries()) {
                const p = this.lookup(v);
                if (p instanceof PDFRawStream) yield { stream: p, ref: v instanceof PDFRef ? v : null, resources: font.get(PDFName.of("Resources")) ?? resources, state: { font: false, tr: new Num(0, "0") }, ancestors: null, kind: "fresh", reply: () => {} };
              }
            }
          }
          continue;
        }
        case "Tr":
          state.tr = a[0];
          line(a, "Tr");
          continue;
        case "BT":
          inText = true;
          line(null, "BT");
          continue;
        case "ET":
          inText = false;
          line(null, "ET");
          continue;
        case "EI": {
          const img = a[0];
          // pdf.js can't paint an inline image that isn't one, and stops reading the stream there.
          if (!(img instanceof InlineImage)) return close();
          if (!hidden()) out.push(writeInlineImage(img));
          continue;
        }
        case "Do": {
          if (hidden() || !(a[0] instanceof Name)) continue;
          const x = this.sub(resources, "XObject")?.get(PDFName.of(a[0].name));
          const xo = this.lookup(x);
          if (!(xo instanceof PDFRawStream)) continue;
          const subtype = this.lookup(xo.dict.get(PDFName.of("Subtype")));
          const st = subtype instanceof PDFName ? subtype.decodeText() : null;
          const oc = xo.dict.get(PDFName.of("OC"));
          if (oc !== undefined && !this.visible(oc)) continue;
          if (st === "Image") {
            line(a, "Do");
            continue;
          }
          if (st !== "Form") continue;
          // A form that runs itself (directly or through others): pdf.js skips the call.
          if (inChain(ancestors, xo)) {
            for (let k = ancestors; k; k = k.up) this.cyclic.add(k.s);
            continue;
          }
          let name: string | null = null;
          yield { stream: xo, ref: x instanceof PDFRef ? x : null, resources, state: { font: state.font, tr: state.tr }, ancestors, kind: "form", reply: (n) => (name = n) };
          out.push(`${writeName(name ?? a[0].name)} Do`);
          continue;
        }
        case "gs": {
          line(a, "gs");
          const gs = a[0] instanceof Name ? this.lookup(this.sub(resources, "ExtGState")?.get(PDFName.of(a[0].name))) : undefined;
          const mask = gs instanceof PDFDict ? this.lookup(gs.get(PDFName.of("SMask"))) : undefined;
          const g = mask instanceof PDFDict ? this.lookup(mask.get(PDFName.of("G"))) : undefined;
          if (g instanceof PDFRawStream && !inChain(ancestors, g)) yield { stream: g, ref: null, resources, state: { font: state.font, tr: state.tr }, ancestors, kind: "fresh", reply: () => {} };
          continue;
        }
        case "scn":
        case "SCN": {
          line(a, cmd);
          const last = a[a.length - 1];
          const pat = last instanceof Name ? this.lookup(this.sub(resources, "Pattern")?.get(PDFName.of(last.name))) : undefined;
          if (pat instanceof PDFRawStream && !inChain(ancestors, pat)) yield { stream: pat, ref: null, resources, state: { font: false, tr: new Num(0, "0") }, ancestors, kind: "fresh", reply: () => {} };
          continue;
        }
        case "sh":
          if (!hidden()) line(a, "sh");
          continue;
        case "Tj":
        case "'":
        case '"':
        case "TJ": {
          if (!state.font) continue;
          const text = cmd === '"' ? a[2] : a[0];
          // pdf.js's text handling throws (and stops the stream) on operands it can't read as text.
          if (cmd === "TJ" ? !(Array.isArray(text) || typeof text === "string") : (Array.isArray(text) && text.length > 0) || text instanceof InlineImage) return close();
          if (hidden()) out.push(`3 Tr ${a.map(writeValue).join(" ")} ${cmd} ${writeValue(state.tr)} Tr`);
          else line(a, cmd);
          continue;
        }
        case "sc":
        case "SC":
        case "g":
        case "G":
        case "rg":
        case "RG":
        case "k":
        case "K":
          if (allNumbers(args)) line(a, cmd);
          continue;
        case "w": {
          const t = a[0];
          if (!(t instanceof Num)) continue;
          out.push(`${t.text.replace(/^-/, "")} w`);
          continue;
        }
        case "d": {
          if (!(a[1] instanceof Num) || !Array.isArray(a[0])) continue;
          line([(a[0] as PValue[]).filter((x) => x instanceof Num), a[1]], "d");
          continue;
        }
        case "MP":
        case "DP":
        case "BX":
        case "EX":
          continue;
        case "BMC":
          if (a.some((x) => x instanceof Dict)) continue;
          marked.push(true);
          out.push(`${writeName(a[0] instanceof Name ? a[0].name : "Mark")} BMC`);
          continue;
        case "BDC": {
          if (!(a[0] instanceof Name)) {
            marked.push(true);
            out.push("/Mark BMC");
            continue;
          }
          if (a[0].name === "OC") {
            const props = a[1];
            let shown = true;
            try {
              if (props instanceof Name) shown = this.visible(this.sub(resources, "Properties")?.get(PDFName.of(props.name)));
              else if (props instanceof Dict) shown = this.visible(toPdfLib(this.pdf, props));
            } catch (e) {
              if (isEngineError(e)) throw e;
              shown = true;
            }
            marked.push(shown);
            out.push("/OC <<>> BDC");
            continue;
          }
          marked.push(true);
          out.push(`${writeName(a[0].name)} BMC`);
          continue;
        }
        case "EMC":
          if (a.some((x) => x instanceof Dict) || marked.length === 0) continue;
          marked.pop();
          out.push("EMC");
          continue;
      }
      if (a.some((x) => x instanceof Dict)) continue;
      if (PAINTING.has(cmd)) {
        pathPending = false;
        line(null, hidden() ? "n" : cmd);
        continue;
      }
      if (cmd === "n") pathPending = false;
      else if (PATH_BUILDING.has(cmd)) pathPending = true;
      line(a, cmd);
    }
    return close();
    function close(): Uint8Array {
      const tail: string[] = [];
      if (inText) tail.push("ET");
      if (pathPending) tail.push("n");
      for (let k = 0; k < marked.length; k++) tail.push("EMC");
      for (let k = 0; k < saved.length; k++) tail.push("Q");
      const text = (excess ? "q ".repeat(excess) + "\n" : "") + out.join("\n") + (tail.length ? "\n" + tail.join("\n") : "") + "\n";
      const bytes = new Uint8Array(text.length);
      for (let i = 0; i < text.length; i++) bytes[i] = text.charCodeAt(i) & 0xff;
      return bytes;
    }
  }
}
const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);
