// Renderer v3: a document read exactly as pdf.js 6.4.299 reads it for the signer.
//
// The signing page shows a document with pdf.js. A reader that resolves objects any other way (pdf-lib keeps the last
// definition of each object number it finds in the file, wherever it is, and ignores the cross-reference table) can be
// shown a different document by the same bytes: an object defined twice, an update appended without a new
// cross-reference section, an object stream that redefines an object. So v3 reads every document the way pdf.js reads
// it, step for step: its lexer and parser, its cross-reference reading (tables, streams, the /Prev chain, hybrid files'
// XRefStm, and which entry wins), its object fetching (an uncompressed object at its offset, checked against its number
// and generation; a compressed one from its object stream), its reconstruction of a file whose cross-reference is
// broken or missing (indexObjects), its decryption (CipherTransformFactory), its stream decoders, and its page tree (the
// pages pdf.js finds, with the caches and cycle checks it uses, and its recovery when the page count is wrong). The
// classifier, both kinds of copy and the verifier all read the document this module returns, so they all see exactly
// the objects and pages pdf.js showed the signer.
//
// Its code follows pdf.js's (Copyright Mozilla Foundation, Apache License 2.0), rewritten in TypeScript with no
// built-in newer than ES2020, so every engine computes the same. A byte-identical copy lives in
// DataHubz/attest-verifier (src/renderer/pdfjs-v3.ts).

import { aesCbcDecryptBlocks, aesCbcEncrypt, md5, rc4, sha256, sha384, sha512 } from "./decrypt-v3";

// ---- Errors, as pdf.js names them -------------------------------------------------------------------------------

export class PdfjsError extends Error {
  constructor(readonly kind: "Format" | "XRefEntry" | "XRefParse" | "ParserEOF" | "InvalidPDF" | "Password" | "Unexpected", message: string) {
    super(message);
  }
}
const formatError = (m: string) => new PdfjsError("Format", m);

// ---- Primitives (primitives.js) ---------------------------------------------------------------------------------

export class Name {
  constructor(readonly name: string) {}
}
export class Cmd {
  constructor(readonly cmd: string) {}
}
export class Ref {
  readonly str: string;
  constructor(readonly num: number, readonly gen: number) {
    this.str = gen === 0 ? `${num}R` : `${num}R${gen}`;
  }
  toString() {
    return this.str;
  }
}
export class RefSet {
  private set = new Set<string>();
  has(ref: Ref | string) {
    return this.set.has(String(ref));
  }
  put(ref: Ref | string) {
    this.set.add(String(ref));
  }
  remove(ref: Ref | string) {
    this.set.delete(String(ref));
  }
}
export class RefMap<T> {
  private map = new Map<string, T>();
  get(ref: Ref | string) {
    return this.map.get(String(ref));
  }
  has(ref: Ref | string) {
    return this.map.has(String(ref));
  }
  put(ref: Ref | string, v: T) {
    this.map.set(String(ref), v);
  }
  clear() {
    this.map.clear();
  }
}
export const EOF = Symbol("EOF");
export const CIRCULAR_REF = Symbol("CIRCULAR_REF");

/** A value pdf.js's parser makes: numbers, byte strings (one character per byte), booleans, null, names, commands, refs, dictionaries, arrays and streams. */
export type PValue = number | string | boolean | null | undefined | Name | Cmd | Ref | Dict | PValue[] | PStream | InlineImage | BaseStream | typeof EOF | typeof CIRCULAR_REF;

export class Dict {
  readonly map = new Map<string, PValue>();
  objId: string | null = null;
  suppressEncryption = false;
  constructor(public xref: XRef | null = null) {}
  get size() {
    return this.map.size;
  }
  get(key1: string, key2?: string): PValue {
    let value = this.map.get(key1);
    if (value === undefined && key2 !== undefined) value = this.map.get(key2);
    if (value instanceof Ref && this.xref) return this.xref.fetch(value, this.suppressEncryption);
    return value;
  }
  getArray(key1: string, key2?: string): PValue {
    let value = this.get(key1, key2);
    if (Array.isArray(value)) {
      value = value.slice();
      for (let i = 0; i < value.length; i++) {
        const v = value[i];
        if (v instanceof Ref && this.xref) value[i] = this.xref.fetch(v, this.suppressEncryption);
      }
    }
    return value;
  }
  getRaw(key: string): PValue {
    return this.map.get(key);
  }
  has(key: string) {
    return this.map.has(key);
  }
  set(key: string, value: PValue) {
    this.map.set(key, value);
  }
  setIfNotExists(key: string, value: PValue) {
    if (!this.has(key)) this.set(key, value);
  }
  delete(key: string) {
    this.map.delete(key);
  }
  /** Dict.merge (without mergeSubDicts): for each key, the first dictionary's value; an empty result is Dict.empty. */
  static merge(xref: XRef | null, dictArray: PValue[], mergeSubDicts = false): Dict {
    const merged = new Dict(xref);
    const properties = new Map<string, PValue[]>();
    for (const dict of dictArray) {
      if (!(dict instanceof Dict)) continue;
      for (const [key, value] of dict.map) {
        let property = properties.get(key);
        if (!property) properties.set(key, (property = []));
        if (property.length && !(mergeSubDicts && value instanceof Dict)) continue;
        property.push(value);
      }
    }
    for (const [name, values] of properties) {
      if (values.length === 1 || !(values[0] instanceof Dict)) {
        merged.set(name, values[0]);
        continue;
      }
      const sub = new Dict(xref);
      for (const d of values) for (const [k, v] of (d as Dict).map) sub.setIfNotExists(k, v);
      if (sub.size > 0) merged.set(name, sub);
    }
    return merged.size > 0 ? merged : EMPTY_DICT;
  }
}
const EMPTY_DICT = new Dict(null);

export const isName = (v: unknown, name?: string): v is Name => v instanceof Name && (name === undefined || v.name === name);
export const isCmd = (v: unknown, cmd?: string): v is Cmd => v instanceof Cmd && (cmd === undefined || v.cmd === cmd);
const isInt = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v);

/** JavaScript's ToNumber for the values pdf.js does arithmetic on without checking them. */
export function jsNumber(v: PValue): number {
  if (typeof v === "number") return v;
  if (typeof v === "boolean") return v ? 1 : 0;
  if (v === null) return 0;
  if (v === undefined) return NaN;
  if (typeof v === "string") return jsStringNumber(v);
  if (Array.isArray(v)) {
    // Array.prototype.toString joins the elements' strings.
    if (v.length === 0) return 0;
    if (v.length === 1) return Number(jsString(v[0]));
    return NaN;
  }
  if (v instanceof Ref) return NaN;
  return NaN;
}
function jsString(v: PValue): string {
  if (typeof v === "number") return String(v);
  if (typeof v === "string") return v;
  if (typeof v === "boolean") return v ? "true" : "false";
  if (v === null || v === undefined) return "";
  if (v instanceof Ref) return v.str;
  if (Array.isArray(v)) return v.map((x) => (x === null || x === undefined ? "" : jsString(x))).join(",");
  return "[object Object]";
}
/** A string's ToNumber, which the language defines exactly (white space trimmed, decimal, hex, binary and octal forms). */
const jsStringNumber = (s: string): number => Number(s);

// ---- Bytes and strings --------------------------------------------------------------------------------------------

export function bytesToString(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 8192) {
    const chunk = bytes.subarray(i, Math.min(i + 8192, bytes.length));
    out += String.fromCharCode.apply(null, chunk as unknown as number[]);
  }
  return out;
}
export function stringToBytes(str: PValue): Uint8Array {
  if (typeof str !== "string") throw new PdfjsError("Unexpected", "Invalid argument for stringToBytes");
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i) & 0xff;
  return bytes;
}
export const isWhiteSpace = (ch: number) => ch === 0x20 || ch === 0x09 || ch === 0x0d || ch === 0x0a;

// ---- Streams (base_stream.js, stream.js, decode_stream.js) ------------------------------------------------------

export abstract class BaseStream {
  pos = 0;
  dict: Dict | null = null;
  abstract getByte(): number;
  abstract getBytes(length?: number): Uint8Array;
  abstract reset(): void;
  abstract makeSubStream(start: number, length?: number, dict?: Dict | null): BaseStream;
  abstract get length(): number;
  get isImageStream() {
    return false;
  }
  get isEmpty(): boolean {
    return this.length === 0;
  }
  peekByte() {
    const b = this.getByte();
    if (b !== -1) this.pos--;
    return b;
  }
  peekBytes(length?: number) {
    const bytes = this.getBytes(length);
    this.pos -= bytes.length;
    return bytes;
  }
  getUint16() {
    const b0 = this.getByte();
    const b1 = this.getByte();
    return b0 === -1 || b1 === -1 ? -1 : (b0 << 8) + b1;
  }
  skip(n?: number) {
    this.pos += n || 1;
  }
  getString(length?: number) {
    return bytesToString(this.getBytes(length));
  }
}

export class Stream extends BaseStream {
  bytes: Uint8Array;
  start: number;
  end: number;
  constructor(bytes: Uint8Array, start?: number, length?: number, dict: Dict | null = null) {
    super();
    this.bytes = bytes;
    this.start = start || 0;
    this.pos = this.start;
    const end = (start as number) + (length as number);
    this.end = end || bytes.length;
    this.dict = dict;
  }
  get length() {
    return this.end - this.start;
  }
  getByte() {
    return this.pos >= this.end ? -1 : this.bytes[this.pos++];
  }
  getBytes(length?: number) {
    const pos = this.pos;
    const endPos = !length ? this.end : Math.min(pos + length, this.end);
    this.pos = endPos;
    return this.bytes.subarray(pos, endPos);
  }
  getByteRange(begin: number, end: number) {
    if (begin < 0) begin = 0;
    if (end > this.end) end = this.end;
    return this.bytes.subarray(begin, end);
  }
  reset() {
    this.pos = this.start;
  }
  moveStart() {
    this.start = this.pos;
  }
  makeSubStream(start: number, length?: number, dict: Dict | null = null): Stream {
    return new Stream(this.bytes, start, length, dict);
  }
}

export class NullStream extends Stream {
  constructor() {
    super(new Uint8Array(0));
  }
}

const emptyBuffer = new Uint8Array(0);
export abstract class DecodeStream extends BaseStream {
  buffer: Uint8Array = emptyBuffer;
  bufferLength = 0;
  eof = false;
  minBufferLength = 512;
  rawMinBufferLength: number;
  constructor(maybeMinBufferLength?: number | null) {
    super();
    this.pos = 0;
    this.rawMinBufferLength = maybeMinBufferLength || 0;
    if (maybeMinBufferLength) while (this.minBufferLength < maybeMinBufferLength) this.minBufferLength *= 2;
  }
  abstract readBlock(): void;
  get length(): number {
    throw new PdfjsError("Unexpected", "length of a decode stream");
  }
  get isEmpty() {
    while (!this.eof && this.bufferLength === 0) this.readBlock();
    return this.bufferLength === 0;
  }
  ensureBuffer(requested: number) {
    const buffer = this.buffer;
    if (requested <= buffer.byteLength) return buffer;
    let size = this.minBufferLength;
    while (size < requested) size *= 2;
    const buffer2 = new Uint8Array(size);
    buffer2.set(buffer);
    return (this.buffer = buffer2);
  }
  getByte() {
    const pos = this.pos;
    while (this.bufferLength <= pos) {
      if (this.eof) return -1;
      this.readBlock();
    }
    return this.buffer[this.pos++];
  }
  getBytes(length?: number) {
    const pos = this.pos;
    let end: number;
    if (length) {
      this.ensureBuffer(pos + length);
      end = pos + length;
      while (!this.eof && this.bufferLength < end) this.readBlock();
      if (end > this.bufferLength) end = this.bufferLength;
    } else {
      while (!this.eof) this.readBlock();
      end = this.bufferLength;
    }
    this.pos = end;
    return this.buffer.subarray(pos, end);
  }
  reset() {
    this.pos = 0;
  }
  makeSubStream(start: number, length?: number, dict: Dict | null = null): Stream {
    if (length === undefined) {
      while (!this.eof) this.readBlock();
    } else {
      const end = start + length;
      while (this.bufferLength <= end && !this.eof) this.readBlock();
    }
    return new Stream(this.buffer, start, length, dict);
  }
}

/** StreamsSequenceStream: a page's content streams one after the other; one that fails to decode is left out whole. */
export class StreamsSequenceStream extends DecodeStream {
  streams: BaseStream[];
  failed: unknown[] = [];
  constructor(streams: BaseStream[]) {
    streams = streams.filter((s) => s instanceof BaseStream && !s.isImageStream);
    let maybeLength = 0;
    for (const s of streams) maybeLength += s instanceof DecodeStream ? s.rawMinBufferLength : s.length;
    super(maybeLength);
    this.streams = streams;
  }
  readBlock() {
    const streams = this.streams;
    if (streams.length === 0) {
      this.eof = true;
      return;
    }
    const stream = streams.shift()!;
    let chunk: Uint8Array;
    try {
      chunk = stream.getBytes();
    } catch (reason) {
      if (isEngineError(reason)) throw reason;
      this.failed.push(reason);
      return;
    }
    const bufferLength = this.bufferLength;
    const newLength = bufferLength + chunk.length;
    const buffer = this.ensureBuffer(newLength);
    buffer.set(chunk, bufferLength);
    this.bufferLength = newLength;
  }
}

/** An engine's own failure (out of memory or stack), never taken for the document's. */
export const isEngineError = (e: unknown) => /Maximum call stack|too much recursion|allocation failed|out of memory|Invalid array length|Array buffer allocation/i.test(String((e as Error)?.message ?? e));

// ---- Decoders (flate_stream.js, predictor_stream.js, lzw_stream.js, ascii_85_stream.js, ascii_hex_stream.js, run_length_stream.js)

const codeLenCodeMap = new Int32Array([16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]);
const lengthDecode = new Int32Array([0x00003, 0x00004, 0x00005, 0x00006, 0x00007, 0x00008, 0x00009, 0x0000a, 0x1000b, 0x1000d, 0x1000f, 0x10011, 0x20013, 0x20017, 0x2001b, 0x2001f, 0x30023, 0x3002b, 0x30033, 0x3003b, 0x40043, 0x40053, 0x40063, 0x40073, 0x50083, 0x500a3, 0x500c3, 0x500e3, 0x00102, 0x00102, 0x00102]);
const distDecode = new Int32Array([0x00001, 0x00002, 0x00003, 0x00004, 0x10005, 0x10007, 0x20009, 0x2000d, 0x30011, 0x30019, 0x40021, 0x40031, 0x50041, 0x50061, 0x60081, 0x600c1, 0x70101, 0x70181, 0x80201, 0x80301, 0x90401, 0x90601, 0xa0801, 0xa0c01, 0xb1001, 0xb1801, 0xc2001, 0xc3001, 0xd4001, 0xd6001]);
type CodeTable = [Int32Array, number];
/** pdf.js's fixed tables are the Huffman tables of the fixed code lengths (RFC 1951, 3.2.6), built the same way. */
let fixedTables: [CodeTable, CodeTable] | null = null;

export class FlateStream extends DecodeStream {
  stream: BaseStream;
  codeSize = 0;
  codeBuf = 0;
  constructor(str: BaseStream, maybeLength?: number | null) {
    super(maybeLength);
    this.stream = str;
    this.dict = str.dict;
    const cmf = str.getByte();
    const flg = str.getByte();
    if (cmf === -1 || flg === -1) throw formatError(`Invalid header in flate stream: ${cmf}, ${flg}`);
    if ((cmf & 0x0f) !== 0x08) throw formatError(`Unknown compression method in flate stream: ${cmf}, ${flg}`);
    if (((cmf << 8) + flg) % 31 !== 0) throw formatError(`Bad FCHECK in flate stream: ${cmf}, ${flg}`);
    if (flg & 0x20) throw formatError(`FDICT bit set in flate stream: ${cmf}, ${flg}`);
  }
  getBits(bits: number) {
    const str = this.stream;
    let codeSize = this.codeSize;
    let codeBuf = this.codeBuf;
    let b: number;
    while (codeSize < bits) {
      if ((b = str.getByte()) === -1) throw formatError("Bad encoding in flate stream");
      codeBuf |= b << codeSize;
      codeSize += 8;
    }
    b = codeBuf & ((1 << bits) - 1);
    this.codeBuf = codeBuf >> bits;
    this.codeSize = codeSize -= bits;
    return b;
  }
  getCode(table: CodeTable) {
    const str = this.stream;
    const codes = table[0];
    const maxLen = table[1];
    let codeSize = this.codeSize;
    let codeBuf = this.codeBuf;
    let b: number;
    while (codeSize < maxLen) {
      if ((b = str.getByte()) === -1) break;
      codeBuf |= b << codeSize;
      codeSize += 8;
    }
    const code = codes[codeBuf & ((1 << maxLen) - 1)];
    const codeLen = code >> 16;
    const codeVal = code & 0xffff;
    if (codeLen < 1 || codeSize < codeLen) throw formatError("Bad encoding in flate stream");
    this.codeBuf = codeBuf >> codeLen;
    this.codeSize = codeSize - codeLen;
    return codeVal;
  }
  static generateHuffmanTable(lengths: Uint8Array): CodeTable {
    const n = lengths.length;
    let maxLen = 0;
    let i: number;
    for (i = 0; i < n; ++i) if (lengths[i] > maxLen) maxLen = lengths[i];
    const size = 1 << maxLen;
    const codes = new Int32Array(size);
    for (let len = 1, code = 0, skip = 2; len <= maxLen; ++len, code <<= 1, skip <<= 1) {
      for (let val = 0; val < n; ++val) {
        if (lengths[val] === len) {
          let code2 = 0;
          let t = code;
          for (i = 0; i < len; ++i) {
            code2 = (code2 << 1) | (t & 1);
            t >>= 1;
          }
          for (i = code2; i < size; i += skip) codes[i] = (len << 16) | val;
          ++code;
        }
      }
    }
    return [codes, maxLen];
  }
  readBlock() {
    let buffer: Uint8Array;
    let hdr: number;
    let len: number;
    const str = this.stream;
    try {
      hdr = this.getBits(3);
    } catch (ex) {
      if (isEngineError(ex)) throw ex;
      this.eof = true;
      return;
    }
    if (hdr & 1) this.eof = true;
    hdr >>= 1;
    if (hdr === 0) {
      let b: number;
      if ((b = str.getByte()) === -1) return void (this.eof = true);
      let blockLen = b;
      if ((b = str.getByte()) === -1) return void (this.eof = true);
      blockLen |= b << 8;
      if ((b = str.getByte()) === -1) return void (this.eof = true);
      let check = b;
      if ((b = str.getByte()) === -1) return void (this.eof = true);
      check |= b << 8;
      if (check !== (~blockLen & 0xffff) && (blockLen !== 0 || check !== 0)) throw formatError("Bad uncompressed block length in flate stream");
      this.codeBuf = 0;
      this.codeSize = 0;
      const bufferLength = this.bufferLength;
      const end = bufferLength + blockLen;
      buffer = this.ensureBuffer(end);
      this.bufferLength = end;
      if (blockLen === 0) {
        if (str.peekByte() === -1) this.eof = true;
      } else {
        const block = str.getBytes(blockLen);
        buffer.set(block, bufferLength);
        if (block.length < blockLen) this.eof = true;
      }
      return;
    }
    let litCodeTable: CodeTable;
    let distCodeTable: CodeTable;
    if (hdr === 1) {
      if (!fixedTables) {
        const lit = new Uint8Array(288);
        for (let k = 0; k < 288; k++) lit[k] = k < 144 ? 8 : k < 256 ? 9 : k < 280 ? 7 : 8;
        const dist = new Uint8Array(30).fill(5);
        fixedTables = [FlateStream.generateHuffmanTable(lit), FlateStream.generateHuffmanTable(dist)];
      }
      [litCodeTable, distCodeTable] = fixedTables;
    } else if (hdr === 2) {
      const numLitCodes = this.getBits(5) + 257;
      const numDistCodes = this.getBits(5) + 1;
      const numCodeLenCodes = this.getBits(4) + 4;
      const codeLenCodeLengths = new Uint8Array(codeLenCodeMap.length);
      let i: number;
      for (i = 0; i < numCodeLenCodes; ++i) codeLenCodeLengths[codeLenCodeMap[i]] = this.getBits(3);
      const codeLenCodeTab = FlateStream.generateHuffmanTable(codeLenCodeLengths);
      len = 0;
      i = 0;
      const codes = numLitCodes + numDistCodes;
      const codeLengths = new Uint8Array(codes);
      let bitsLength: number, bitsOffset: number, what: number;
      while (i < codes) {
        const code = this.getCode(codeLenCodeTab);
        if (code === 16) {
          bitsLength = 2;
          bitsOffset = 3;
          what = len;
        } else if (code === 17) {
          bitsLength = 3;
          bitsOffset = 3;
          what = len = 0;
        } else if (code === 18) {
          bitsLength = 7;
          bitsOffset = 11;
          what = len = 0;
        } else {
          codeLengths[i++] = len = code;
          continue;
        }
        let repeatLength = this.getBits(bitsLength) + bitsOffset;
        while (repeatLength-- > 0) codeLengths[i++] = what;
      }
      litCodeTable = FlateStream.generateHuffmanTable(codeLengths.subarray(0, numLitCodes));
      distCodeTable = FlateStream.generateHuffmanTable(codeLengths.subarray(numLitCodes, codes));
    } else {
      throw formatError("Unknown block type in flate stream");
    }
    buffer = this.buffer;
    let limit = buffer ? buffer.length : 0;
    let pos = this.bufferLength;
    for (;;) {
      let code1 = this.getCode(litCodeTable);
      if (code1 < 256) {
        if (pos + 1 >= limit) {
          buffer = this.ensureBuffer(pos + 1);
          limit = buffer.length;
        }
        buffer[pos++] = code1;
        continue;
      }
      if (code1 === 256) {
        this.bufferLength = pos;
        return;
      }
      code1 -= 257;
      code1 = lengthDecode[code1];
      let code2 = code1 >> 16;
      if (code2 > 0) code2 = this.getBits(code2);
      len = (code1 & 0xffff) + code2;
      code1 = this.getCode(distCodeTable);
      code1 = distDecode[code1];
      code2 = code1 >> 16;
      if (code2 > 0) code2 = this.getBits(code2);
      const dist = (code1 & 0xffff) + code2;
      if (pos + len >= limit) {
        buffer = this.ensureBuffer(pos + len);
        limit = buffer.length;
      }
      for (let k = 0; k < len; ++k, ++pos) buffer[pos] = buffer[pos - dist];
    }
  }
}

/** pdf.js's PredictorStream: its constructor returns the stream it wraps when there's no predictor to apply. */
export function predictorStream(str: BaseStream, maybeLength: number | null | undefined, params: PValue): BaseStream {
  if (!(params instanceof Dict)) return str;
  const p = params.get("Predictor");
  const predictor = (p as never) || 1;
  if (jsLessOrEqual(predictor, 1)) return str;
  if (predictor !== 2 && (jsLess(predictor, 10) || jsGreater(predictor, 15))) throw formatError(`Unsupported predictor: ${jsString(predictor)}`);
  return new PredictorStream(str, maybeLength, params, predictor);
}
const jsLess = (a: PValue, b: number) => jsNumber(a) < b;
const jsGreater = (a: PValue, b: number) => jsNumber(a) > b;
const jsLessOrEqual = (a: PValue, b: number) => jsNumber(a) <= b;

class PredictorStream extends DecodeStream {
  stream: BaseStream;
  tiff: boolean;
  colors: number;
  bits: number;
  columns: number;
  pixBytes: number;
  rowBytes: number;
  constructor(str: BaseStream, maybeLength: number | null | undefined, params: Dict, predictor: PValue) {
    super(maybeLength);
    this.tiff = predictor === 2;
    this.stream = str;
    this.dict = str.dict;
    const colors = (params.get("Colors") as never) || 1;
    const bits = (params.get("BPC", "BitsPerComponent") as never) || 8;
    const columns = (params.get("Columns") as never) || 1;
    this.colors = jsNumber(colors);
    this.bits = jsNumber(bits);
    this.columns = jsNumber(columns);
    this.pixBytes = (this.colors * this.bits + 7) >> 3;
    this.rowBytes = (this.columns * this.colors * this.bits + 7) >> 3;
    // Kept for pdf.js's comparisons on them, which are made on the values as they are.
    this.bitsValue = bits;
    this.colorsValue = colors;
  }
  bitsValue: PValue;
  colorsValue: PValue;
  readBlock() {
    if (this.tiff) this.readBlockTiff();
    else this.readBlockPng();
  }
  readBlockTiff() {
    const rowBytes = this.rowBytes;
    const bufferLength = this.bufferLength;
    const buffer = this.ensureBuffer(bufferLength + rowBytes);
    const bits = this.bits;
    const colors = this.colors;
    const rawBytes = this.stream.getBytes(rowBytes);
    this.eof = !rawBytes.length;
    if (this.eof) return;
    let inbuf = 0, outbuf = 0, inbits = 0, outbits = 0;
    let pos = bufferLength;
    let i: number;
    const at = (a: ArrayLike<number>, k: number) => (k >= 0 && k < a.length ? a[k] : NaN);
    if (this.bitsValue === 1 && this.colorsValue === 1) {
      for (i = 0; i < rowBytes; ++i) {
        let c = at(rawBytes, i) ^ inbuf;
        c ^= c >> 1;
        c ^= c >> 2;
        c ^= c >> 4;
        inbuf = (c & 1) << 7;
        buffer[pos++] = c;
      }
    } else if (this.bitsValue === 8) {
      for (i = 0; i < colors; ++i) buffer[pos++] = at(rawBytes, i);
      for (; i < rowBytes; ++i) {
        buffer[pos] = at(buffer, pos - colors) + at(rawBytes, i);
        pos++;
      }
    } else if (this.bitsValue === 16) {
      const bytesPerPixel = colors * 2;
      for (i = 0; i < bytesPerPixel; ++i) buffer[pos++] = at(rawBytes, i);
      for (; i < rowBytes; i += 2) {
        const sum = ((at(rawBytes, i) & 0xff) << 8) + (at(rawBytes, i + 1) & 0xff) + ((at(buffer, pos - bytesPerPixel) & 0xff) << 8) + (at(buffer, pos - bytesPerPixel + 1) & 0xff);
        buffer[pos++] = (sum >> 8) & 0xff;
        buffer[pos++] = sum & 0xff;
      }
    } else {
      const compArray = new Uint8Array(colors + 1);
      const bitMask = (1 << bits) - 1;
      let j = 0, k = bufferLength;
      const columns = this.columns;
      for (i = 0; i < columns; ++i) {
        for (let kk = 0; kk < colors; ++kk) {
          if (inbits < bits) {
            inbuf = (inbuf << 8) | (at(rawBytes, j++) & 0xff);
            inbits += 8;
          }
          compArray[kk] = (compArray[kk] + (inbuf >> (inbits - bits))) & bitMask;
          inbits -= bits;
          outbuf = (outbuf << bits) | compArray[kk];
          outbits += bits;
          if (outbits >= 8) {
            buffer[k++] = (outbuf >> (outbits - 8)) & 0xff;
            outbits -= 8;
          }
        }
      }
      if (outbits > 0) buffer[k++] = (outbuf << (8 - outbits)) + (inbuf & ((1 << (8 - outbits)) - 1));
    }
    this.bufferLength += rowBytes;
  }
  readBlockPng() {
    const rowBytes = this.rowBytes;
    const pixBytes = this.pixBytes;
    const predictor = this.stream.getByte();
    const rawBytes = this.stream.getBytes(rowBytes);
    this.eof = !rawBytes.length;
    if (this.eof) return;
    const bufferLength = this.bufferLength;
    const buffer = this.ensureBuffer(bufferLength + rowBytes);
    let prevRow = buffer.subarray(bufferLength - rowBytes, bufferLength);
    if (prevRow.length === 0) prevRow = new Uint8Array(rowBytes);
    const at = (a: ArrayLike<number>, k: number) => (k >= 0 && k < a.length ? a[k] : NaN);
    let i: number;
    let j = bufferLength;
    switch (predictor) {
      case 0:
        for (i = 0; i < rowBytes; ++i) buffer[j++] = at(rawBytes, i);
        break;
      case 1:
        for (i = 0; i < pixBytes; ++i) buffer[j++] = at(rawBytes, i);
        for (; i < rowBytes; ++i) {
          buffer[j] = (at(buffer, j - pixBytes) + at(rawBytes, i)) & 0xff;
          j++;
        }
        break;
      case 2:
        for (i = 0; i < rowBytes; ++i) buffer[j++] = (at(prevRow, i) + at(rawBytes, i)) & 0xff;
        break;
      case 3:
        for (i = 0; i < pixBytes; ++i) buffer[j++] = (at(prevRow, i) >> 1) + at(rawBytes, i);
        for (; i < rowBytes; ++i) {
          buffer[j] = (((at(prevRow, i) + at(buffer, j - pixBytes)) >> 1) + at(rawBytes, i)) & 0xff;
          j++;
        }
        break;
      case 4:
        for (i = 0; i < pixBytes; ++i) buffer[j++] = at(prevRow, i) + at(rawBytes, i);
        for (; i < rowBytes; ++i) {
          const up = at(prevRow, i);
          const upLeft = at(prevRow, i - pixBytes);
          const left = at(buffer, j - pixBytes);
          const p = left + up - upLeft;
          let pa = p - left;
          if (pa < 0) pa = -pa;
          let pb = p - up;
          if (pb < 0) pb = -pb;
          let pc = p - upLeft;
          if (pc < 0) pc = -pc;
          const c = at(rawBytes, i);
          if (pa <= pb && pa <= pc) buffer[j++] = left + c;
          else if (pb <= pc) buffer[j++] = up + c;
          else buffer[j++] = upLeft + c;
        }
        break;
      default:
        throw formatError(`Unsupported predictor: ${predictor}`);
    }
    this.bufferLength += rowBytes;
  }
}

class LZWStream extends DecodeStream {
  stream: BaseStream;
  cachedData = 0;
  bitsCached = 0;
  lzw: {
    earlyChange: number;
    codeLength: number;
    nextCode: number;
    dictionaryValues: Uint8Array;
    dictionaryLengths: Uint16Array;
    dictionaryPrevCodes: Uint16Array;
    currentSequence: Uint8Array;
    currentSequenceLength: number;
    prevCode?: number;
  } | null;
  constructor(str: BaseStream, maybeLength: number | null | undefined, earlyChange: number) {
    super(maybeLength);
    this.stream = str;
    this.dict = str.dict;
    const size = 4096;
    this.lzw = {
      earlyChange,
      codeLength: 9,
      nextCode: 258,
      dictionaryValues: new Uint8Array(size),
      dictionaryLengths: new Uint16Array(size).fill(1, 0, 256),
      dictionaryPrevCodes: new Uint16Array(size),
      currentSequence: new Uint8Array(size),
      currentSequenceLength: 0,
    };
    for (let i = 0; i < 256; ++i) this.lzw.dictionaryValues[i] = i;
  }
  readBits(n: number): number | null {
    let bitsCached = this.bitsCached;
    let cachedData = this.cachedData;
    while (bitsCached < n) {
      const c = this.stream.getByte();
      if (c === -1) {
        this.eof = true;
        return null;
      }
      cachedData = (cachedData << 8) | c;
      bitsCached += 8;
    }
    this.bitsCached = bitsCached -= n;
    this.cachedData = cachedData;
    return (cachedData >>> bitsCached) & ((1 << n) - 1);
  }
  readBlock() {
    const blockSize = 512;
    let estimatedDecodedSize = blockSize * 2;
    let i: number, j: number, q: number;
    const st = this.lzw;
    if (!st) throw new TypeError("Cannot destructure property 'earlyChange' of 'lzwState' as it is undefined.");
    const earlyChange = st.earlyChange;
    let nextCode = st.nextCode;
    const dictionaryValues = st.dictionaryValues;
    const dictionaryLengths = st.dictionaryLengths;
    const dictionaryPrevCodes = st.dictionaryPrevCodes;
    let codeLength = st.codeLength;
    let prevCode = st.prevCode as number;
    const currentSequence = st.currentSequence;
    let currentSequenceLength = st.currentSequenceLength;
    let decodedLength = 0;
    let currentBufferLength = this.bufferLength;
    let buffer = this.ensureBuffer(this.bufferLength + estimatedDecodedSize);
    for (i = 0; i < blockSize; i++) {
      const code = this.readBits(codeLength);
      const hasPrev = currentSequenceLength > 0;
      if (code !== null && code < 256) {
        currentSequence[0] = code;
        currentSequenceLength = 1;
      } else if (code !== null && code >= 258) {
        if (code < nextCode) {
          currentSequenceLength = dictionaryLengths[code];
          for (j = currentSequenceLength - 1, q = code; j >= 0; j--) {
            currentSequence[j] = dictionaryValues[q];
            q = dictionaryPrevCodes[q];
          }
        } else {
          currentSequence[currentSequenceLength++] = currentSequence[0];
        }
      } else if (code === 256) {
        codeLength = 9;
        nextCode = 258;
        currentSequenceLength = 0;
        continue;
      } else {
        // 257 (end of data), or no more bits (null: pdf.js's comparisons with null take this branch too).
        this.eof = true;
        this.lzw = null;
        break;
      }
      if (hasPrev) {
        dictionaryPrevCodes[nextCode] = prevCode;
        dictionaryLengths[nextCode] = dictionaryLengths[prevCode] + 1;
        dictionaryValues[nextCode] = currentSequence[0];
        nextCode++;
        codeLength = (nextCode + earlyChange) & (nextCode + earlyChange - 1) ? codeLength : Math.min(Math.log(nextCode + earlyChange) / 0.6931471805599453 + 1, 12) | 0;
      }
      prevCode = code;
      decodedLength += currentSequenceLength;
      if (estimatedDecodedSize < decodedLength) {
        do estimatedDecodedSize += blockSize;
        while (estimatedDecodedSize < decodedLength);
        buffer = this.ensureBuffer(this.bufferLength + estimatedDecodedSize);
      }
      for (j = 0; j < currentSequenceLength; j++) buffer[currentBufferLength++] = currentSequence[j];
    }
    if (this.lzw) {
      this.lzw.nextCode = nextCode;
      this.lzw.codeLength = codeLength;
      this.lzw.prevCode = prevCode;
      this.lzw.currentSequenceLength = currentSequenceLength;
    }
    this.bufferLength = currentBufferLength;
  }
}

class Ascii85Stream extends DecodeStream {
  stream: BaseStream;
  input = new Uint8Array(5);
  constructor(str: BaseStream, maybeLength: number | null | undefined) {
    super(maybeLength ? maybeLength * 0.8 : maybeLength);
    this.stream = str;
    this.dict = str.dict;
  }
  readBlock() {
    const str = this.stream;
    let c = str.getByte();
    while (isWhiteSpace(c)) c = str.getByte();
    if (c === -1 || c === 0x7e) {
      this.eof = true;
      return;
    }
    const bufferLength = this.bufferLength;
    let buffer: Uint8Array;
    let i: number;
    if (c === 0x7a) {
      buffer = this.ensureBuffer(bufferLength + 4);
      buffer.fill(0, bufferLength, bufferLength + 4);
      this.bufferLength += 4;
    } else {
      const input = this.input;
      input[0] = c;
      for (i = 1; i < 5; ++i) {
        c = str.getByte();
        while (isWhiteSpace(c)) c = str.getByte();
        input[i] = c;
        if (c === -1 || c === 0x7e) break;
      }
      buffer = this.ensureBuffer(bufferLength + i - 1);
      this.bufferLength += i - 1;
      if (i < 5) {
        input.fill(0x21 + 84, i, 5);
        this.eof = true;
      }
      let t = 0;
      for (i = 0; i < 5; ++i) t = t * 85 + (input[i] - 0x21);
      for (i = 3; i >= 0; --i) {
        buffer[bufferLength + i] = t & 0xff;
        t >>= 8;
      }
    }
  }
}

class AsciiHexStream extends DecodeStream {
  stream: BaseStream;
  firstDigit = -1;
  constructor(str: BaseStream, maybeLength: number | null | undefined) {
    super(maybeLength ? maybeLength * 0.5 : maybeLength);
    this.stream = str;
    this.dict = str.dict;
  }
  readBlock() {
    const bytes = this.stream.getBytes(8000);
    if (!bytes.length) {
      this.eof = true;
      return;
    }
    const maxDecodeLength = (bytes.length + 1) >> 1;
    const buffer = this.ensureBuffer(this.bufferLength + maxDecodeLength);
    let bufferLength = this.bufferLength;
    let firstDigit = this.firstDigit;
    for (let k = 0; k < bytes.length; k++) {
      const ch = bytes[k];
      let digit: number;
      if (ch >= 0x30 && ch <= 0x39) digit = ch & 0x0f;
      else if ((ch >= 0x41 && ch <= 0x46) || (ch >= 0x61 && ch <= 0x66)) digit = (ch & 0x0f) + 9;
      else if (ch === 0x3e) {
        this.eof = true;
        break;
      } else continue;
      if (firstDigit < 0) firstDigit = digit;
      else {
        buffer[bufferLength++] = (firstDigit << 4) | digit;
        firstDigit = -1;
      }
    }
    if (firstDigit >= 0 && this.eof) {
      buffer[bufferLength++] = firstDigit << 4;
      firstDigit = -1;
    }
    this.firstDigit = firstDigit;
    this.bufferLength = bufferLength;
  }
}

class RunLengthStream extends DecodeStream {
  stream: BaseStream;
  constructor(str: BaseStream, maybeLength: number | null | undefined) {
    super(maybeLength);
    this.stream = str;
    this.dict = str.dict;
  }
  readBlock() {
    const repeatHeader = this.stream.getBytes(2);
    if (repeatHeader.length < 2 || repeatHeader[0] === 128) {
      this.eof = true;
      return;
    }
    let buffer: Uint8Array;
    let bufferLength = this.bufferLength;
    let n = repeatHeader[0];
    if (n < 128) {
      buffer = this.ensureBuffer(bufferLength + n + 1);
      buffer[bufferLength++] = repeatHeader[1];
      if (n > 0) {
        const source = this.stream.getBytes(n);
        buffer.set(source, bufferLength);
        bufferLength += n;
      }
    } else {
      n = 257 - n;
      buffer = this.ensureBuffer(bufferLength + n + 1);
      buffer.fill(repeatHeader[1], bufferLength, bufferLength + n);
      bufferLength += n;
    }
    this.bufferLength = bufferLength;
  }
}

/**
 * An image filter's stream (DCT, JPEG 2000, JBIG2, CCITT) or Brotli's: pdf.js decodes them with decoders v3 doesn't
 * carry. As content, an image stream draws nothing (pdf.js leaves it out of a page's content); read in any other way,
 * it fails here, and v3 records the document as one it can't reproduce exactly.
 */
export class OpaqueStream extends DecodeStream {
  constructor(readonly filter: string, readonly inner: BaseStream, readonly image: boolean) {
    super(0);
    this.dict = inner.dict;
  }
  get isImageStream() {
    return this.image;
  }
  readBlock(): void {
    throw new PdfjsError("Unexpected", `a ${this.filter} stream v3 doesn't decode`);
  }
}

/** A stream decrypted as pdf.js's DecryptStream decrypts it, 512 bytes at a time. */
export class DecryptStream extends DecodeStream {
  stream: BaseStream;
  nextChunk: Uint8Array | null = null;
  constructor(str: BaseStream, maybeLength: number | null | undefined, readonly decrypt: (data: Uint8Array, finalize: boolean) => Uint8Array) {
    super(maybeLength);
    this.stream = str;
    this.dict = str.dict;
  }
  readBlock() {
    let chunk = this.nextChunk ?? this.stream.getBytes(512);
    if (!chunk.length) {
      this.eof = true;
      return;
    }
    this.nextChunk = this.stream.getBytes(512);
    const hasMoreData = this.nextChunk.length > 0;
    chunk = this.decrypt(chunk, !hasMoreData);
    const bufferLength = this.bufferLength;
    const newLength = bufferLength + chunk.length;
    const buffer = this.ensureBuffer(newLength);
    buffer.set(chunk, bufferLength);
    this.bufferLength = newLength;
  }
}

/** What a filter needs from the place its stream is read: its dictionary's values, and the cipher if a Crypt filter needs one. */
export interface FilterSource {
  fetchIfRef(v: PValue): PValue;
  cipher: CipherTransform | null;
}

/** Parser.filter: the stream through its filters, as pdf.js chains them. */
export function applyFilters(src: FilterSource, stream: BaseStream, dict: Dict, length: number | null): BaseStream {
  let filter = dict.get("F", "Filter");
  let params = dict.get("DP", "DecodeParms");
  if (filter instanceof Name) return makeFilter(src, stream, filter.name, length, params);
  let maybeLength: number | null = length;
  if (Array.isArray(filter)) {
    const filterArray = filter;
    const paramsArray = params;
    for (let i = 0; i < filterArray.length; ++i) {
      filter = src.fetchIfRef(filterArray[i]);
      if (!(filter instanceof Name)) throw formatError(`Bad filter name "${jsString(filter)}"`);
      params = null;
      if (Array.isArray(paramsArray) && i in paramsArray) params = src.fetchIfRef(paramsArray[i]);
      stream = makeFilter(src, stream, filter.name, maybeLength, params);
      maybeLength = null;
    }
  }
  return stream;
}

/** Parser.makeFilter: an unknown filter passes the bytes through; one that can't be set up gives an empty stream. */
export function makeFilter(src: FilterSource, stream: BaseStream, name: string, maybeLength: number | null, params: PValue): BaseStream {
  if (maybeLength === 0) return new NullStream();
  try {
    switch (name) {
      case "Fl":
      case "FlateDecode":
        if (params) return predictorStream(new FlateStream(stream, maybeLength), maybeLength, params);
        return new FlateStream(stream, maybeLength);
      case "LZW":
      case "LZWDecode": {
        let earlyChange: PValue = 1;
        if (params) {
          if (params instanceof Dict && params.has("EarlyChange")) earlyChange = params.get("EarlyChange");
          else if (!(params instanceof Dict) && hasEarlyChange(params)) earlyChange = undefined;
          return predictorStream(new LZWStream(stream, maybeLength, jsNumber(earlyChange)), maybeLength, params);
        }
        return new LZWStream(stream, maybeLength, 1);
      }
      case "DCT":
      case "DCTDecode":
      case "JPX":
      case "JPXDecode":
      case "CCF":
      case "CCITTFaxDecode":
      case "JBIG2Decode":
        return new OpaqueStream(name, stream, true);
      case "BrotliDecode":
        return new OpaqueStream(name, stream, false);
      case "A85":
      case "ASCII85Decode":
        return new Ascii85Stream(stream, maybeLength);
      case "AHx":
      case "ASCIIHexDecode":
        return new AsciiHexStream(stream, maybeLength);
      case "RL":
      case "RunLengthDecode":
        return new RunLengthStream(stream, maybeLength);
      case "Crypt": {
        if (!src.cipher) return stream;
        const param = params instanceof Dict ? params.get("Name") : null;
        const cryptName = param instanceof Name ? param : new Name("Identity");
        return src.cipher.createStream(stream, maybeLength, cryptName);
      }
    }
    return stream;
  } catch (ex) {
    if (isEngineError(ex)) throw ex;
    return new NullStream();
  }
}
/** `params.has("EarlyChange")` on a value that isn't a dictionary throws in pdf.js (it has no `has`), unless it's an object with one. */
function hasEarlyChange(params: PValue): boolean {
  throw new TypeError(`params.has is not a function (${jsString(params)})`);
}

// ---- The lexer and parser (parser.js) ---------------------------------------------------------------------------

// prettier-ignore
const specialChars = [1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 2, 0, 0, 2, 2, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const special = (ch: number) => (ch >= 0 && ch < 256 ? specialChars[ch] : undefined);
function toHexDigit(ch: number) {
  if (ch >= 0x30 && ch <= 0x39) return ch & 0x0f;
  if ((ch >= 0x41 && ch <= 0x46) || (ch >= 0x61 && ch <= 0x66)) return (ch & 0x0f) + 9;
  return -1;
}

/** A number as pdf.js read it, with the digits it read them from, so it can be written back to read the same. */
export class NumberToken {
  constructor(readonly value: number, readonly sign: number, readonly digits: string, readonly point: number) {}
}

export type KnownCommands = Record<string, unknown>;

export class Lexer {
  stream: BaseStream;
  currentChar = -1;
  knownCommands: KnownCommands | null;
  beginInlineImagePos = -1;
  /** When set (content), numbers are also kept as NumberToken via lastNumber. */
  lastNumber: NumberToken | null = null;
  constructor(stream: BaseStream, knownCommands: KnownCommands | null = null) {
    this.stream = stream;
    this.nextChar();
    this.knownCommands = knownCommands;
  }
  nextChar() {
    return (this.currentChar = this.stream.getByte());
  }
  peekChar() {
    return this.stream.peekByte();
  }
  getNumber(): number {
    let ch = this.currentChar;
    let divideBy = 0;
    let sign = 1;
    if (ch === 0x2d) {
      sign = -1;
      ch = this.nextChar();
      if (ch === 0x2d) ch = this.nextChar();
    } else if (ch === 0x2b) ch = this.nextChar();
    if (ch === 0x0a || ch === 0x0d) {
      do ch = this.nextChar();
      while (ch === 0x0a || ch === 0x0d);
    }
    let point = -1;
    let digits = "";
    if (ch === 0x2e) {
      divideBy = 10;
      point = 0;
      ch = this.nextChar();
    }
    if (ch < 0x30 || ch > 0x39) {
      if (isWhiteSpace(ch) || ch === 0x28 || ch === 0x3c || ch === -1) {
        this.lastNumber = new NumberToken(0, 1, "0", -1);
        return 0;
      }
      throw formatError(`Invalid number: ${String.fromCharCode(ch)} (charCode ${ch})`);
    }
    let baseValue = ch - 0x30;
    digits += String.fromCharCode(ch);
    while ((ch = this.nextChar()) >= 0) {
      if (ch >= 0x30 && ch <= 0x39) {
        const currentDigit = ch - 0x30;
        if (divideBy !== 0) divideBy *= 10;
        baseValue = baseValue * 10 + currentDigit;
        digits += String.fromCharCode(ch);
      } else if (ch === 0x2e) {
        if (divideBy === 0) {
          divideBy = 1;
          point = digits.length;
        } else break;
      } else if (ch === 0x2d) {
        // A minus sign in the middle: pdf.js warns and goes on.
      } else break;
    }
    if (divideBy !== 0) baseValue /= divideBy;
    const value = sign * baseValue;
    this.lastNumber = new NumberToken(value, sign, digits, point);
    return value;
  }
  getString(): string {
    let numParen = 1;
    let done = false;
    const strBuf: string[] = [];
    let ch = this.nextChar();
    for (;;) {
      let charBuffered = false;
      switch (ch | 0) {
        case -1:
          done = true;
          break;
        case 0x28:
          ++numParen;
          strBuf.push("(");
          break;
        case 0x29:
          if (--numParen === 0) {
            this.nextChar();
            done = true;
          } else strBuf.push(")");
          break;
        case 0x5c:
          ch = this.nextChar();
          switch (ch) {
            case -1:
              done = true;
              break;
            case 0x6e:
              strBuf.push("\n");
              break;
            case 0x72:
              strBuf.push("\r");
              break;
            case 0x74:
              strBuf.push("\t");
              break;
            case 0x62:
              strBuf.push("\b");
              break;
            case 0x66:
              strBuf.push("\f");
              break;
            case 0x5c:
            case 0x28:
            case 0x29:
              strBuf.push(String.fromCharCode(ch));
              break;
            case 0x30:
            case 0x31:
            case 0x32:
            case 0x33:
            case 0x34:
            case 0x35:
            case 0x36:
            case 0x37: {
              let x = ch & 0x0f;
              ch = this.nextChar();
              charBuffered = true;
              if (ch >= 0x30 && ch <= 0x37) {
                x = (x << 3) + (ch & 0x0f);
                ch = this.nextChar();
                if (ch >= 0x30 && ch <= 0x37) {
                  charBuffered = false;
                  x = (x << 3) + (ch & 0x0f);
                }
              }
              strBuf.push(String.fromCharCode(x));
              break;
            }
            case 0x0d:
              if (this.peekChar() === 0x0a) this.nextChar();
              break;
            case 0x0a:
              break;
            default:
              strBuf.push(String.fromCharCode(ch));
              break;
          }
          break;
        default:
          strBuf.push(String.fromCharCode(ch));
          break;
      }
      if (done) break;
      if (!charBuffered) ch = this.nextChar();
    }
    return strBuf.join("");
  }
  getName(): Name {
    let ch: number;
    let previousCh: number;
    const strBuf: string[] = [];
    while ((ch = this.nextChar()) >= 0 && !special(ch)) {
      if (ch === 0x23) {
        ch = this.nextChar();
        if (special(ch)) {
          strBuf.push("#");
          break;
        }
        const x = toHexDigit(ch);
        if (x !== -1) {
          previousCh = ch;
          ch = this.nextChar();
          const x2 = toHexDigit(ch);
          if (x2 === -1) {
            strBuf.push("#", String.fromCharCode(previousCh));
            if (special(ch)) break;
            strBuf.push(String.fromCharCode(ch));
            continue;
          }
          strBuf.push(String.fromCharCode((x << 4) | x2));
        } else strBuf.push("#", String.fromCharCode(ch));
      } else strBuf.push(String.fromCharCode(ch));
    }
    return new Name(strBuf.join(""));
  }
  getHexString(): string {
    const strBuf: string[] = [];
    let ch = this.currentChar;
    let firstDigit = -1;
    let digit: number;
    for (;;) {
      if (ch < 0) break;
      else if (ch === 0x3e) {
        this.nextChar();
        break;
      } else if (special(ch) === 1) {
        ch = this.nextChar();
        continue;
      } else {
        digit = toHexDigit(ch);
        if (digit === -1) {
          // pdf.js warns and skips it.
        } else if (firstDigit === -1) firstDigit = digit;
        else {
          strBuf.push(String.fromCharCode((firstDigit << 4) | digit));
          firstDigit = -1;
        }
        ch = this.nextChar();
      }
    }
    if (firstDigit !== -1) strBuf.push(String.fromCharCode(firstDigit << 4));
    return strBuf.join("");
  }
  getObj(): PValue {
    let comment = false;
    let ch = this.currentChar;
    for (;;) {
      if (ch < 0) return EOF;
      if (comment) {
        if (ch === 0x0a || ch === 0x0d) comment = false;
      } else if (ch === 0x25) comment = true;
      else if (special(ch) !== 1) break;
      ch = this.nextChar();
    }
    switch (ch | 0) {
      case 0x30:
      case 0x31:
      case 0x32:
      case 0x33:
      case 0x34:
      case 0x35:
      case 0x36:
      case 0x37:
      case 0x38:
      case 0x39:
      case 0x2b:
      case 0x2d:
      case 0x2e:
        return this.getNumber();
      case 0x28:
        return this.getString();
      case 0x2f:
        return this.getName();
      case 0x5b:
        this.nextChar();
        return new Cmd("[");
      case 0x5d:
        this.nextChar();
        return new Cmd("]");
      case 0x3c:
        ch = this.nextChar();
        if (ch === 0x3c) {
          this.nextChar();
          return new Cmd("<<");
        }
        return this.getHexString();
      case 0x3e:
        ch = this.nextChar();
        if (ch === 0x3e) {
          this.nextChar();
          return new Cmd(">>");
        }
        return new Cmd(">");
      case 0x7b:
        this.nextChar();
        return new Cmd("{");
      case 0x7d:
        this.nextChar();
        return new Cmd("}");
      case 0x29:
        this.nextChar();
        throw formatError(`Illegal character: ${ch}`);
    }
    let str = String.fromCharCode(ch);
    if (ch < 0x20 || ch > 0x7f) {
      const nextCh = this.peekChar();
      if (nextCh >= 0x20 && nextCh <= 0x7f) {
        this.nextChar();
        return new Cmd(str);
      }
    }
    const knownCommands = this.knownCommands;
    let knownCommandFound = knownCommands !== null && knownCommands[str] !== undefined;
    while ((ch = this.nextChar()) >= 0 && !special(ch)) {
      const possibleCommand = str + String.fromCharCode(ch);
      if (knownCommandFound && knownCommands![possibleCommand] === undefined) break;
      if (str.length === 128) throw formatError(`Command token too long: ${str.length}`);
      str = possibleCommand;
      knownCommandFound = knownCommands !== null && knownCommands[str] !== undefined;
    }
    if (str === "true") return true;
    if (str === "false") return false;
    if (str === "null") return null;
    if (str === "BI") this.beginInlineImagePos = this.stream.pos;
    return new Cmd(str);
  }
  skipToNextLine() {
    let ch = this.currentChar;
    while (ch >= 0) {
      if (ch === 0x0d) {
        ch = this.nextChar();
        if (ch === 0x0a) this.nextChar();
        break;
      } else if (ch === 0x0a) {
        this.nextChar();
        break;
      }
      ch = this.nextChar();
    }
  }
}

/** A stream as pdf.js's parser makes it: its dictionary, its bytes (decrypted when the document is), and its filters. */
export class PStream {
  constructor(readonly dict: Dict, readonly raw: Uint8Array, readonly cipher: CipherTransform | null, readonly cryptFirst: boolean) {}
}

export class Parser {
  lexer: Lexer;
  xref: XRef | null;
  allowStreams: boolean;
  recoveryMode: boolean;
  /** The nesting of arrays and dictionaries pdf.js reads with recursion; past this v3 stops, as pdf.js does when its stack runs out. */
  static MAX_NESTING = 2900;
  depth = 0;
  buf1: PValue = undefined;
  buf2: PValue = undefined;
  /** Content streams read with a lexer keyed to pdf.js's operators keep inline images as InlineImage. */
  constructor(o: { lexer: Lexer; xref: XRef | null; allowStreams?: boolean; recoveryMode?: boolean }) {
    this.lexer = o.lexer;
    this.xref = o.xref;
    this.allowStreams = o.allowStreams ?? false;
    this.recoveryMode = o.recoveryMode ?? false;
    this.refill();
  }
  refill() {
    this.buf1 = this.lexer.getObj();
    this.buf2 = this.lexer.getObj();
  }
  shift() {
    if (this.buf2 instanceof Cmd && this.buf2.cmd === "ID") {
      this.buf1 = this.buf2;
      this.buf2 = null;
    } else {
      this.buf1 = this.buf2;
      this.buf2 = this.lexer.getObj();
    }
  }
  tryShift() {
    try {
      this.shift();
      return true;
    } catch (e) {
      if (isEngineError(e)) throw e;
      return false;
    }
  }
  /** Whether a token is an integer (a ref's number or generation), and its value. */
  intOf(v: PValue): number | null {
    return isInt(v) ? v : null;
  }
  /**
   * Parser.getObj, without recursion: arrays and dictionaries are read with an explicit stack, in exactly the order
   * pdf.js's recursive reading takes, so nesting of any depth reads the same in every engine. pdf.js itself runs out of
   * stack at some depth, which differs between engines; v3 stops where Chromium's pdf.js does (MAX_NESTING).
   */
  getObj(cipherTransform: CipherTransform | null = null): PValue {
    type Frame = { array: PValue[] } | { dict: Dict; key: string | null };
    const stack: Frame[] = [];
    let value: PValue;
    // The loop condition of the innermost open container, run when it opens and after each value it takes: returns
    // the finished container (to give to its parent), or undefined when it needs another value read.
    const step = (): { done: PValue } | null => {
      const top = stack[stack.length - 1];
      if ("array" in top) {
        if (!isCmd(this.buf1, "]") && this.buf1 !== EOF) return null;
        if (this.buf1 === EOF) {
          if (this.recoveryMode) return { done: top.array };
          throw new PdfjsError("ParserEOF", "End of file inside array.");
        }
        this.shift();
        return { done: top.array };
      }
      while (!isCmd(this.buf1, ">>") && this.buf1 !== EOF) {
        if (!(this.buf1 instanceof Name)) {
          this.shift();
          continue;
        }
        const key = this.buf1.name;
        this.shift();
        if ((this.buf1 as PValue) === EOF) break;
        top.key = key;
        return null;
      }
      if (this.buf1 === EOF) {
        if (this.recoveryMode) return { done: top.dict };
        throw new PdfjsError("ParserEOF", "End of file inside dictionary.");
      }
      if (isCmd(this.buf2, "stream")) return { done: this.allowStreams ? this.makeStream(top.dict, cipherTransform) : top.dict };
      this.shift();
      return { done: top.dict };
    };
    for (;;) {
      const buf1 = this.buf1;
      this.shift();
      let opened = false;
      if (buf1 instanceof Cmd) {
        if (buf1.cmd === "BI") value = this.makeInlineImage(cipherTransform);
        else if (buf1.cmd === "[" || buf1.cmd === "<<") {
          if (stack.length >= Parser.MAX_NESTING) throw new PdfjsError("Format", "arrays and dictionaries nested deeper than pdf.js reads");
          stack.push(buf1.cmd === "[" ? { array: [] } : { dict: new Dict(this.xref), key: null });
          opened = true;
        } else value = buf1;
      } else {
        const n = this.intOf(buf1);
        if (n !== null) {
          const g = this.intOf(this.buf1);
          if (g !== null && isCmd(this.buf2, "R")) {
            value = new Ref(n, g);
            this.shift();
            this.shift();
          } else value = buf1;
        } else if (typeof buf1 === "string") value = cipherTransform ? cipherTransform.decryptString(buf1) : buf1;
        else value = buf1;
      }
      // Give the value (or the container just opened) to the containers waiting for it, closing those it completes.
      for (;;) {
        if (!opened) {
          if (!stack.length) return value!;
          const top = stack[stack.length - 1];
          if ("array" in top) top.array.push(value!);
          else top.dict.set(top.key!, value!);
        }
        opened = false;
        const r = step();
        if (r === null) break;
        stack.pop();
        value = r.done;
      }
    }
  }
  // Inline images in content are handled by the content reader (content-v3.ts); here pdf.js's parser reads them only
  // where an object holds one, which it reads the same way.
  makeInlineImage(cipherTransform: CipherTransform | null): PValue {
    return readInlineImage(this, cipherTransform);
  }
  findStreamLength(startPos: number): number {
    const stream = this.lexer.stream;
    stream.pos = startPos;
    const SCAN_BLOCK_LENGTH = 2048;
    const signatureLength = 9;
    const END_SIGNATURE = [0x65, 0x6e, 0x64];
    const endLength = 3;
    const PARTIAL_SIGNATURE = [[0x73, 0x74, 0x72, 0x65, 0x61, 0x6d], [0x73, 0x74, 0x65, 0x61, 0x6d], [0x73, 0x74, 0x72, 0x65, 0x61]];
    const normalLength = signatureLength - endLength;
    const end = (stream as Stream).end;
    while (stream.pos < end) {
      const scanBytes = stream.peekBytes(SCAN_BLOCK_LENGTH);
      const scanLength = scanBytes.length - signatureLength;
      if (scanLength <= 0) break;
      let pos = 0;
      while (pos < scanLength) {
        let j = 0;
        while (j < endLength && scanBytes[pos + j] === END_SIGNATURE[j]) j++;
        if (j >= endLength) {
          let found = false;
          for (const part of PARTIAL_SIGNATURE) {
            const partLen = part.length;
            let k = 0;
            while (k < partLen && scanBytes[pos + j + k] === part[k]) k++;
            if (k >= normalLength) {
              found = true;
              break;
            }
            if (k >= partLen) {
              const lastByte = scanBytes[pos + j + k];
              if (isWhiteSpace(lastByte)) found = true;
              break;
            }
          }
          if (found) {
            stream.pos += pos;
            return stream.pos - startPos;
          }
        }
        pos++;
      }
      stream.pos += scanLength;
    }
    return -1;
  }
  makeStream(dict: Dict, cipherTransform: CipherTransform | null): PStream {
    const lexer = this.lexer;
    const stream = lexer.stream;
    lexer.skipToNextLine();
    const startPos = stream.pos - 1;
    let length = dict.get("Length");
    if (!isInt(length)) length = 0;
    stream.pos = startPos + (length as number);
    lexer.nextChar();
    if (this.tryShift() && isCmd(this.buf2, "endstream")) {
      this.shift();
    } else {
      length = this.findStreamLength(startPos);
      if (length < 0) throw formatError("Missing endstream command.");
      lexer.nextChar();
      this.shift();
      this.shift();
    }
    this.shift();
    const sub = stream.makeSubStream(startPos, length as number, dict);
    const filter = dict.get("F", "Filter");
    const hasCrypt = this.hasCryptFilter(filter);
    // The stream's bytes, decrypted as pdf.js decrypts them before its filters (a Crypt filter decrypts in its place).
    let raw = sub.getBytes();
    if (cipherTransform && !hasCrypt) raw = cipherTransform.createStream(new Stream(raw, 0, raw.length, dict), length as number, null).getBytes();
    const cryptFirst = hasCrypt && firstFilterIsCrypt(filter, (v) => this.fetchIfRef(v));
    return new PStream(dict, raw, cipherTransform, cryptFirst);
  }
  fetchIfRef(v: PValue): PValue {
    return this.xref ? this.xref.fetchIfRef(v) : v;
  }
  hasCryptFilter(filter: PValue): boolean {
    return Array.isArray(filter) ? filter.some((f) => isName(this.fetchIfRef(f), "Crypt")) : isName(filter, "Crypt");
  }
}
function firstFilterIsCrypt(filter: PValue, fetch: (v: PValue) => PValue): boolean {
  if (Array.isArray(filter)) return isName(fetch(filter[0]), "Crypt");
  return isName(filter, "Crypt");
}

/** An inline image as pdf.js's parser reads it (makeInlineImage): its dictionary and the bytes of its data, before its filters. */
export class InlineImage {
  constructor(readonly dict: Dict, readonly data: Uint8Array, readonly cipher: CipherTransform | null) {}
}

function findDefaultInlineStreamEnd(parser: Parser, stream: BaseStream): number {
  const E = 0x45, I = 0x49, SPACE = 0x20, LF = 0xa, CR = 0xd, NUL = 0x0;
  const knownCommands = parser.lexer.knownCommands;
  const startPos = stream.pos;
  const n = 15;
  let state = 0;
  let ch = 0;
  let maybeEIPos = 0;
  while ((ch = stream.getByte()) !== -1) {
    if (state === 0) state = ch === E ? 1 : 0;
    else if (state === 1) state = ch === I ? 2 : 0;
    else {
      if (ch === SPACE || ch === LF || ch === CR) {
        maybeEIPos = stream.pos;
        const followingBytes = stream.peekBytes(n);
        const ii = followingBytes.length;
        if (ii === 0) break;
        for (let i = 0; i < ii; i++) {
          ch = followingBytes[i];
          if (ch === NUL && followingBytes[i + 1] !== NUL) continue;
          if (ch !== LF && ch !== CR && (ch < SPACE || ch > 0x7f)) {
            state = 0;
            break;
          }
        }
        if (state !== 2) continue;
        if (!knownCommands) continue;
        const tmpLexer = new Lexer(new Stream(stream.peekBytes(5 * n)), knownCommands);
        let numArgs = 0;
        for (;;) {
          const nextObj = tmpLexer.getObj();
          if (nextObj === EOF) {
            state = 0;
            break;
          }
          if (nextObj instanceof Cmd) {
            const knownCommand = knownCommands[nextObj.cmd] as { numArgs: number; variableArgs: boolean } | null | undefined;
            if (!knownCommand) {
              state = 0;
              break;
            } else if (knownCommand.variableArgs ? numArgs <= knownCommand.numArgs : numArgs === knownCommand.numArgs) break;
            numArgs = 0;
            continue;
          }
          numArgs++;
        }
        if (state === 2) break;
      } else state = 0;
    }
  }
  if (ch === -1) {
    if (maybeEIPos) stream.skip(-(stream.pos - maybeEIPos));
  }
  let endOffset = 4;
  stream.skip(-endOffset);
  ch = stream.peekByte();
  stream.skip(endOffset);
  if (!isWhiteSpace(ch)) endOffset--;
  return stream.pos - endOffset - startPos;
}
function inlineStreamSkipEI(stream: BaseStream) {
  let state = 0;
  let ch: number;
  while ((ch = stream.getByte()) !== -1) {
    if (state === 0) state = ch === 0x45 ? 1 : 0;
    else if (state === 1) state = ch === 0x49 ? 2 : 0;
    else if (state === 2) break;
  }
}
function findDCTDecodeInlineStreamEnd(parser: Parser, stream: BaseStream): number {
  const startPos = stream.pos;
  let foundEOI = false;
  let b: number;
  let markerLength: number;
  while ((b = stream.getByte()) !== -1) {
    if (b !== 0xff) continue;
    switch (stream.getByte()) {
      case 0x00:
        break;
      case 0xff:
        stream.skip(-1);
        break;
      case 0xd9:
        foundEOI = true;
        break;
      case 0xc0: case 0xc1: case 0xc2: case 0xc3: case 0xc5: case 0xc6: case 0xc7: case 0xc9: case 0xca: case 0xcb:
      case 0xcd: case 0xce: case 0xcf: case 0xc4: case 0xcc: case 0xda: case 0xdb: case 0xdc: case 0xdd: case 0xde:
      case 0xdf: case 0xe0: case 0xe1: case 0xe2: case 0xe3: case 0xe4: case 0xe5: case 0xe6: case 0xe7: case 0xe8:
      case 0xe9: case 0xea: case 0xeb: case 0xec: case 0xed: case 0xee: case 0xef: case 0xfe:
        markerLength = stream.getUint16();
        if (markerLength > 2) stream.skip(markerLength - 2);
        else stream.skip(-2);
        break;
    }
    if (foundEOI) break;
  }
  const length = stream.pos - startPos;
  if (b === -1) {
    stream.skip(-length);
    return findDefaultInlineStreamEnd(parser, stream);
  }
  inlineStreamSkipEI(stream);
  return length;
}
function findASCII85DecodeInlineStreamEnd(parser: Parser, stream: BaseStream): number {
  const startPos = stream.pos;
  let ch: number;
  while ((ch = stream.getByte()) !== -1) {
    if (ch === 0x7e) {
      const tildePos = stream.pos;
      ch = stream.peekByte();
      while (isWhiteSpace(ch)) {
        stream.skip();
        ch = stream.peekByte();
      }
      if (ch === 0x3e) {
        stream.skip();
        break;
      }
      if (stream.pos > tildePos) {
        const maybeEI = stream.peekBytes(2);
        if (maybeEI[0] === 0x45 && maybeEI[1] === 0x49) break;
      }
    }
  }
  const length = stream.pos - startPos;
  if (ch === -1) {
    stream.skip(-length);
    return findDefaultInlineStreamEnd(parser, stream);
  }
  inlineStreamSkipEI(stream);
  return length;
}
function findASCIIHexDecodeInlineStreamEnd(parser: Parser, stream: BaseStream): number {
  const startPos = stream.pos;
  let ch: number;
  while ((ch = stream.getByte()) !== -1) if (ch === 0x3e) break;
  const length = stream.pos - startPos;
  if (ch === -1) {
    stream.skip(-length);
    return findDefaultInlineStreamEnd(parser, stream);
  }
  inlineStreamSkipEI(stream);
  return length;
}

/** Parser.makeInlineImage, keeping the image's dictionary and data bytes (its cache, a speed-up, changes nothing drawn). */
function readInlineImage(parser: Parser, cipherTransform: CipherTransform | null): InlineImage {
  const lexer = parser.lexer;
  const stream = lexer.stream;
  const dict = new Dict(parser.xref);
  while (!isCmd(parser.buf1, "ID") && parser.buf1 !== EOF) {
    if (!(parser.buf1 instanceof Name)) throw formatError("Dictionary key must be a name object");
    const key = parser.buf1.name;
    parser.shift();
    if ((parser.buf1 as PValue) === EOF) break;
    dict.set(key, parser.getObj(cipherTransform));
  }
  const filter = dict.get("F", "Filter");
  let filterName: string | undefined;
  if (filter instanceof Name) filterName = filter.name;
  else if (Array.isArray(filter)) {
    const filterZero = parser.fetchIfRef(filter[0]);
    if (filterZero instanceof Name) filterName = filterZero.name;
  }
  const startPos = stream.pos;
  let length: number;
  switch (filterName) {
    case "DCT":
    case "DCTDecode":
      length = findDCTDecodeInlineStreamEnd(parser, stream);
      break;
    case "A85":
    case "ASCII85Decode":
      length = findASCII85DecodeInlineStreamEnd(parser, stream);
      break;
    case "AHx":
    case "ASCIIHexDecode":
      length = findASCIIHexDecodeInlineStreamEnd(parser, stream);
      break;
    default:
      length = findDefaultInlineStreamEnd(parser, stream);
  }
  const image = stream.makeSubStream(startPos, length, dict);
  const data = image.getBytes();
  parser.buf2 = new Cmd("EI");
  parser.shift();
  return new InlineImage(dict, data, cipherTransform && !parser.hasCryptFilter(filter) ? cipherTransform : null);
}

// ---- Decryption (crypto.js: CipherTransform and CipherTransformFactory) -----------------------------------------

type CipherFn = (data: Uint8Array, finalize: boolean) => Uint8Array;
/** A cipher instance (pdf.js makes a new one per string or stream): RC4 keeps its state across a stream's blocks. */
type CipherMaker = () => CipherFn;

export class CipherTransform {
  private cache = new Map<string, CipherMaker>();
  embeddedFilterName: PValue = null;
  constructor(private resolveCipher: (filterName: PValue) => CipherMaker, readonly stringFilterName: PValue = null, readonly streamFilterName: PValue = null) {}
  private getCipher(filterName: PValue): CipherMaker {
    const key = filterName instanceof Name ? filterName.name : "__default__";
    let c = this.cache.get(key);
    if (!c) this.cache.set(key, (c = this.resolveCipher(filterName)));
    return c;
  }
  createStream(stream: BaseStream, length: number | null | undefined, cryptFilterName: PValue): DecryptStream {
    const dict = stream.dict;
    const isEmbedded = dict instanceof Dict && isName(dict.get("Type"), "EmbeddedFile");
    const defaultFilterName = this.embeddedFilterName && isEmbedded ? this.embeddedFilterName : this.streamFilterName;
    const cipher = this.getCipher(cryptFilterName || defaultFilterName)();
    return new DecryptStream(stream, length, cipher);
  }
  decryptString(s: string): string {
    const cipher = this.getCipher(this.stringFilterName)();
    return bytesToString(cipher(stringToBytes(s), true));
  }
}

const nullCipher: CipherMaker = () => (data) => data;
const rc4Cipher = (key: Uint8Array): CipherMaker => () => {
  // pdf.js's ARCFourCipher keeps its state across the blocks of one stream.
  const state = rc4State(key);
  return (data) => rc4Run(state, data);
};
const aesCipher = (key: Uint8Array, size: 16 | 32): CipherMaker => () => aesStreamState(key, size);

/** pdf.js's ARCFourCipher: the key schedule, then a byte stream that continues across calls. */
function rc4State(key: Uint8Array) {
  const s = new Uint8Array(256);
  for (let i = 0; i < 256; ++i) s[i] = i;
  for (let i = 0, j = 0; i < 256; ++i) {
    const tmp = s[i];
    j = (j + tmp + key[i % key.length]) & 0xff;
    s[i] = s[j];
    s[j] = tmp;
  }
  return { s, a: 0, b: 0 };
}
function rc4Run(st: { s: Uint8Array; a: number; b: number }, data: Uint8Array): Uint8Array {
  let a = st.a, b = st.b;
  const s = st.s;
  const output = new Uint8Array(data.length);
  for (let i = 0; i < data.length; ++i) {
    a = (a + 1) & 0xff;
    const tmp = s[a];
    b = (b + tmp) & 0xff;
    const tmp2 = s[b];
    s[a] = tmp2;
    s[b] = tmp;
    output[i] = data[i] ^ s[(tmp + tmp2) & 0xff];
  }
  st.a = a;
  st.b = b;
  return output;
}
/** pdf.js's AESBaseCipher.decryptBlock across a stream's 512-byte pieces (the IV, then whole blocks, padding removed at the end). */
function aesStreamState(key: Uint8Array, size: 16 | 32): CipherFn {
  let buffer = new Uint8Array(0);
  let iv: Uint8Array | null = null;
  return (data, finalize) => {
    // Bytes left over from the last call come first.
    const all = new Uint8Array(buffer.length + data.length);
    all.set(buffer);
    all.set(data, buffer.length);
    let p = all;
    if (!iv) {
      if (p.length < 16) {
        buffer = p;
        return new Uint8Array(0);
      }
      iv = p.slice(0, 16);
      p = p.subarray(16);
    }
    const blocks = Math.floor(p.length / 16);
    buffer = p.slice(blocks * 16);
    if (!blocks) return new Uint8Array(0);
    const res = aesCbcDecryptBlocks(key, size, p.subarray(0, blocks * 16), iv);
    iv = p.slice(blocks * 16 - 16, blocks * 16);
    let len = res.length;
    if (finalize) {
      let pad = res[len - 1];
      if (pad <= 16) {
        for (let i = 15; i >= 16 - pad; i--) {
          if (res[len - 16 + i] !== pad) {
            pad = 0;
            break;
          }
        }
        len -= pad;
      }
    }
    return res.subarray(0, len);
  };
}

/** A string decrypted with AES as pdf.js's CipherTransform.decryptString decrypts one (the IV first, padding removed). */
export const aesDecryptString = (key: Uint8Array, size: 16 | 32, data: Uint8Array) => aesStreamState(key, size)(data, true);

const PASSWORD_PAD = Uint8Array.from([0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41, 0x64, 0x00, 0x4e, 0x56, 0xff, 0xfa, 0x01, 0x08, 0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80, 0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a]);

export class CipherTransformFactory {
  algorithm: number;
  cf: PValue;
  stmf: PValue;
  strf: PValue;
  eff: PValue;
  encryptionKey: Uint8Array | null = null;
  constructor(dict: Dict, fileId: PValue) {
    const filter = dict.get("Filter");
    if (!isName(filter, "Standard")) throw formatError("unknown encryption method");
    const algorithm = dict.get("V");
    if (!isInt(algorithm) || (algorithm !== 1 && algorithm !== 2 && algorithm !== 4 && algorithm !== 5)) throw formatError("unsupported encryption algorithm");
    this.algorithm = algorithm;
    let keyLength: PValue = dict.get("Length");
    if (!keyLength) {
      if (algorithm <= 3) keyLength = 40;
      else {
        const cfDict = dict.get("CF");
        const streamCryptoName = dict.get("StmF");
        if (cfDict instanceof Dict && streamCryptoName instanceof Name) {
          cfDict.suppressEncryption = true;
          const handlerDict = cfDict.get(streamCryptoName.name);
          const l = optionalGet(handlerDict, "Length");
          keyLength = (l as never) || 128;
          if (jsNumber(keyLength) < 40) keyLength = jsNumber(keyLength) << 3;
        }
      }
    }
    if (!isInt(keyLength) || keyLength < 40 || keyLength % 8 !== 0) throw formatError("invalid key length");
    let cf: PValue = null;
    let stmf: PValue = new Name("Identity");
    let strf: PValue = new Name("Identity");
    let eff: PValue = stmf;
    if (algorithm >= 4) {
      cf = dict.get("CF");
      if (cf instanceof Dict) cf.suppressEncryption = true;
      stmf = (dict.get("StmF") as never) || new Name("Identity");
      strf = (dict.get("StrF") as never) || new Name("Identity");
      eff = (dict.get("EFF") as never) || stmf;
    }
    this.cf = cf;
    this.stmf = stmf;
    this.strf = strf;
    this.eff = eff;
    const ownerBytes = stringToBytes(dict.get("O"));
    const userBytes = stringToBytes(dict.get("U"));
    const ownerPassword = ownerBytes.subarray(0, 32);
    const userPassword = userBytes.subarray(0, 32);
    const flags = dict.get("P");
    const revision = dict.get("R");
    const encryptMetadata = (algorithm === 4 || algorithm === 5) && dict.get("EncryptMetadata") !== false;
    const fileIdBytes = stringToBytes(fileId);
    let encryptionKey: Uint8Array | null;
    if (algorithm !== 5) {
      encryptionKey = prepareKeyData(fileIdBytes, ownerPassword, userPassword, flags, revision, keyLength, encryptMetadata);
    } else {
      const uBytes = userBytes.subarray(0, 48);
      const userValidationSalt = userBytes.subarray(32, 40);
      const userKeySalt = userBytes.subarray(40, 48);
      stringToBytes(dict.get("OE"));
      const userEncryption = stringToBytes(dict.get("UE"));
      stringToBytes(dict.get("Perms"));
      encryptionKey = createEncryptionKey20(revision === 6, uBytes, userPassword, userValidationSalt, userKeySalt, userEncryption);
    }
    if (!encryptionKey) {
      if (this.algorithm >= 4 && isName(this.stmf, "Identity") && isName(this.strf, "Identity")) {
        const effCF = optionalGet(this.cf, (this.eff as Name)?.name);
        const authEvent = optionalGet(effCF, "AuthEvent");
        if (isName(authEvent, "EFOpen")) {
          this.encryptionKey = null;
          return;
        }
      }
      throw new PdfjsError("Password", "No password given");
    }
    if (algorithm === 4 && encryptionKey.length < 16) {
      this.encryptionKey = new Uint8Array(16);
      this.encryptionKey.set(encryptionKey);
    } else this.encryptionKey = encryptionKey;
  }
  createCipherTransform(num: number, gen: number): CipherTransform {
    if (this.algorithm === 4 || this.algorithm === 5) {
      const resolveCipher = (filterName: PValue): CipherMaker => {
        if (!(filterName instanceof Name)) throw formatError("Invalid crypt filter name.");
        if (!(this.cf instanceof Dict)) throw new TypeError("this.cf.get is not a function");
        const cryptFilter = this.cf.get(filterName.name);
        const cfm = optionalGet(cryptFilter, "CFM");
        if (!cfm || (cfm as Name).name === "None") return nullCipher;
        if (!this.encryptionKey) throw new PdfjsError("Password", "No password given");
        const name = (cfm as Name).name;
        if (this.algorithm === 5 || name === "AESV3") return aesCipher(this.encryptionKey, 32);
        if (name === "V2") return rc4Cipher(buildObjectKey(num, gen, this.encryptionKey, false));
        if (name === "AESV2") return aesCipher(buildObjectKey(num, gen, this.encryptionKey, true), 16);
        throw formatError("Unknown crypto method");
      };
      const transform = new CipherTransform(resolveCipher, this.strf, this.stmf);
      transform.embeddedFilterName = this.eff;
      return transform;
    }
    const key = this.encryptionKey!;
    return new CipherTransform(() => rc4Cipher(buildObjectKey(num, gen, key, false)));
  }
}

/** `v?.get(key)` in pdf.js: undefined for null or undefined, a dictionary's value, and a TypeError for anything else. */
function optionalGet(v: PValue, key: string | undefined): PValue {
  if (v === null || v === undefined) return undefined;
  if (v instanceof Dict) return v.get(key as string);
  throw new TypeError("get is not a function");
}

function prepareKeyData(fileId: Uint8Array, ownerPassword: Uint8Array, userPassword: Uint8Array, flagsValue: PValue, revisionValue: PValue, keyLength: number, encryptMetadata: boolean): Uint8Array | null {
  const flags = jsNumber(flagsValue);
  const revision = revisionValue;
  const hashData = new Uint8Array(40 + ownerPassword.length + fileId.length);
  let i = 0;
  let j = 0;
  while (i < 32) hashData[i++] = PASSWORD_PAD[j++];
  hashData.set(ownerPassword, i);
  i += ownerPassword.length;
  hashData[i++] = flags & 0xff;
  hashData[i++] = (flags >> 8) & 0xff;
  hashData[i++] = (flags >> 16) & 0xff;
  hashData[i++] = (flags >>> 24) & 0xff;
  hashData.set(fileId, i);
  i += fileId.length;
  const revGe = (n: number) => jsNumber(revision) >= n;
  if (revGe(4) && !encryptMetadata) {
    hashData.fill(0xff, i, i + 4);
    i += 4;
  }
  let hash = md5(hashData.subarray(0, i));
  const keyLengthInBytes = keyLength >> 3;
  if (revGe(3)) for (j = 0; j < 50; ++j) hash = md5(firstBytesOf(hash, keyLengthInBytes));
  const encryptionKey = hash.subarray(0, keyLengthInBytes);
  let checkData: Uint8Array;
  if (revGe(3)) {
    i = 0;
    hashData.set(PASSWORD_PAD, i);
    i += 32;
    hashData.set(fileId, i);
    i += fileId.length;
    checkData = rc4(encryptionKey, md5(hashData.subarray(0, i)));
    const n = encryptionKey.length;
    const derivedKey = new Uint8Array(n);
    for (j = 1; j <= 19; ++j) {
      for (let k = 0; k < n; ++k) derivedKey[k] = encryptionKey[k] ^ j;
      checkData = rc4(derivedKey, checkData);
    }
  } else checkData = rc4(encryptionKey, PASSWORD_PAD);
  for (let k = 0; k < checkData.length; k++) if (userPassword[k] !== checkData[k]) return null;
  return encryptionKey;
}
/** calculateMD5(data, 0, length): length bytes from the start, reading past the end as undefined (0 in a typed array). */
function firstBytesOf(data: Uint8Array, length: number): Uint8Array {
  const out = new Uint8Array(length);
  out.set(data.subarray(0, length));
  return out;
}
function hash2(revision6: boolean, input: Uint8Array): Uint8Array {
  if (!revision6) return sha256(input);
  let k = sha256(input);
  let e: Uint8Array = Uint8Array.from([0]);
  const empty = new Uint8Array(0);
  for (let i = 0; i < 64 || e[e.length - 1] > i - 32; i++) {
    const once = new Uint8Array(k.length);
    once.set(k);
    const k1 = new Uint8Array(once.length * 64);
    for (let j = 0; j < 64; j++) k1.set(once, j * once.length);
    void empty;
    e = aesCbcEncrypt(k.subarray(0, 16), k.subarray(16, 32), k1);
    let sum = 0;
    for (let j = 0; j < 16; j++) sum += e[j];
    const pick = sum % 3;
    k = pick === 0 ? sha256(e) : pick === 1 ? sha384(e) : sha512(e);
  }
  return k.subarray(0, 32);
}
function createEncryptionKey20(revision6: boolean, uBytes: Uint8Array, userPassword: Uint8Array, userValidationSalt: Uint8Array, userKeySalt: Uint8Array, userEncryption: Uint8Array): Uint8Array | null {
  const check = hash2(revision6, userValidationSalt);
  if (check.length !== userPassword.length) return null;
  for (let i = 0; i < check.length; i++) if (check[i] !== userPassword[i]) return null;
  const k = hash2(revision6, userKeySalt);
  return aesCbcDecryptBlocks(k, 32, userEncryption, new Uint8Array(16));
}
function buildObjectKey(num: number, gen: number, encryptionKey: Uint8Array, isAes: boolean): Uint8Array {
  const n = encryptionKey.length;
  const key = new Uint8Array(n + 9);
  key.set(encryptionKey);
  let i = n;
  key[i++] = num & 0xff;
  key[i++] = (num >> 8) & 0xff;
  key[i++] = (num >> 16) & 0xff;
  key[i++] = gen & 0xff;
  key[i++] = (gen >> 8) & 0xff;
  if (isAes) {
    key[i++] = 0x73;
    key[i++] = 0x41;
    key[i++] = 0x6c;
    key[i++] = 0x54;
  }
  return md5(key.subarray(0, i)).subarray(0, Math.min(n + 5, 16));
}

// ---- Cross-reference (xref.js) ----------------------------------------------------------------------------------

type XRefEntry = { offset: number; gen: number; free: boolean; uncompressed: boolean };

export class XRef {
  private cacheMap = new Map<number, PValue>();
  private entries: (XRefEntry | undefined)[] = [];
  private pendingRefs = new RefSet();
  private xrefStms = new Set<number>();
  startXRefQueue: number[] = [];
  topDict: Dict | null = null;
  trailer: Dict | null = null;
  root: Dict | null = null;
  encrypt: CipherTransformFactory | null = null;
  generationFallback = false;
  private tableState: { entryNum: number; streamPos: number; parserBuf1: PValue; parserBuf2: PValue; firstEntryNum?: PValue; entryCount?: PValue } | null = null;
  private streamState: { entryRanges: PValue[]; byteWidths: PValue; entryNum: number; streamPos: number } | null = null;
  constructor(readonly stream: Stream) {}
  setStartXRef(startXRef: number) {
    this.startXRefQueue = [startXRef];
  }
  parse(recoveryMode: boolean) {
    let trailerDict: Dict;
    if (!recoveryMode) trailerDict = this.readXRef() as Dict;
    else trailerDict = this.indexObjects();
    trailerDict.xref = this;
    this.trailer = trailerDict;
    let encrypt: PValue;
    try {
      encrypt = trailerDict.get("Encrypt");
    } catch (ex) {
      if (isEngineError(ex)) throw ex;
    }
    if (encrypt instanceof Dict) {
      const ids = trailerDict.get("ID");
      const fileId = Array.isArray(ids) && ids.length ? ids[0] : (ids as { length?: number } | null)?.length ? jsIndex(ids, 0) : "";
      encrypt.suppressEncryption = true;
      this.encrypt = new CipherTransformFactory(encrypt, fileId);
    }
    let root: PValue;
    try {
      root = trailerDict.get("Root");
    } catch (ex) {
      if (isEngineError(ex)) throw ex;
    }
    if (root instanceof Dict) {
      try {
        const pages = root.get("Pages");
        if (pages instanceof Dict) {
          this.root = root;
          return;
        }
      } catch (ex) {
        if (isEngineError(ex)) throw ex;
      }
    }
    if (!recoveryMode) throw new PdfjsError("XRefParse", "");
    throw new PdfjsError("InvalidPDF", "Invalid Root reference.");
  }
  processXRefTable(parser: Parser): Dict {
    this.tableState ??= { entryNum: 0, streamPos: parser.lexer.stream.pos, parserBuf1: parser.buf1, parserBuf2: parser.buf2 };
    const obj = this.readXRefTable(parser);
    if (!isCmd(obj, "trailer")) throw formatError("Invalid XRef table: could not find trailer dictionary");
    let dict = parser.getObj();
    if (dict instanceof PStream) dict = dict.dict;
    if (!(dict instanceof Dict)) throw formatError("Invalid XRef table: could not parse trailer dictionary");
    this.tableState = null;
    return dict;
  }
  readXRefTable(parser: Parser): PValue {
    const stream = parser.lexer.stream;
    const tableState = this.tableState!;
    stream.pos = tableState.streamPos;
    parser.buf1 = tableState.parserBuf1;
    parser.buf2 = tableState.parserBuf2;
    let obj: PValue;
    for (;;) {
      if (!("firstEntryNum" in tableState) || !("entryCount" in tableState)) {
        if (isCmd((obj = parser.getObj()), "trailer")) break;
        tableState.firstEntryNum = obj;
        tableState.entryCount = parser.getObj();
      }
      let first = tableState.firstEntryNum;
      const count = tableState.entryCount;
      if (!isInt(first) || !isInt(count)) throw formatError("Invalid XRef table: wrong types in subsection header");
      for (let i = tableState.entryNum; i < count; i++) {
        tableState.streamPos = stream.pos;
        tableState.entryNum = i;
        tableState.parserBuf1 = parser.buf1;
        tableState.parserBuf2 = parser.buf2;
        const offset = parser.getObj();
        const gen = parser.getObj();
        const entry: XRefEntry = { offset: offset as number, gen: gen as number, free: false, uncompressed: false };
        const type = parser.getObj();
        if (type instanceof Cmd) {
          if (type.cmd === "f") entry.free = true;
          else if (type.cmd === "n") entry.uncompressed = true;
        }
        if (!isInt(offset) || !isInt(gen) || !(entry.free || entry.uncompressed)) throw formatError(`Invalid entry in XRef subsection: ${first}, ${count}`);
        if (i === 0 && entry.free && first === 1) first = 0;
        const at = (first as number) + i;
        if (at >= 0 && this.entries[at] === undefined) this.entries[at] = entry;
      }
      tableState.entryNum = 0;
      tableState.streamPos = stream.pos;
      tableState.parserBuf1 = parser.buf1;
      tableState.parserBuf2 = parser.buf2;
      delete tableState.firstEntryNum;
      delete tableState.entryCount;
    }
    if (this.entries[0] && !this.entries[0].free) throw formatError("Invalid XRef table: unexpected first object");
    return obj;
  }
  processXRefStream(stream: BaseStream): Dict {
    if (!this.streamState) {
      const dict = stream.dict!;
      const byteWidths = dict.get("W");
      const range = (dict.get("Index") as never) || [0, dict.get("Size")];
      this.streamState = { entryRanges: range, byteWidths, entryNum: 0, streamPos: stream.pos };
    }
    this.readXRefStream(stream);
    this.streamState = null;
    return stream.dict!;
  }
  readXRefStream(stream: BaseStream) {
    const streamState = this.streamState!;
    stream.pos = streamState.streamPos;
    const widths = streamState.byteWidths;
    // pdf.js destructures the widths: an array's first three elements (a string's first three characters).
    const [typeFieldWidth, offsetFieldWidth, generationFieldWidth] = destructure3(widths);
    const entryRanges = streamState.entryRanges;
    if (!Array.isArray(entryRanges)) throw new TypeError("entryRanges is not iterable");
    while (entryRanges.length > 0) {
      const [first, n] = entryRanges;
      if (!isInt(first) || !isInt(n)) throw formatError(`Invalid XRef range fields: ${jsString(first)}, ${jsString(n)}`);
      if (![typeFieldWidth, offsetFieldWidth, generationFieldWidth].every((w) => isInt(w) && w >= 0) || (typeFieldWidth as number) + (offsetFieldWidth as number) + (generationFieldWidth as number) === 0) throw formatError(`Invalid XRef entry fields length: ${first}, ${n}`);
      const tw = typeFieldWidth as number, ow = offsetFieldWidth as number, gw = generationFieldWidth as number;
      for (let i = streamState.entryNum; i < n; ++i) {
        streamState.entryNum = i;
        streamState.streamPos = stream.pos;
        let type = 0, offset = 0, generation = 0;
        for (let j = 0; j < tw; ++j) {
          const typeByte = stream.getByte();
          if (typeByte === -1) throw formatError("Invalid XRef byteWidths 'type'.");
          type = (type << 8) | typeByte;
        }
        if (tw === 0) type = 1;
        for (let j = 0; j < ow; ++j) {
          const offsetByte = stream.getByte();
          if (offsetByte === -1) throw formatError("Invalid XRef byteWidths 'offset'.");
          offset = (offset << 8) | offsetByte;
        }
        for (let j = 0; j < gw; ++j) {
          const generationByte = stream.getByte();
          if (generationByte === -1) throw formatError("Invalid XRef byteWidths 'generation'.");
          generation = (generation << 8) | generationByte;
        }
        const entry: XRefEntry = { offset, gen: generation, free: false, uncompressed: false };
        switch (type) {
          case 0:
            entry.free = true;
            break;
          case 1:
            entry.uncompressed = true;
            break;
          case 2:
            break;
          default:
            throw formatError(`Invalid XRef entry type: ${type}`);
        }
        const at = first + i;
        if (at >= 0 && this.entries[at] === undefined) this.entries[at] = entry;
      }
      streamState.entryNum = 0;
      streamState.streamPos = stream.pos;
      entryRanges.splice(0, 2);
    }
  }
  indexObjects(): Dict {
    const TAB = 0x9, LF = 0xa, CR = 0xd, SPACE = 0x20, PERCENT = 0x25, LT = 0x3c;
    const readToken = (data: Uint8Array, offset: number) => {
      let token = "";
      let ch = data[offset];
      while (ch !== LF && ch !== CR && ch !== LT) {
        if (++offset >= data.length) break;
        token += String.fromCharCode(ch);
        ch = data[offset];
      }
      return token;
    };
    const skipUntil = (data: Uint8Array, offset: number, what: number[]) => {
      const length = what.length, dataLength = data.length;
      let skipped = 0;
      while (offset < dataLength) {
        let i = 0;
        while (i < length && data[offset + i] === what[i]) ++i;
        if (i >= length) break;
        offset++;
        skipped++;
      }
      return skipped;
    };
    const gEndobjRegExp = /\b(endobj|\d+\s+\d+\s+obj|xref|trailer\s*<<)\b/g;
    const gStartxrefRegExp = /\b(startxref|\d+\s+\d+\s+obj)\b/g;
    const objRegExp = /^(\d+)\s+(\d+)\s+obj\b/;
    const trailerBytes = [116, 114, 97, 105, 108, 101, 114];
    const startxrefBytes = [115, 116, 97, 114, 116, 120, 114, 101, 102];
    const xrefBytes = [47, 88, 82, 101, 102];
    this.entries.length = 0;
    this.cacheMap.clear();
    const stream = this.stream;
    stream.pos = 0;
    const buffer = stream.getBytes();
    const bufferStr = bytesToString(buffer);
    const length = buffer.length;
    let position = stream.start;
    const trailers: number[] = [];
    const xrefStms: number[] = [];
    while (position < length) {
      let ch = buffer[position];
      if (ch === TAB || ch === LF || ch === CR || ch === SPACE) {
        ++position;
        continue;
      }
      if (ch === PERCENT) {
        do {
          ++position;
          if (position >= length) break;
          ch = buffer[position];
        } while (ch !== LF && ch !== CR);
        continue;
      }
      const token = readToken(buffer, position);
      let m: RegExpExecArray | null;
      if (token.startsWith("xref") && (token.length === 4 || /\s/.test(token[4]))) {
        position += skipUntil(buffer, position, trailerBytes);
        trailers.push(position);
        position += skipUntil(buffer, position, startxrefBytes);
      } else if ((m = objRegExp.exec(token))) {
        const num = (m[1] as unknown as number) | 0, gen = (m[2] as unknown as number) | 0;
        const startPos = position + token.length;
        let contentLength: number;
        let updateEntries = false;
        if (!this.entries[num]) updateEntries = true;
        else if (this.entries[num]!.gen === gen) {
          try {
            const parser = new Parser({ lexer: new Lexer(stream.makeSubStream(startPos)), xref: null });
            parser.getObj();
            updateEntries = true;
          } catch (ex) {
            if (isEngineError(ex)) throw ex;
            if (!(ex instanceof PdfjsError && ex.kind === "ParserEOF")) updateEntries = true;
          }
        }
        if (updateEntries) this.entries[num] = { offset: position - stream.start, gen, free: false, uncompressed: true };
        gEndobjRegExp.lastIndex = startPos;
        const match = gEndobjRegExp.exec(bufferStr);
        if (match) {
          const endPos = gEndobjRegExp.lastIndex + 1;
          contentLength = endPos - position;
          if (match[1] !== "endobj") contentLength -= match[1].length + 1;
        } else contentLength = length - position;
        const content = buffer.subarray(position, position + contentLength);
        const xrefTagOffset = skipUntil(content, 0, xrefBytes);
        if (xrefTagOffset < contentLength && content[xrefTagOffset + 5] < 64) {
          xrefStms.push(position - stream.start);
          this.xrefStms.add(position - stream.start);
        }
        position += contentLength;
      } else if (token.startsWith("trailer") && (token.length === 7 || /\s/.test(token[7]))) {
        trailers.push(position);
        const startPos = position + token.length;
        let contentLength: number;
        gStartxrefRegExp.lastIndex = startPos;
        const match = gStartxrefRegExp.exec(bufferStr);
        if (match) {
          const endPos = gStartxrefRegExp.lastIndex + 1;
          contentLength = endPos - position;
          if (match[1] !== "startxref") contentLength -= match[1].length + 1;
        } else contentLength = length - position;
        position += contentLength;
      } else position += token.length + 1;
    }
    for (const xrefStm of xrefStms) {
      this.startXRefQueue.push(xrefStm);
      this.readXRef(true);
    }
    const trailerDicts: Dict[] = [];
    let isEncrypted = false;
    for (const trailer of trailers) {
      stream.pos = trailer;
      const parser = new Parser({ lexer: new Lexer(stream), xref: this, allowStreams: true, recoveryMode: true });
      const obj = parser.getObj();
      if (!isCmd(obj, "trailer")) continue;
      const dict = parser.getObj();
      if (!(dict instanceof Dict)) continue;
      trailerDicts.push(dict);
      if (dict.has("Encrypt")) isEncrypted = true;
    }
    let trailerDict: Dict | undefined;
    let trailerError: unknown;
    for (const dict of [...trailerDicts, "genFallback" as const, ...trailerDicts]) {
      if (dict === "genFallback") {
        if (!trailerError) break;
        this.generationFallback = true;
        continue;
      }
      let validPagesDict = false;
      try {
        const rootDict = dict.get("Root");
        if (!(rootDict instanceof Dict)) continue;
        const pagesDict = rootDict.get("Pages");
        if (!(pagesDict instanceof Dict)) continue;
        const pagesCount = pagesDict.get("Count");
        if (isInt(pagesCount)) validPagesDict = true;
      } catch (ex) {
        if (isEngineError(ex)) throw ex;
        trailerError = ex;
        continue;
      }
      if (validPagesDict && (!isEncrypted || dict.has("Encrypt")) && dict.has("ID")) return dict;
      trailerDict = dict;
    }
    if (trailerDict) return trailerDict;
    if (this.topDict) return this.topDict;
    if (!trailerDicts.length) {
      for (const num of jsArrayKeys(this.entries)) {
        const entry = this.entries[num];
        if (!entry) continue;
        const ref = new Ref(num, entry.gen);
        let obj: PValue;
        try {
          obj = this.fetch(ref);
        } catch (ex) {
          if (isEngineError(ex)) throw ex;
          continue;
        }
        if (obj instanceof PStream) obj = obj.dict;
        if (obj instanceof Dict && obj.has("Root")) return obj;
      }
    }
    throw new PdfjsError("InvalidPDF", "Invalid PDF structure.");
  }
  readXRef(recoveryMode = false): Dict | undefined {
    const stream = this.stream;
    const startXRefParsedCache = new Set<number>();
    while (this.startXRefQueue.length) {
      try {
        const startXRef = this.startXRefQueue[0];
        if (startXRefParsedCache.has(startXRef)) {
          this.startXRefQueue.shift();
          continue;
        }
        startXRefParsedCache.add(startXRef);
        stream.pos = startXRef + stream.start;
        const parser = new Parser({ lexer: new Lexer(stream), xref: this, allowStreams: true });
        let obj = parser.getObj();
        let dict: Dict;
        if (isCmd(obj, "xref")) {
          dict = this.processXRefTable(parser);
          this.topDict ||= dict;
          obj = dict.get("XRefStm");
          if (isInt(obj) && !this.xrefStms.has(obj)) {
            this.xrefStms.add(obj);
            this.startXRefQueue.push(obj);
          }
        } else if (isInt(obj)) {
          if (!isInt(parser.getObj()) || !isCmd(parser.getObj(), "obj") || !((obj = parser.getObj()) instanceof PStream)) throw formatError("Invalid XRef stream");
          dict = this.processXRefStream(this.decodedStream(obj));
          this.topDict ||= dict;
          if (!dict) throw formatError("Failed to read XRef stream");
        } else throw formatError("Invalid XRef stream header");
        obj = dict.get("Prev");
        if (isInt(obj)) this.startXRefQueue.push(obj);
        else if (obj instanceof Ref) this.startXRefQueue.push(obj.num);
      } catch (e) {
        if (isEngineError(e)) throw e;
      }
      this.startXRefQueue.shift();
    }
    if (this.topDict) return this.topDict;
    if (recoveryMode) return undefined;
    throw new PdfjsError("XRefParse", "");
  }
  getEntry(i: number): XRefEntry | null {
    const entry = i >= 0 ? this.entries[i] : undefined;
    return entry && !entry.free && entry.offset ? entry : null;
  }
  fetchIfRef(obj: PValue, suppressEncryption = false): PValue {
    return obj instanceof Ref ? this.fetch(obj, suppressEncryption) : obj;
  }
  fetch(ref: Ref, suppressEncryption = false): PValue {
    const num = ref.num;
    const cacheEntry = this.cacheMap.get(num);
    if (cacheEntry !== undefined) {
      if (cacheEntry instanceof Dict && !cacheEntry.objId) cacheEntry.objId = ref.str;
      return cacheEntry;
    }
    let xrefEntry: PValue | XRefEntry | null = this.getEntry(num);
    if (xrefEntry === null) return null;
    if (this.pendingRefs.has(ref)) {
      this.pendingRefs.remove(ref);
      return CIRCULAR_REF;
    }
    this.pendingRefs.put(ref);
    try {
      xrefEntry = (xrefEntry as XRefEntry).uncompressed ? this.fetchUncompressed(ref, xrefEntry as XRefEntry, suppressEncryption) : this.fetchCompressed(ref, xrefEntry as XRefEntry);
      this.pendingRefs.remove(ref);
    } catch (ex) {
      this.pendingRefs.remove(ref);
      throw ex;
    }
    if (xrefEntry instanceof Dict) xrefEntry.objId = ref.str;
    else if (xrefEntry instanceof PStream) xrefEntry.dict.objId = ref.str;
    return xrefEntry;
  }
  fetchUncompressed(ref: Ref, xrefEntry: XRefEntry, suppressEncryption = false): PValue {
    const gen = ref.gen;
    let num: number = ref.num;
    if (xrefEntry.gen !== gen) {
      if (this.generationFallback && xrefEntry.gen < gen) return this.fetchUncompressed(new Ref(num, xrefEntry.gen), xrefEntry, suppressEncryption);
      throw new PdfjsError("XRefEntry", `Inconsistent generation in XRef: ${ref.str}`);
    }
    const stream = this.stream.makeSubStream(xrefEntry.offset + this.stream.start);
    const parser = new Parser({ lexer: new Lexer(stream), xref: this, allowStreams: true });
    const obj1 = parser.getObj();
    const obj2 = parser.getObj();
    const obj3 = parser.getObj();
    if (obj1 !== num || obj2 !== gen || !(obj3 instanceof Cmd)) throw new PdfjsError("XRefEntry", `Bad (uncompressed) XRef entry: ${ref.str}`);
    if (obj3.cmd !== "obj") {
      if (obj3.cmd.startsWith("obj")) {
        num = parseInt(obj3.cmd.substring(3), 10);
        if (!Number.isNaN(num)) return num;
      }
      throw new PdfjsError("XRefEntry", `Bad (uncompressed) XRef entry: ${ref.str}`);
    }
    const value = this.encrypt && !suppressEncryption ? parser.getObj(this.encrypt.createCipherTransform(num, gen)) : parser.getObj();
    if (!(value instanceof PStream)) this.cacheMap.set(num, value);
    return value;
  }
  fetchCompressed(ref: Ref, xrefEntry: XRefEntry): PValue {
    const tableOffset = xrefEntry.offset;
    const fetched = this.fetch(new Ref(tableOffset, 0));
    if (!(fetched instanceof PStream)) throw formatError("bad ObjStm stream");
    const stream = this.decodedStream(fetched);
    const first = fetched.dict.get("First");
    const n = fetched.dict.get("N");
    if (!isInt(first) || !isInt(n)) throw formatError("invalid first and n parameters for ObjStm stream");
    let parser = new Parser({ lexer: new Lexer(stream), xref: this, allowStreams: true });
    const nums = new Array<number>(n);
    const offsets = new Array<number>(n);
    for (let i = 0; i < n; ++i) {
      const num = parser.getObj();
      if (!isInt(num)) throw formatError(`invalid object number in the ObjStm stream: ${jsString(num)}`);
      const offset = parser.getObj();
      if (!isInt(offset)) throw formatError(`invalid object offset in the ObjStm stream: ${jsString(offset)}`);
      nums[i] = num;
      const entry = this.getEntry(num);
      if (entry?.offset === tableOffset && entry.gen !== i) entry.gen = i;
      offsets[i] = offset;
    }
    const start = streamStart(stream) + first;
    const entries = new Array<PValue>(n);
    for (let i = 0; i < n; ++i) {
      const length = i < n - 1 ? offsets[i + 1] - offsets[i] : undefined;
      if (length !== undefined && length < 0) throw formatError("Invalid offset in the ObjStm stream.");
      parser = new Parser({ lexer: new Lexer(stream.makeSubStream(start + offsets[i], length, stream.dict)), xref: this, allowStreams: true });
      const obj = parser.getObj();
      entries[i] = obj;
      if (obj instanceof PStream) continue;
      const num = nums[i];
      const entry = num >= 0 ? this.entries[num] : undefined;
      if (entry && entry.offset === tableOffset && entry.gen === i) this.cacheMap.set(num, obj);
    }
    const value = entries[xrefEntry.gen];
    if (value === undefined) throw new PdfjsError("XRefEntry", `Bad (compressed) XRef entry: ${ref.str}`);
    return value;
  }
  /** A stream object read through its filters (and its Crypt filter, when it names one), as pdf.js reads it. */
  decodedStream(s: PStream): BaseStream {
    const base = new Stream(s.raw, 0, s.raw.length, s.dict);
    return applyFilters({ fetchIfRef: (v) => this.fetchIfRef(v), cipher: s.cipher }, base, s.dict, s.raw.length);
  }
}
/** A stream's `start` as pdf.js reads it (`stream.start || 0`): a decoded stream has none. */
const streamStart = (s: BaseStream) => (s instanceof Stream ? s.start || 0 : 0);
function destructure3(v: PValue): [PValue, PValue, PValue] {
  if (Array.isArray(v)) return [v[0], v[1], v[2]];
  if (typeof v === "string") return [v[0], v[1], v[2]];
  throw new TypeError("byteWidths is not iterable");
}
const jsIndex = (v: PValue, i: number): PValue => (Array.isArray(v) || typeof v === "string" ? v[i] : undefined);
/** `for (const num in array)`: the array's own indices that hold a value, as strings in ascending order. */
function jsArrayKeys(a: unknown[]): number[] {
  const out: number[] = [];
  for (let i = 0; i < a.length; i++) if (i in a) out.push(i);
  return out;
}

// ---- The document: header, startxref, linearization, page tree (document.js, catalog.js) -----------------------

const PDF_HEADER_SIGNATURE = [0x25, 0x50, 0x44, 0x46, 0x2d];
const STARTXREF_SIGNATURE = [0x73, 0x74, 0x61, 0x72, 0x74, 0x78, 0x72, 0x65, 0x66];
const ENDOBJ_SIGNATURE = [0x65, 0x6e, 0x64, 0x6f, 0x62, 0x6a];
function find(stream: Stream, signature: number[], limit = 1024, backwards = false): boolean {
  const signatureLength = signature.length;
  const scanBytes = stream.peekBytes(limit);
  const scanLength = scanBytes.length - signatureLength;
  if (scanLength <= 0) return false;
  if (backwards) {
    const signatureEnd = signatureLength - 1;
    let pos = scanBytes.length - 1;
    while (pos >= signatureEnd) {
      let j = 0;
      while (j < signatureLength && scanBytes[pos - j] === signature[signatureEnd - j]) j++;
      if (j >= signatureLength) {
        stream.pos += pos - signatureEnd;
        return true;
      }
      pos--;
    }
  } else {
    let pos = 0;
    while (pos <= scanLength) {
      let j = 0;
      while (j < signatureLength && scanBytes[pos + j] === signature[j]) j++;
      if (j >= signatureLength) {
        stream.pos += pos;
        return true;
      }
      pos++;
    }
  }
  return false;
}

type Linearization = { numPages: number; objectNumberFirst: number; pageFirst: number } | null;
function linearizationOf(stream: Stream): Linearization {
  const getInt = (linDict: Dict, name: string, allowZeroValue = false) => {
    const obj = linDict.get(name);
    if (isInt(obj) && (allowZeroValue ? obj >= 0 : obj > 0)) return obj;
    throw new Error(`The "${name}" parameter in the linearization dictionary is invalid.`);
  };
  const parser = new Parser({ lexer: new Lexer(stream), xref: null });
  const obj1 = parser.getObj();
  const obj2 = parser.getObj();
  const obj3 = parser.getObj();
  const linDict = parser.getObj();
  let obj: PValue;
  if (!(isInt(obj1) && isInt(obj2) && isCmd(obj3, "obj") && linDict instanceof Dict && typeof (obj = linDict.get("Linearized")) === "number" && obj > 0)) return null;
  if (getInt(linDict, "L") !== stream.length) throw new Error('The "L" parameter in the linearization dictionary does not equal the stream length.');
  const hints = linDict.get("H");
  if (!(Array.isArray(hints) && (hints.length === 2 || hints.length === 4) && hints.every((h) => isInt(h) && h > 0))) throw new Error("Hint array in the linearization dictionary is invalid.");
  return { objectNumberFirst: getInt(linDict, "O"), numPages: (getInt(linDict, "E"), getInt(linDict, "N")), pageFirst: (getInt(linDict, "T"), linDict.has("P") ? getInt(linDict, "P", true) : 0) };
}

/** A page as pdf.js's getPage gives it: its dictionary and ref, or the error pdf.js gets for it. */
export type PdfjsPage = { dict: Dict; ref: Ref | null } | { error: unknown };

/** The document pdf.js loads: its cross-reference, trailer and catalog, and its pages as the signing page asks for them. */
export interface PdfjsDocument {
  xref: XRef;
  trailer: Dict;
  root: Dict;
  pages: PdfjsPage[];
  /** Whether pdf.js reconstructed the cross-reference (indexObjects). */
  recovered: boolean;
}

class Loader {
  stream: Stream;
  xref: XRef;
  linearization: Linearization | undefined;
  startXRefValue: number | undefined;
  pagePromises = new Map<number, PdfjsPage>();
  catalog: Catalog | null = null;
  constructor(bytes: Uint8Array) {
    if (bytes.length <= 0) throw new PdfjsError("InvalidPDF", "The PDF file is empty, i.e. its size is zero bytes.");
    this.stream = new Stream(bytes);
    this.xref = new XRef(this.stream);
  }
  getLinearization(): Linearization {
    if (this.linearization === undefined) {
      try {
        this.linearization = linearizationOf(this.stream);
      } catch (err) {
        if (isEngineError(err)) throw err;
        this.linearization = null;
      }
    }
    return this.linearization;
  }
  startXRef(): number {
    if (this.startXRefValue !== undefined) return this.startXRefValue;
    const stream = this.stream;
    let startXRef = 0;
    if (this.getLinearization()) {
      stream.reset();
      if (find(stream, ENDOBJ_SIGNATURE)) {
        stream.skip(6);
        let ch = stream.peekByte();
        while (isWhiteSpace(ch)) {
          stream.pos++;
          ch = stream.peekByte();
        }
        startXRef = stream.pos - stream.start;
      }
    } else {
      const step = 1024;
      const startXRefLength = STARTXREF_SIGNATURE.length;
      let found = false;
      let pos = stream.end;
      while (!found && pos > 0) {
        pos -= step - startXRefLength;
        if (pos < 0) pos = 0;
        stream.pos = pos;
        found = find(stream, STARTXREF_SIGNATURE, step, true);
      }
      if (found) {
        stream.skip(9);
        let ch: number;
        do ch = stream.getByte();
        while (isWhiteSpace(ch));
        let str = "";
        while (ch >= 0x20 && ch <= 0x39) {
          str += String.fromCharCode(ch);
          ch = stream.getByte();
        }
        startXRef = parseInt(str, 10);
        if (isNaN(startXRef)) startXRef = 0;
      }
    }
    return (this.startXRefValue = startXRef);
  }
  checkHeader() {
    const stream = this.stream;
    stream.reset();
    if (!find(stream, PDF_HEADER_SIGNATURE)) return;
    stream.moveStart();
  }
  initDocument(recoveryMode: boolean) {
    this.checkHeader();
    this.xref.setStartXRef(this.startXRef());
    this.xref.parse(recoveryMode);
    this.catalog = new Catalog(this.xref);
    this.checkFirstPage(recoveryMode);
    this.checkLastPage(recoveryMode);
  }
  getPage(pageIndex: number): PdfjsPage {
    const cached = this.pagePromises.get(pageIndex);
    if (cached) return cached;
    const catalog = this.catalog!;
    let result: PdfjsPage;
    try {
      const lin = this.getLinearization();
      const [dict, ref] = lin && lin.pageFirst === pageIndex ? this.getLinearizationPage(pageIndex) : catalog.getPageDict(pageIndex);
      result = { dict: dict as Dict, ref };
    } catch (error) {
      if (isEngineError(error)) throw error;
      result = { error };
    }
    this.pagePromises.set(pageIndex, result);
    return result;
  }
  getLinearizationPage(pageIndex: number): [Dict, Ref | null] {
    const catalog = this.catalog!;
    const ref = new Ref(this.getLinearization()!.objectNumberFirst, 0);
    try {
      const obj = this.xref.fetch(ref);
      if (obj instanceof Dict) {
        let type = obj.getRaw("Type");
        if (type instanceof Ref) type = this.xref.fetch(type);
        if (isName(type, "Page") || (!obj.has("Type") && !obj.has("Kids") && obj.has("Contents"))) {
          if (!catalog.pageKidsCountCache.has(ref)) catalog.pageKidsCountCache.put(ref, 1);
          if (!catalog.pageIndexCache.has(ref)) catalog.pageIndexCache.put(ref, 0);
          return [obj, ref];
        }
      }
      throw formatError("The Linearization dictionary doesn't point to a valid Page dictionary.");
    } catch (reason) {
      if (isEngineError(reason)) throw reason;
      return catalog.getPageDict(pageIndex);
    }
  }
  checkFirstPage(recoveryMode: boolean) {
    if (recoveryMode) return;
    const page = this.getPage(0);
    if ("error" in page && page.error instanceof PdfjsError && page.error.kind === "XRefEntry") {
      this.pagePromises.delete(0);
      this.catalog!.cleanup();
      throw new PdfjsError("XRefParse", "");
    }
  }
  checkLastPage(recoveryMode: boolean) {
    const catalog = this.catalog!;
    catalog.actualNumPages = null;
    let numPages: PValue;
    try {
      const lin = this.getLinearization();
      if (lin) numPages = lin.numPages;
      else numPages = catalog.numPages();
      if (!isInt(numPages)) throw formatError("Page count is not an integer.");
      else if (numPages <= 1) return;
      const page = this.getPage(numPages - 1);
      if ("error" in page) throw page.error;
    } catch (reason) {
      if (isEngineError(reason)) throw reason;
      this.pagePromises.delete(jsNumber(numPages!) - 1);
      catalog.cleanup();
      if (reason instanceof PdfjsError && reason.kind === "XRefEntry" && !recoveryMode) throw new PdfjsError("XRefParse", "");
      let pagesTree: Map<number, [Dict | unknown, Ref | null]>;
      try {
        pagesTree = catalog.getAllPageDicts(recoveryMode);
      } catch (reasonAll) {
        if (isEngineError(reasonAll)) throw reasonAll;
        if (reasonAll instanceof PdfjsError && reasonAll.kind === "XRefEntry" && !recoveryMode) throw new PdfjsError("XRefParse", "");
        catalog.actualNumPages = 1;
        return;
      }
      for (const [pageIndex, [pageDict, ref]] of pagesTree) {
        if (pageDict instanceof Dict) this.pagePromises.set(pageIndex, { dict: pageDict, ref });
        else this.pagePromises.set(pageIndex, { error: pageDict });
      }
      catalog.actualNumPages = pagesTree.size;
    }
  }
  numPages(): number {
    const catalog = this.catalog!;
    if (catalog.actualNumPages !== null) return catalog.actualNumPages;
    const lin = this.getLinearization();
    if (lin) return lin.numPages;
    return catalog.numPages() as number;
  }
}

class Catalog {
  catDict: Dict;
  actualNumPages: number | null = null;
  pageKidsCountCache = new RefMap<number>();
  pageIndexCache = new RefMap<number>();
  pageDictCache = new RefMap<() => PValue>();
  topPages: Dict;
  constructor(readonly xref: XRef) {
    const catDict = xref.root;
    if (!(catDict instanceof Dict)) throw formatError("Catalog object is not a dictionary.");
    this.catDict = catDict;
    const pagesObj = catDict.get("Pages");
    if (!(pagesObj instanceof Dict)) throw formatError("Invalid top-level pages dictionary.");
    this.topPages = pagesObj;
  }
  cleanup() {
    this.pageKidsCountCache.clear();
    this.pageIndexCache.clear();
    this.pageDictCache.clear();
  }
  private pagesCount: PValue | undefined;
  numPages(): PValue {
    if (this.actualNumPages !== null) return this.actualNumPages;
    if (this.pagesCount === undefined) {
      const obj = this.topPages.get("Count");
      if (!isInt(obj)) throw formatError("Page count in top-level pages dictionary is not an integer.");
      this.pagesCount = obj;
    }
    return this.pagesCount;
  }
  getPageDict(pageIndex: number): [Dict, Ref | null] {
    const nodesToVisit: PValue[] = [this.topPages];
    const visitedNodes = new RefSet();
    const pagesRef = this.catDict.getRaw("Pages");
    if (pagesRef instanceof Ref) visitedNodes.put(pagesRef);
    const xref = this.xref;
    let currentPageIndex = 0;
    while (nodesToVisit.length) {
      const currentNode = nodesToVisit.pop();
      if (currentNode instanceof Ref) {
        const count = this.pageKidsCountCache.get(currentNode);
        if (count !== undefined && count >= 0 && currentPageIndex + count <= pageIndex) {
          currentPageIndex += count;
          continue;
        }
        if (visitedNodes.has(currentNode)) throw formatError("Pages tree contains circular reference.");
        visitedNodes.put(currentNode);
        const cached = this.pageDictCache.get(currentNode);
        const obj = cached ? cached() : xref.fetch(currentNode);
        if (obj instanceof Dict) {
          let type = obj.getRaw("Type");
          if (type instanceof Ref) type = xref.fetch(type);
          if (isName(type, "Page") || !obj.has("Kids")) {
            if (!this.pageKidsCountCache.has(currentNode)) this.pageKidsCountCache.put(currentNode, 1);
            if (!this.pageIndexCache.has(currentNode)) this.pageIndexCache.put(currentNode, currentPageIndex);
            if (currentPageIndex === pageIndex) return [obj, currentNode];
            currentPageIndex++;
            continue;
          }
        }
        nodesToVisit.push(obj);
        continue;
      }
      if (!(currentNode instanceof Dict)) throw formatError("Page dictionary kid reference points to wrong type of object.");
      const objId = currentNode.objId;
      let count = currentNode.getRaw("Count");
      if (count instanceof Ref) count = xref.fetch(count);
      if (isInt(count) && count >= 0) {
        if (objId && !this.pageKidsCountCache.has(objId)) this.pageKidsCountCache.put(objId, count);
        if (currentPageIndex + count <= pageIndex) {
          currentPageIndex += count;
          continue;
        }
      }
      let kids = currentNode.getRaw("Kids");
      if (kids instanceof Ref) kids = xref.fetch(kids);
      if (!Array.isArray(kids)) {
        let type = currentNode.getRaw("Type");
        if (type instanceof Ref) type = xref.fetch(type);
        if (isName(type, "Page") || !currentNode.has("Kids")) {
          if (currentPageIndex === pageIndex) return [currentNode, null];
          currentPageIndex++;
          continue;
        }
        throw formatError("Page dictionary kids object is not an array.");
      }
      for (let last = kids.length - 1; last >= 0; last--) {
        const lastKid = kids[last];
        nodesToVisit.push(lastKid);
        if (currentNode === this.topPages && lastKid instanceof Ref && !this.pageDictCache.has(lastKid)) {
          // pdf.js starts fetching the top level's kids at once; a fetch that fails fails when the kid is visited.
          let settled: { v: PValue } | { e: unknown };
          try {
            settled = { v: xref.fetch(lastKid) };
          } catch (e) {
            if (isEngineError(e)) throw e;
            settled = { e };
          }
          this.pageDictCache.put(lastKid, () => {
            if ("e" in settled) throw settled.e;
            return settled.v;
          });
        }
      }
    }
    throw new Error(`Page index ${pageIndex} not found.`);
  }
  getAllPageDicts(recoveryMode: boolean): Map<number, [Dict | unknown, Ref | null]> {
    const queue: { currentNode: Dict; posInKids: number }[] = [{ currentNode: this.topPages, posInKids: 0 }];
    const visitedNodes = new RefSet();
    const pagesRef = this.catDict.getRaw("Pages");
    if (pagesRef instanceof Ref) visitedNodes.put(pagesRef);
    const map = new Map<number, [Dict | unknown, Ref | null]>();
    const xref = this.xref;
    let pageIndex = 0;
    const addPageDict = (pageDict: Dict, pageRef: Ref | null) => {
      if (pageRef && !this.pageIndexCache.has(pageRef)) this.pageIndexCache.put(pageRef, pageIndex);
      map.set(pageIndex++, [pageDict, pageRef]);
    };
    const addPageError = (error: unknown) => {
      if (error instanceof PdfjsError && error.kind === "XRefEntry" && !recoveryMode) throw error;
      // The signing page's pdf.js ignores errors: a bad first page found by reconstruction becomes an empty one.
      if (recoveryMode && pageIndex === 0) error = EMPTY_DICT;
      map.set(pageIndex++, [error, null]);
    };
    const fetch = (r: Ref): { v: PValue } | { e: unknown } => {
      try {
        return { v: xref.fetch(r) };
      } catch (e) {
        if (isEngineError(e)) throw e;
        return { e };
      }
    };
    while (queue.length > 0) {
      const queueItem = queue[queue.length - 1];
      const { currentNode, posInKids } = queueItem;
      let kids = currentNode.getRaw("Kids");
      if (kids instanceof Ref) {
        const f = fetch(kids);
        if ("e" in f) {
          addPageError(f.e);
          break;
        }
        kids = f.v;
      }
      if (!Array.isArray(kids)) {
        let type = currentNode.getRaw("Type");
        if (type instanceof Ref) {
          const f = fetch(type);
          if ("e" in f) {
            addPageError(f.e);
            break;
          }
          type = f.v;
        }
        if (isName(type, "Page") || !currentNode.has("Kids")) {
          addPageDict(currentNode, null);
          break;
        }
        addPageError(formatError("Page dictionary kids object is not an array."));
        break;
      }
      if (posInKids >= kids.length) {
        queue.pop();
        continue;
      }
      const kidObj = kids[posInKids];
      let obj: PValue;
      if (kidObj instanceof Ref) {
        if (visitedNodes.has(kidObj)) {
          addPageError(formatError("Pages tree contains circular reference."));
          break;
        }
        visitedNodes.put(kidObj);
        const f = fetch(kidObj);
        if ("e" in f) {
          addPageError(f.e);
          break;
        }
        obj = f.v;
      } else obj = kidObj;
      if (!(obj instanceof Dict)) {
        addPageError(formatError("Page dictionary kid reference points to wrong type of object."));
        break;
      }
      let type = obj.getRaw("Type");
      if (type instanceof Ref) {
        const f = fetch(type);
        if ("e" in f) {
          addPageError(f.e);
          break;
        }
        type = f.v;
      }
      if (isName(type, "Page") || !obj.has("Kids")) addPageDict(obj, kidObj instanceof Ref ? kidObj : null);
      else queue.push({ currentNode: obj, posInKids: 0 });
      queueItem.posInKids++;
    }
    return map;
  }
}

/** Why pdf.js can't show a document's pages to the signer. */
export type Unreadable = "password" | "unsupported" | "damaged";

/**
 * The document as the signing page's pdf.js loads it (getDocument, which reconstructs a broken cross-reference, then
 * getPage for every page in turn), or why the signer's page couldn't show it.
 */
export function loadLikePdfjs(bytes: Uint8Array): PdfjsDocument | { unreadable: Unreadable; error: unknown } {
  let loader: Loader;
  let recovered = false;
  const classify = (e: unknown): Unreadable => (e instanceof PdfjsError && e.kind === "Password" ? "password" : e instanceof PdfjsError && /encryption|key length|crypt/i.test(e.message) ? "unsupported" : "damaged");
  try {
    loader = new Loader(bytes);
  } catch (e) {
    if (isEngineError(e)) throw e;
    return { unreadable: "damaged", error: e };
  }
  try {
    try {
      loader.initDocument(false);
    } catch (e) {
      if (!(e instanceof PdfjsError && e.kind === "XRefParse")) throw e;
      recovered = true;
      loader.initDocument(true);
    }
  } catch (e) {
    if (isEngineError(e)) throw e;
    if (loader.xref.encrypt === null && e instanceof Error && /stringToBytes|is not a function|Cannot read prop/i.test(e.message) && loader.xref.trailer?.has("Encrypt")) return { unreadable: "unsupported", error: e };
    return { unreadable: classify(e), error: e };
  }
  let numPages: number;
  try {
    numPages = loader.numPages();
  } catch (e) {
    if (isEngineError(e)) throw e;
    return { unreadable: "damaged", error: e };
  }
  const pages: PdfjsPage[] = [];
  for (let i = 0; i < numPages; i++) pages.push(loader.getPage(i));
  return { xref: loader.xref, trailer: loader.xref.trailer!, root: loader.xref.root!, pages, recovered };
}

/** getInheritableProperty with stopWhenFound false, as Page reads Resources, MediaBox, CropBox, Rotate and Annots. */
export function inheritableProperty(dict: Dict, key: string, getArray: boolean): PValue {
  const values: PValue[] = [];
  const visited = new RefSet();
  let d: PValue = dict;
  while (d instanceof Dict && !(d.objId && visited.has(d.objId))) {
    if (d.objId) visited.put(d.objId);
    const value = getArray ? d.getArray(key) : d.get(key);
    if (value !== undefined) values.push(value);
    d = d.get("Parent");
  }
  if (!values.length) return undefined;
  return values.length === 1 || !(values[0] instanceof Dict) ? values[0] : Dict.merge(dict.xref, values);
}
