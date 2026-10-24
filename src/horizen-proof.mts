// Checks that a value was in Horizen's state, using only data that outlives the Horizen chain: a block header, a
// Merkle Patricia proof from that header's state root, and the output root the Horizen chain posted to Base for that
// block. No dependencies: the caller passes keccak256, so the verifier can carry this file as is.
//
// The chain of trust: storage proof -> account proof -> header stateRoot -> keccak(header) = blockHash ->
// outputRoot = keccak(version 0 | stateRoot | messagePasserStorageRoot | blockHash) -> rootClaim of a dispute game on
// Base that resolved DEFENDER_WINS.

export type Keccak = (data: Uint8Array) => Uint8Array;

export const hexToBytes = (hex: string): Uint8Array => {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (h.length % 2 || /[^0-9a-f]/i.test(h)) throw new Error(`not hex: ${hex.slice(0, 20)}`);
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  return out;
};

export const bytesToHex = (b: Uint8Array): string => "0x" + Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

const concat = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) (out.set(p, o), (o += p.length));
  return out;
};

const equal = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

// ---- RLP

export type Rlp = Uint8Array | Rlp[];

/** Decodes one RLP item that must span all of `data`. */
export function rlpDecode(data: Uint8Array): Rlp {
  const [item, end] = decodeAt(data, 0);
  if (end !== data.length) throw new Error("rlp: trailing bytes");
  return item;
}

function decodeAt(d: Uint8Array, p: number): [Rlp, number] {
  if (p >= d.length) throw new Error("rlp: truncated");
  const b = d[p];
  const len = (n: number, at: number) => {
    if (n === 0 || d[at] === 0) throw new Error("rlp: non-canonical length");
    let v = 0;
    for (let i = 0; i < n; i++) v = v * 256 + d[at + i];
    return v;
  };
  const take = (s: number, n: number) => {
    if (s + n > d.length) throw new Error("rlp: truncated");
    return d.subarray(s, s + n);
  };
  if (b < 0x80) return [d.subarray(p, p + 1), p + 1];
  if (b < 0xb8) {
    const n = b - 0x80;
    if (n === 1 && d[p + 1] < 0x80) throw new Error("rlp: non-canonical byte");
    return [take(p + 1, n), p + 1 + n];
  }
  if (b < 0xc0) {
    const ll = b - 0xb7, n = len(ll, p + 1);
    if (n < 56) throw new Error("rlp: non-canonical length");
    return [take(p + 1 + ll, n), p + 1 + ll + n];
  }
  let n: number, s: number;
  if (b < 0xf8) (n = b - 0xc0), (s = p + 1);
  else {
    const ll = b - 0xf7;
    n = len(ll, p + 1);
    if (n < 56) throw new Error("rlp: non-canonical length");
    s = p + 1 + ll;
  }
  const end = s + n;
  if (end > d.length) throw new Error("rlp: truncated");
  const items: Rlp[] = [];
  for (let q = s; q < end; ) {
    const [it, next] = decodeAt(d, q);
    items.push(it);
    q = next;
  }
  return [items, end];
}

export function rlpEncode(item: Rlp): Uint8Array {
  const head = (n: number, base: number) => {
    if (n < 56) return Uint8Array.of(base + n);
    const bytes: number[] = [];
    for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v % 256);
    return Uint8Array.of(base + 55 + bytes.length, ...bytes);
  };
  if (item instanceof Uint8Array) {
    if (item.length === 1 && item[0] < 0x80) return item;
    return concat(head(item.length, 0x80), item);
  }
  const body = concat(...item.map(rlpEncode));
  return concat(head(body.length, 0xc0), body);
}

/** A non-negative integer (hex quantity or bigint) as minimal big-endian bytes, the way RLP encodes integers. */
export function intBytes(v: string | bigint | number): Uint8Array {
  let n = BigInt(v);
  if (n < 0n) throw new Error("negative");
  const out: number[] = [];
  for (; n > 0n; n >>= 8n) out.unshift(Number(n & 0xffn));
  return Uint8Array.from(out);
}

export const bytesToBigInt = (b: Uint8Array): bigint => (b.length ? BigInt(bytesToHex(b)) : 0n);

// ---- Merkle Patricia proofs

const nibbles = (b: Uint8Array) => Array.from(b).flatMap((x) => [x >> 4, x & 15]);

/**
 * Walks `proof` (RLP nodes, root first) from `root` along keccak(key). Returns the value stored there, or null when the
 * proof shows nothing is stored under the key. Throws when the proof doesn't connect to `root`.
 */
export function verifyMptProof(keccak: Keccak, root: Uint8Array, key: Uint8Array, proof: Uint8Array[]): Uint8Array | null {
  const path = nibbles(keccak(key));
  let pos = 0;
  let want: Uint8Array | Rlp[] = root; // a hash to match, or an embedded node (shorter than 32 bytes) already decoded
  let i = 0;
  for (;;) {
    let node: Rlp;
    if (want instanceof Uint8Array) {
      if (i >= proof.length) throw new Error("mpt: proof ends early");
      const raw = proof[i++];
      if (!equal(keccak(raw), want)) throw new Error(`mpt: node ${i - 1} doesn't hash to its reference`);
      node = rlpDecode(raw);
    } else node = want;
    if (!Array.isArray(node)) throw new Error("mpt: node is not a list");
    let next: Rlp;
    if (node.length === 17) {
      if (pos === path.length) throw new Error("mpt: key ends at a branch");
      next = node[path[pos++]];
    } else if (node.length === 2) {
      const enc = node[0];
      if (!(enc instanceof Uint8Array) || enc.length === 0) throw new Error("mpt: bad path");
      const flag = enc[0] >> 4;
      if (flag > 3) throw new Error("mpt: bad path flag");
      const seg = nibbles(enc).slice(flag & 1 ? 1 : 2);
      const rest = path.slice(pos);
      if (flag >= 2) {
        // leaf
        if (i !== proof.length) throw new Error("mpt: nodes after a leaf");
        if (seg.length !== rest.length || seg.some((x, k) => x !== rest[k])) return null;
        const v = node[1];
        if (!(v instanceof Uint8Array)) throw new Error("mpt: leaf value is a list");
        return v;
      }
      // extension
      if (seg.length > rest.length || seg.some((x, k) => x !== rest[k])) {
        if (i !== proof.length) throw new Error("mpt: nodes after a diverging extension");
        return null;
      }
      pos += seg.length;
      next = node[1];
    } else throw new Error("mpt: bad node size");
    if (next instanceof Uint8Array) {
      if (next.length === 0) {
        if (i !== proof.length) throw new Error("mpt: nodes after an empty child");
        return null;
      }
      if (next.length !== 32) throw new Error("mpt: bad child reference");
      want = next;
    } else want = next;
  }
}

export interface Account { nonce: bigint; balance: bigint; storageRoot: Uint8Array; codeHash: Uint8Array }

export function verifyAccount(keccak: Keccak, stateRoot: Uint8Array, address: string, proof: string[]): Account | null {
  const v = verifyMptProof(keccak, stateRoot, hexToBytes(address), proof.map(hexToBytes));
  if (!v) return null;
  const a = rlpDecode(v);
  if (!Array.isArray(a) || a.length !== 4 || !a.every((x) => x instanceof Uint8Array)) throw new Error("account: bad shape");
  const [nonce, balance, storageRoot, codeHash] = a as Uint8Array[];
  return { nonce: bytesToBigInt(nonce), balance: bytesToBigInt(balance), storageRoot, codeHash };
}

/** The 32-byte word in `slot` (0 when the proof shows the slot is empty). */
export function verifyStorage(keccak: Keccak, storageRoot: Uint8Array, slot: string, proof: string[]): bigint {
  const v = verifyMptProof(keccak, storageRoot, hexToBytes(slot), proof.map(hexToBytes));
  if (!v) return 0n;
  const inner = rlpDecode(v);
  if (!(inner instanceof Uint8Array) || inner.length > 32 || inner[0] === 0) throw new Error("storage: bad value");
  return bytesToBigInt(inner);
}

// ---- Storage slots (Solidity layout)

export const word = (v: string | bigint): Uint8Array => {
  const n = typeof v === "bigint" ? v : BigInt(v);
  return hexToBytes(n.toString(16).padStart(64, "0"));
};

export const slotHex = (n: bigint) => "0x" + n.toString(16).padStart(64, "0");

/** mapping(key => ...) at `slot`: keccak(key . slot). */
export const mappingSlot = (keccak: Keccak, key: string | bigint, slot: string | bigint): string =>
  bytesToHex(keccak(concat(word(key), word(slot))));

/** Element `index` of a dynamic array at `slot`, with `perSlot` elements packed into each word. */
export const arraySlot = (keccak: Keccak, slot: bigint, index: number, perSlot = 1): string =>
  slotHex(bytesToBigInt(keccak(word(slot))) + BigInt(Math.floor(index / perSlot)));

// ---- Headers and output roots

/** Header fields in RLP order (OP Stack after Isthmus: London, Shanghai, Cancun and Prague fields). */
export const HEADER_FIELDS = [
  "parentHash", "sha3Uncles", "miner", "stateRoot", "transactionsRoot", "receiptsRoot", "logsBloom", "difficulty",
  "number", "gasLimit", "gasUsed", "timestamp", "extraData", "mixHash", "nonce", "baseFeePerGas", "withdrawalsRoot",
  "blobGasUsed", "excessBlobGas", "parentBeaconBlockRoot", "requestsHash",
] as const;
const INT_FIELDS = new Set(["difficulty", "number", "gasLimit", "gasUsed", "timestamp", "baseFeePerGas", "blobGasUsed", "excessBlobGas"]);

/** RLP of a header given as JSON-RPC fields. Ends at the last field present. */
export function encodeHeader(h: Record<string, string>): Uint8Array {
  const items: Rlp[] = [];
  for (const f of HEADER_FIELDS) {
    if (h[f] === undefined || h[f] === null) break;
    items.push(INT_FIELDS.has(f) ? intBytes(h[f]) : hexToBytes(h[f]));
  }
  return rlpEncode(items);
}

export interface Header { hash: Uint8Array; number: bigint; timestamp: bigint; stateRoot: Uint8Array; withdrawalsRoot: Uint8Array }

/** Decodes a raw header and returns its hash and the fields the proofs use. */
export function readHeader(keccak: Keccak, raw: Uint8Array): Header {
  const h = rlpDecode(raw);
  if (!Array.isArray(h) || h.length < 17 || !h.every((x) => x instanceof Uint8Array)) throw new Error("header: bad shape");
  const f = h as Uint8Array[];
  const idx = (name: (typeof HEADER_FIELDS)[number]) => HEADER_FIELDS.indexOf(name);
  return {
    hash: keccak(raw),
    number: bytesToBigInt(f[idx("number")]),
    timestamp: bytesToBigInt(f[idx("timestamp")]),
    stateRoot: f[idx("stateRoot")],
    withdrawalsRoot: f[idx("withdrawalsRoot")],
  };
}

/** OP Stack output root, version 0. After Isthmus the header's withdrawalsRoot is the message passer's storage root. */
export const outputRoot = (keccak: Keccak, header: Header): Uint8Array =>
  keccak(concat(new Uint8Array(32), header.stateRoot, header.withdrawalsRoot, header.hash));
