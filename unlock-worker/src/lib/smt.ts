/**
 * Sparse Merkle tree of depth 256 (SHA-256), shared by the server and the
 * browser. Keys are 32 bytes (the sha256 of an email); each key has exactly one
 * slot, so the tree can hold at most one value per person.
 *
 *   leaf  = H(0x00 || key || value)
 *   node  = H(0x01 || left || right)
 *   empty = 32 zero bytes at the leaves; E[h+1] = H(0x01 || E[h] || E[h])
 *
 * The path to a key follows its bits, most significant first (0 = left).
 * A proof lists the non-empty siblings from the root down, with a bitmap of
 * which depths have one.
 */

export type Hex = string;
export interface SmtEntry {
  key: Hex; // 64 hex chars
  value: Hex; // 64 hex chars
}
export interface SmtProof {
  bitmap: Hex; // 64 hex chars: bit d set = a non-empty sibling at depth d
  siblings: Hex[]; // non-empty siblings, from depth 0 down
}

const DEPTH = 256;

const toBytes = (hex: Hex) => {
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error("expected 32 bytes of hex");
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
};
const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const bit = (key: Uint8Array, d: number) => (key[d >> 3] >> (7 - (d & 7))) & 1;

async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const buf = new Uint8Array(len);
  let o = 0;
  for (const p of parts) {
    buf.set(p, o);
    o += p.length;
  }
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf as unknown as BufferSource));
}

const LEAF = new Uint8Array([0]);
const NODE = new Uint8Array([1]);

let emptyCache: Uint8Array[] | null = null;
/** E[h]: the hash of an empty subtree of height h. */
async function empties(): Promise<Uint8Array[]> {
  if (emptyCache) return emptyCache;
  const e: Uint8Array[] = [new Uint8Array(32)];
  for (let h = 1; h <= DEPTH; h++) e.push(await sha256(NODE, e[h - 1], e[h - 1]));
  return (emptyCache = e);
}

const leafHash = (key: Uint8Array, value: Uint8Array) => sha256(LEAF, key, value);

type Item = { key: Uint8Array; value: Uint8Array };

async function subtree(items: Item[], depth: number, E: Uint8Array[]): Promise<Uint8Array> {
  if (items.length === 0) return E[DEPTH - depth];
  if (depth === DEPTH) return leafHash(items[0].key, items[0].value);
  const left = items.filter((i) => bit(i.key, depth) === 0);
  const right = items.filter((i) => bit(i.key, depth) === 1);
  return sha256(NODE, await subtree(left, depth + 1, E), await subtree(right, depth + 1, E));
}

function items(entries: SmtEntry[]): Item[] {
  const seen = new Set<string>();
  return entries.map((e) => {
    if (seen.has(e.key)) throw new Error("duplicate key");
    seen.add(e.key);
    return { key: toBytes(e.key), value: toBytes(e.value) };
  });
}

/** The root of a tree holding `entries`. */
export async function smtRoot(entries: SmtEntry[]): Promise<Hex> {
  return toHex(await subtree(items(entries), 0, await empties()));
}

/** A proof for `key` (present or absent) in the tree holding `entries`. */
export async function smtProof(entries: SmtEntry[], keyHex: Hex): Promise<SmtProof> {
  const E = await empties();
  const key = toBytes(keyHex);
  let set = items(entries);
  const bitmap = new Uint8Array(32);
  const siblings: Hex[] = [];
  for (let d = 0; d < DEPTH; d++) {
    const side = bit(key, d);
    const other = set.filter((i) => bit(i.key, d) !== side);
    set = set.filter((i) => bit(i.key, d) === side);
    if (other.length) {
      bitmap[d >> 3] |= 1 << (7 - (d & 7));
      siblings.push(toHex(await subtree(other, d + 1, E)));
    }
  }
  return { bitmap: toHex(bitmap), siblings };
}

/** The root that `proof` implies for `key` holding `value` (or empty, with null). */
export async function smtComputeRoot(keyHex: Hex, valueHex: Hex | null, proof: SmtProof): Promise<Hex> {
  const E = await empties();
  const key = toBytes(keyHex);
  const bitmap = toBytes(proof.bitmap);
  let cur = valueHex ? await leafHash(key, toBytes(valueHex)) : E[0];
  let s = proof.siblings.length - 1;
  for (let d = DEPTH - 1; d >= 0; d--) {
    const present = (bitmap[d >> 3] >> (7 - (d & 7))) & 1;
    const sib = present ? toBytes(proof.siblings[s--] ?? "") : E[DEPTH - 1 - d];
    cur = bit(key, d) === 0 ? await sha256(NODE, cur, sib) : await sha256(NODE, sib, cur);
  }
  if (s !== -1) throw new Error("proof has unused siblings");
  return toHex(cur);
}

export async function smtVerify(keyHex: Hex, valueHex: Hex | null, proof: SmtProof, rootHex: Hex): Promise<boolean> {
  try {
    return (await smtComputeRoot(keyHex, valueHex, proof)) === rootHex;
  } catch {
    return false;
  }
}
