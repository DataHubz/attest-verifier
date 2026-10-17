// Renderer v3: the digests and ciphers pdf.js decrypts documents with (MD5, SHA-256/384/512, RC4 and AES, as in
// pdf.js's crypto.js), how pdf.js reads a string's bytes, and the error for a document pdf.js can't show. The standard
// security handler itself (CipherTransformFactory), and decrypting each object as it's read, are in pdfjs-v3.ts.
// Its code follows pdf.js's (Copyright Mozilla Foundation, Apache License 2.0).
//
// Everything is plain JavaScript (no WebCrypto, no Math functions whose results engines may round differently), so the
// app, the open verifier and every browser decrypt a document to the same bytes. A byte-identical copy lives in
// DataHubz/attest-verifier (src/renderer/decrypt-v3.ts).
import { PDFHexString, type PDFString } from "pdf-lib";

// ---- Digests -------------------------------------------------------------------------------------------------------

const MD5_K = new Int32Array([
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
]);
const MD5_S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];

/** MD5 (RFC 1321). */
export function md5(data: Uint8Array): Uint8Array {
  const n = data.length;
  const total = (((n + 8) >> 6) + 1) << 6;
  const m = new Uint8Array(total);
  m.set(data);
  m[n] = 0x80;
  const bits = n * 8;
  m[total - 8] = bits & 0xff;
  m[total - 7] = (bits >>> 8) & 0xff;
  m[total - 6] = (bits >>> 16) & 0xff;
  m[total - 5] = (bits >>> 24) & 0xff;
  const hi = Math.floor(n / 0x20000000);
  m[total - 4] = hi & 0xff;
  m[total - 3] = (hi >>> 8) & 0xff;
  m[total - 2] = (hi >>> 16) & 0xff;
  m[total - 1] = (hi >>> 24) & 0xff;
  let h0 = 0x67452301, h1 = 0xefcdab89 | 0, h2 = 0x98badcfe | 0, h3 = 0x10325476;
  const w = new Int32Array(16);
  for (let off = 0; off < total; off += 64) {
    for (let j = 0; j < 16; j++) w[j] = m[off + 4 * j] | (m[off + 4 * j + 1] << 8) | (m[off + 4 * j + 2] << 16) | (m[off + 4 * j + 3] << 24);
    let a = h0, b = h1, c = h2, d = h3;
    for (let i = 0; i < 64; i++) {
      let f: number, g: number;
      if (i < 16) { f = (b & c) | (~b & d); g = i; }
      else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) & 15; }
      else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) & 15; }
      else { f = c ^ (b | ~d); g = (7 * i) & 15; }
      const t = d;
      d = c;
      c = b;
      const x = (a + f + MD5_K[i] + w[g]) | 0;
      const s = MD5_S[(i >> 4) * 4 + (i & 3)];
      b = (b + ((x << s) | (x >>> (32 - s)))) | 0;
      a = t;
    }
    h0 = (h0 + a) | 0;
    h1 = (h1 + b) | 0;
    h2 = (h2 + c) | 0;
    h3 = (h3 + d) | 0;
  }
  const out = new Uint8Array(16);
  for (const [k, h] of [h0, h1, h2, h3].entries()) for (let j = 0; j < 4; j++) out[4 * k + j] = (h >>> (8 * j)) & 0xff;
  return out;
}

const SHA256_K = new Int32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

/** The message padded for SHA-2: a 1 bit, zeros, and the length in bits, big-endian, in a block of `block` bytes. */
function shaPadded(data: Uint8Array, block: number): Uint8Array {
  const n = data.length;
  const lenBytes = block === 64 ? 8 : 16;
  const total = Math.ceil((n + 1 + lenBytes) / block) * block;
  const m = new Uint8Array(total);
  m.set(data);
  m[n] = 0x80;
  const lo = (n << 3) >>> 0;
  const hi = Math.floor(n / 0x20000000);
  m[total - 8] = (hi >>> 24) & 0xff;
  m[total - 7] = (hi >>> 16) & 0xff;
  m[total - 6] = (hi >>> 8) & 0xff;
  m[total - 5] = hi & 0xff;
  m[total - 4] = (lo >>> 24) & 0xff;
  m[total - 3] = (lo >>> 16) & 0xff;
  m[total - 2] = (lo >>> 8) & 0xff;
  m[total - 1] = lo & 0xff;
  return m;
}
const be32 = (m: Uint8Array, at: number) => (m[at] << 24) | (m[at + 1] << 16) | (m[at + 2] << 8) | m[at + 3];

/** SHA-256 (FIPS 180-4). */
export function sha256(data: Uint8Array): Uint8Array {
  const m = shaPadded(data, 64);
  const h = new Int32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const w = new Int32Array(64);
  const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < m.length; off += 64) {
    for (let t = 0; t < 16; t++) w[t] = be32(m, off + 4 * t);
    for (let t = 16; t < 64; t++) {
      const s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
      const s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) | 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let t = 0; t < 64; t++) {
      const t1 = (hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + SHA256_K[t] + w[t]) | 0;
      const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
      hh = g;
      g = f;
      f = e;
      e = (d + t1) | 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) | 0;
    }
    h[0] = (h[0] + a) | 0;
    h[1] = (h[1] + b) | 0;
    h[2] = (h[2] + c) | 0;
    h[3] = (h[3] + d) | 0;
    h[4] = (h[4] + e) | 0;
    h[5] = (h[5] + f) | 0;
    h[6] = (h[6] + g) | 0;
    h[7] = (h[7] + hh) | 0;
  }
  const out = new Uint8Array(32);
  for (let k = 0; k < 8; k++) for (let j = 0; j < 4; j++) out[4 * k + j] = (h[k] >>> (24 - 8 * j)) & 0xff;
  return out;
}

const SHA512_K = [
  "428a2f98d728ae22", "7137449123ef65cd", "b5c0fbcfec4d3b2f", "e9b5dba58189dbbc", "3956c25bf348b538", "59f111f1b605d019", "923f82a4af194f9b", "ab1c5ed5da6d8118",
  "d807aa98a3030242", "12835b0145706fbe", "243185be4ee4b28c", "550c7dc3d5ffb4e2", "72be5d74f27b896f", "80deb1fe3b1696b1", "9bdc06a725c71235", "c19bf174cf692694",
  "e49b69c19ef14ad2", "efbe4786384f25e3", "0fc19dc68b8cd5b5", "240ca1cc77ac9c65", "2de92c6f592b0275", "4a7484aa6ea6e483", "5cb0a9dcbd41fbd4", "76f988da831153b5",
  "983e5152ee66dfab", "a831c66d2db43210", "b00327c898fb213f", "bf597fc7beef0ee4", "c6e00bf33da88fc2", "d5a79147930aa725", "06ca6351e003826f", "142929670a0e6e70",
  "27b70a8546d22ffc", "2e1b21385c26c926", "4d2c6dfc5ac42aed", "53380d139d95b3df", "650a73548baf63de", "766a0abb3c77b2a8", "81c2c92e47edaee6", "92722c851482353b",
  "a2bfe8a14cf10364", "a81a664bbc423001", "c24b8b70d0f89791", "c76c51a30654be30", "d192e819d6ef5218", "d69906245565a910", "f40e35855771202a", "106aa07032bbd1b8",
  "19a4c116b8d2d0c8", "1e376c085141ab53", "2748774cdf8eeb99", "34b0bcb5e19b48a8", "391c0cb3c5c95a63", "4ed8aa4ae3418acb", "5b9cca4f7763e373", "682e6ff3d6b2b8a3",
  "748f82ee5defb2fc", "78a5636f43172f60", "84c87814a1f0ab72", "8cc702081a6439ec", "90befffa23631e28", "a4506cebde82bde9", "bef9a3f7b2c67915", "c67178f2e372532b",
  "ca273eceea26619c", "d186b8c721c0c207", "eada7dd6cde0eb1e", "f57d4f7fee6ed178", "06f067aa72176fba", "0a637dc5a2c898a6", "113f9804bef90dae", "1b710b35131c471b",
  "28db77f523047d84", "32caab7b40c72493", "3c9ebe0a15c9bebc", "431d67c49c100d4c", "4cc5d4becb3e42b6", "597f299cfc657e2a", "5fcb6fab3ad6faec", "6c44198c4a475817",
];
const SHA512_KH = new Int32Array(SHA512_K.map((x) => parseInt(x.slice(0, 8), 16) | 0));
const SHA512_KL = new Int32Array(SHA512_K.map((x) => parseInt(x.slice(8), 16) | 0));
const SHA512_IV = ["6a09e667f3bcc908", "bb67ae8584caa73b", "3c6ef372fe94f82b", "a54ff53a5f1d36f1", "510e527fade682d1", "9b05688c2b3e6c1f", "1f83d9abfb41bd6b", "5be0cd19137e2179"];
const SHA384_IV = ["cbbb9d5dc1059ed8", "629a292a367cd507", "9159015a3070dd17", "152fecd8f70e5939", "67332667ffc00b31", "8eb44a8768581511", "db0c2e0d64f98fa7", "47b5481dbefa4fa4"];

/** SHA-512, or SHA-384 (FIPS 180-4), in 32-bit halves. */
function sha2_64(data: Uint8Array, mode384: boolean): Uint8Array {
  const m = shaPadded(data, 128);
  const iv = mode384 ? SHA384_IV : SHA512_IV;
  const hh = new Int32Array(iv.map((x) => parseInt(x.slice(0, 8), 16) | 0));
  const hl = new Int32Array(iv.map((x) => parseInt(x.slice(8), 16) | 0));
  const wh = new Int32Array(80), wl = new Int32Array(80);
  // Rotations and shifts of a 64-bit value (hi, lo), each half returned on its own.
  const rh = (h: number, l: number, n: number) => (n < 32 ? (h >>> n) | (l << (32 - n)) : (l >>> (n - 32)) | (h << (64 - n)));
  const rl = (h: number, l: number, n: number) => (n < 32 ? (l >>> n) | (h << (32 - n)) : (h >>> (n - 32)) | (l << (64 - n)));
  const sum = (lows: number[], highs: number[]): [number, number] => {
    let lo = 0;
    for (const x of lows) lo += x >>> 0;
    let hi = Math.floor(lo / 0x100000000);
    for (const x of highs) hi += x;
    return [hi | 0, lo | 0];
  };
  for (let off = 0; off < m.length; off += 128) {
    for (let t = 0; t < 16; t++) {
      wh[t] = be32(m, off + 8 * t);
      wl[t] = be32(m, off + 8 * t + 4);
    }
    for (let t = 16; t < 80; t++) {
      const h15 = wh[t - 15], l15 = wl[t - 15], h2 = wh[t - 2], l2 = wl[t - 2];
      const s0h = rh(h15, l15, 1) ^ rh(h15, l15, 8) ^ (h15 >>> 7);
      const s0l = rl(h15, l15, 1) ^ rl(h15, l15, 8) ^ ((l15 >>> 7) | (h15 << 25));
      const s1h = rh(h2, l2, 19) ^ rh(h2, l2, 61) ^ (h2 >>> 6);
      const s1l = rl(h2, l2, 19) ^ rl(h2, l2, 61) ^ ((l2 >>> 6) | (h2 << 26));
      [wh[t], wl[t]] = sum([s1l, wl[t - 7], s0l, wl[t - 16]], [s1h, wh[t - 7], s0h, wh[t - 16]]);
    }
    let ah = hh[0], al = hl[0], bh = hh[1], bl = hl[1], ch = hh[2], cl = hl[2], dh = hh[3], dl = hl[3];
    let eh = hh[4], el = hl[4], fh = hh[5], fl = hl[5], gh = hh[6], gl = hl[6], xh = hh[7], xl = hl[7];
    for (let t = 0; t < 80; t++) {
      const S1h = rh(eh, el, 14) ^ rh(eh, el, 18) ^ rh(eh, el, 41);
      const S1l = rl(eh, el, 14) ^ rl(eh, el, 18) ^ rl(eh, el, 41);
      const chh = (eh & fh) ^ (~eh & gh), chl = (el & fl) ^ (~el & gl);
      const [t1h, t1l] = sum([xl, S1l, chl, SHA512_KL[t], wl[t]], [xh, S1h, chh, SHA512_KH[t], wh[t]]);
      const S0h = rh(ah, al, 28) ^ rh(ah, al, 34) ^ rh(ah, al, 39);
      const S0l = rl(ah, al, 28) ^ rl(ah, al, 34) ^ rl(ah, al, 39);
      const mjh = (ah & bh) ^ (ah & ch) ^ (bh & ch), mjl = (al & bl) ^ (al & cl) ^ (bl & cl);
      const [t2h, t2l] = sum([S0l, mjl], [S0h, mjh]);
      xh = gh; xl = gl;
      gh = fh; gl = fl;
      fh = eh; fl = el;
      [eh, el] = sum([dl, t1l], [dh, t1h]);
      dh = ch; dl = cl;
      ch = bh; cl = bl;
      bh = ah; bl = al;
      [ah, al] = sum([t1l, t2l], [t1h, t2h]);
    }
    for (const [k, [vh, vl]] of [[ah, al], [bh, bl], [ch, cl], [dh, dl], [eh, el], [fh, fl], [gh, gl], [xh, xl]].entries()) [hh[k], hl[k]] = sum([hl[k], vl], [hh[k], vh]);
  }
  const words = mode384 ? 6 : 8;
  const out = new Uint8Array(words * 8);
  for (let k = 0; k < words; k++) {
    for (let j = 0; j < 4; j++) {
      out[8 * k + j] = (hh[k] >>> (24 - 8 * j)) & 0xff;
      out[8 * k + 4 + j] = (hl[k] >>> (24 - 8 * j)) & 0xff;
    }
  }
  return out;
}
export const sha512 = (data: Uint8Array) => sha2_64(data, false);
export const sha384 = (data: Uint8Array) => sha2_64(data, true);

// ---- Ciphers -------------------------------------------------------------------------------------------------------

/** RC4, as pdf.js's ARCFourCipher (its state carried from one call to the next). */
class Rc4 {
  private s = new Uint8Array(256);
  private a = 0;
  private b = 0;
  constructor(key: Uint8Array) {
    for (let i = 0; i < 256; i++) this.s[i] = i;
    const n = key.length;
    for (let i = 0, j = 0; i < 256; i++) {
      const t = this.s[i];
      j = (j + t + (n ? key[i % n] : 0)) & 0xff;
      this.s[i] = this.s[j];
      this.s[j] = t;
    }
  }
  run(data: Uint8Array): Uint8Array {
    const s = this.s;
    const out = new Uint8Array(data.length);
    let a = this.a, b = this.b;
    for (let i = 0; i < data.length; i++) {
      a = (a + 1) & 0xff;
      const t = s[a];
      b = (b + t) & 0xff;
      const t2 = s[b];
      s[a] = t2;
      s[b] = t;
      out[i] = data[i] ^ s[(t + t2) & 0xff];
    }
    this.a = a;
    this.b = b;
    return out;
  }
}
export const rc4 = (key: Uint8Array, data: Uint8Array) => new Rc4(key).run(data);

const xtime = (b: number) => ((b << 1) ^ (b & 0x80 ? 0x1b : 0)) & 0xff;
const SBOX = new Uint8Array(256);
const INV_SBOX = new Uint8Array(256);
const GF_EXP = new Uint8Array(256);
const GF_LOG = new Uint8Array(256);
{
  for (let i = 0, x = 1; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x ^= xtime(x);
  }
  for (let i = 0; i < 256; i++) {
    const inv = i === 0 ? 0 : GF_EXP[(255 - GF_LOG[i]) % 255];
    let s = inv, r = inv;
    for (let k = 0; k < 4; k++) {
      r = ((r << 1) | (r >> 7)) & 0xff;
      s ^= r;
    }
    SBOX[i] = s ^ 0x63;
    INV_SBOX[s ^ 0x63] = i;
  }
}
const gfMul = (a: number, b: number) => (a && b ? GF_EXP[(GF_LOG[a] + GF_LOG[b]) % 255] : 0);
const MUL9 = Uint8Array.from({ length: 256 }, (_, i) => gfMul(i, 9));
const MUL11 = Uint8Array.from({ length: 256 }, (_, i) => gfMul(i, 11));
const MUL13 = Uint8Array.from({ length: 256 }, (_, i) => gfMul(i, 13));
const MUL14 = Uint8Array.from({ length: 256 }, (_, i) => gfMul(i, 14));

/** AES (FIPS 197) with a 128-bit or 256-bit key, one 16-byte block at a time. */
class Aes {
  private w: Uint8Array;
  private rounds: number;
  constructor(key: Uint8Array) {
    const nk = key.length / 4;
    this.rounds = nk + 6;
    const w = new Uint8Array(16 * (this.rounds + 1));
    w.set(key);
    let rcon = 1;
    for (let i = nk; i < 4 * (this.rounds + 1); i++) {
      let t0 = w[4 * i - 4], t1 = w[4 * i - 3], t2 = w[4 * i - 2], t3 = w[4 * i - 1];
      if (i % nk === 0) {
        [t0, t1, t2, t3] = [SBOX[t1] ^ rcon, SBOX[t2], SBOX[t3], SBOX[t0]];
        rcon = xtime(rcon);
      } else if (nk > 6 && i % nk === 4) {
        [t0, t1, t2, t3] = [SBOX[t0], SBOX[t1], SBOX[t2], SBOX[t3]];
      }
      w[4 * i] = w[4 * (i - nk)] ^ t0;
      w[4 * i + 1] = w[4 * (i - nk) + 1] ^ t1;
      w[4 * i + 2] = w[4 * (i - nk) + 2] ^ t2;
      w[4 * i + 3] = w[4 * (i - nk) + 3] ^ t3;
    }
    this.w = w;
  }
  encrypt(input: Uint8Array): Uint8Array {
    const w = this.w;
    let s = new Uint8Array(16);
    for (let i = 0; i < 16; i++) s[i] = input[i] ^ w[i];
    for (let r = 1; r <= this.rounds; r++) {
      const t = new Uint8Array(16);
      for (let c = 0; c < 4; c++) for (let row = 0; row < 4; row++) t[row + 4 * c] = SBOX[s[row + 4 * ((c + row) & 3)]];
      if (r < this.rounds) {
        for (let c = 0; c < 4; c++) {
          const a0 = t[4 * c], a1 = t[4 * c + 1], a2 = t[4 * c + 2], a3 = t[4 * c + 3];
          t[4 * c] = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3;
          t[4 * c + 1] = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3;
          t[4 * c + 2] = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3;
          t[4 * c + 3] = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3);
        }
      }
      for (let i = 0; i < 16; i++) t[i] ^= w[16 * r + i];
      s = t;
    }
    return s;
  }
  decrypt(input: Uint8Array): Uint8Array {
    const w = this.w;
    let s = new Uint8Array(16);
    for (let i = 0; i < 16; i++) s[i] = input[i] ^ w[16 * this.rounds + i];
    for (let r = this.rounds - 1; r >= 0; r--) {
      const t = new Uint8Array(16);
      for (let c = 0; c < 4; c++) for (let row = 0; row < 4; row++) t[row + 4 * ((c + row) & 3)] = INV_SBOX[s[row + 4 * c]];
      for (let i = 0; i < 16; i++) t[i] ^= w[16 * r + i];
      if (r > 0) {
        for (let c = 0; c < 4; c++) {
          const a0 = t[4 * c], a1 = t[4 * c + 1], a2 = t[4 * c + 2], a3 = t[4 * c + 3];
          t[4 * c] = MUL14[a0] ^ MUL11[a1] ^ MUL13[a2] ^ MUL9[a3];
          t[4 * c + 1] = MUL9[a0] ^ MUL14[a1] ^ MUL11[a2] ^ MUL13[a3];
          t[4 * c + 2] = MUL13[a0] ^ MUL9[a1] ^ MUL14[a2] ^ MUL11[a3];
          t[4 * c + 3] = MUL11[a0] ^ MUL13[a1] ^ MUL9[a2] ^ MUL14[a3];
        }
      }
      s = t;
    }
    return s;
  }
}
/** pdf.js's AES ciphers take the key's first 16 (AES-128) or 32 (AES-256) bytes, zeros after a shorter one. */
const aesKey = (key: Uint8Array, bytes: 16 | 32) => {
  const k = new Uint8Array(bytes);
  k.set(key.subarray(0, bytes));
  return k;
};

/** AES-CBC decryption of whole blocks after an IV, with no padding removed (a 16- or 32-byte key, zeros after a shorter one). */
export function aesCbcDecryptBlocks(key: Uint8Array, size: 16 | 32, data: Uint8Array, iv: Uint8Array): Uint8Array {
  const aes = new Aes(aesKey(key, size));
  const blocks = Math.floor(data.length / 16);
  const out = new Uint8Array(blocks * 16);
  let prev = iv;
  for (let b = 0; b < blocks; b++) {
    const c = data.slice(16 * b, 16 * b + 16);
    const x = aes.decrypt(c);
    for (let i = 0; i < 16; i++) out[16 * b + i] = x[i] ^ prev[i];
    prev = c;
  }
  return out;
}

/** AES-CBC encryption without padding, as pdf.js's AESBaseCipher.encrypt: whole blocks only. */
export function aesCbcEncrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array {
  const aes = new Aes(aesKey(key, key.length > 16 ? 32 : 16));
  const blocks = Math.floor(data.length / 16);
  const out = new Uint8Array(blocks * 16);
  let prev = iv;
  for (let b = 0; b < blocks; b++) {
    const x = new Uint8Array(16);
    for (let i = 0; i < 16; i++) x[i] = data[16 * b + i] ^ prev[i];
    prev = aes.encrypt(x);
    out.set(prev, 16 * b);
  }
  return out;
}

// ---- Strings as pdf.js reads them ----------------------------------------------------------------------------------

const isOctal = (c: number) => c >= 0x30 && c <= 0x37;
/** A literal string's bytes from its text as written (between its parentheses), as pdf.js's lexer reads them. */
function literalBytes(raw: string): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < raw.length; i++) {
    const ch = raw.charCodeAt(i);
    if (ch !== 0x5c) {
      out.push(ch & 0xff);
      continue;
    }
    if (++i >= raw.length) break;
    const e = raw.charCodeAt(i);
    if (e === 0x6e) out.push(0x0a);
    else if (e === 0x72) out.push(0x0d);
    else if (e === 0x74) out.push(0x09);
    else if (e === 0x62) out.push(0x08);
    else if (e === 0x66) out.push(0x0c);
    else if (isOctal(e)) {
      let x = e & 0x0f;
      if (isOctal(raw.charCodeAt(i + 1))) {
        x = (x << 3) + (raw.charCodeAt(++i) & 0x0f);
        if (isOctal(raw.charCodeAt(i + 1))) x = (x << 3) + (raw.charCodeAt(++i) & 0x0f);
      }
      out.push(x & 0xff);
    } else if (e === 0x0d) {
      if (raw.charCodeAt(i + 1) === 0x0a) i++;
    } else if (e !== 0x0a) out.push(e & 0xff);
  }
  return Uint8Array.from(out);
}
/** A hex string's bytes from its digits as written, as pdf.js reads them: white space and other characters skipped, an odd last digit as its high half. */
function hexBytes(raw: string): Uint8Array {
  const out: number[] = [];
  let first = -1;
  for (let i = 0; i < raw.length; i++) {
    const c = raw.charCodeAt(i);
    const d = c >= 0x30 && c <= 0x39 ? c - 0x30 : c >= 0x41 && c <= 0x46 ? c - 0x37 : c >= 0x61 && c <= 0x66 ? c - 0x57 : -1;
    if (d < 0) continue;
    if (first < 0) first = d;
    else {
      out.push((first << 4) | d);
      first = -1;
    }
  }
  if (first >= 0) out.push(first << 4);
  return Uint8Array.from(out);
}
/** A string's bytes, as pdf.js reads them (literal or hex). */
export function stringBytes(s: PDFString | PDFHexString): Uint8Array {
  return s instanceof PDFHexString ? hexBytes(s.asString()) : literalBytes(s.asString());
}
// ---- Documents pdf.js can't open ------------------------------------------------------------------------------

/** Why a document can't be opened: it needs a password, its encryption is one pdf.js doesn't open, or the file can't be read. */
export class UnreadablePdf extends Error {
  constructor(readonly kind: "password" | "unsupported" | "damaged") {
    super(kind === "password" ? "A PDF that opens only with a password" : kind === "unsupported" ? "A PDF encrypted in a way pdf.js doesn't open" : "A PDF that can't be read");
  }
}
