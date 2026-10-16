// Renderer v3: opening an encrypted document exactly as pdf.js opens it for the signer.
//
// pdf.js opens a document encrypted with the standard security handler without asking for a password when its user
// password is empty (an owner password only, as government forms are protected): RC4 40 to 128 bits (V 1 and 2), RC4
// or AES-128 through crypt filters (V 4), and AES-256 (V 5, revisions 5 and 6). It decrypts every string and stream of
// every object it reads from the file, and nothing inside an object stream (the stream itself is decrypted). This file
// does the same, with pdf.js's own rules (CipherTransformFactory, CipherTransform, DecryptStream and the AES and RC4
// ciphers in pdf.js's crypto.js, which it follows step for step, including how pdf.js reads a string's bytes, removes
// AES padding and feeds a stream to its cipher 512 bytes at a time), and gives renderer v3 the decrypted document. A
// document pdf.js opens only with a password, or doesn't open at all, can't be decrypted here either.
//
// Everything is plain JavaScript (no WebCrypto, no Math functions whose results engines may round differently), so the
// app, the open verifier and every browser decrypt a document to the same bytes. A byte-identical copy lives in
// DataHubz/attest-verifier (src/renderer/decrypt-v3.ts).
import { PDFArray, PDFBool, PDFDict, PDFDocument, PDFHexString, PDFName, PDFNumber, PDFParser, PDFRawStream, PDFRef, PDFString, ParseSpeeds, type PDFContext, type PDFObject } from "pdf-lib";

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

/**
 * AES-CBC decryption as pdf.js does it (AESBaseCipher.decryptBlock): the first 16 bytes are the IV (nothing comes out
 * of less); a partial last block is dropped; and the padding of the last block the final call decrypts is removed when
 * every padding byte is right. A stream is fed to it as pdf.js's DecryptStream feeds it, 512 bytes at a time, so a
 * stream whose last piece holds no whole block keeps the padding of the block before; a string comes in one piece.
 * The key's length picks AES-128 (16 bytes) or AES-256 (32 bytes).
 */
export function aesDecryptLikePdfjs(key: Uint8Array, data: Uint8Array, stream: boolean): Uint8Array {
  const aes = new Aes(key);
  const pieces: Uint8Array[] = [];
  if (stream) for (let at = 0; at < data.length; at += 512) pieces.push(data.subarray(at, at + 512));
  else pieces.push(data);
  const out: Uint8Array[] = [];
  let iv: Uint8Array | null = null;
  for (const [k, piece] of pieces.entries()) {
    let p = piece;
    if (!iv) {
      if (p.length < 16) continue;
      iv = p.slice(0, 16);
      p = p.subarray(16);
    }
    const blocks = Math.floor(p.length / 16);
    if (!blocks) continue;
    const res = new Uint8Array(blocks * 16);
    for (let b = 0; b < blocks; b++) {
      const c = p.slice(16 * b, 16 * b + 16);
      const x = aes.decrypt(c);
      for (let i = 0; i < 16; i++) res[16 * b + i] = x[i] ^ iv[i];
      iv = c;
    }
    let len = res.length;
    if (k === pieces.length - 1) {
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
    out.push(res.subarray(0, len));
  }
  const total = out.reduce((n, x) => n + x.length, 0);
  const all = new Uint8Array(total);
  let at = 0;
  for (const x of out) {
    all.set(x, at);
    at += x.length;
  }
  return all;
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
/** The same kind of string, holding these bytes (a literal one with every byte that needs it escaped). */
function stringOf(kind: PDFString | PDFHexString, bytes: Uint8Array): PDFString | PDFHexString {
  if (kind instanceof PDFHexString) {
    let hex = "";
    for (const b of bytes) hex += (b < 16 ? "0" : "") + b.toString(16).toUpperCase();
    return PDFHexString.of(hex);
  }
  let text = "";
  for (const b of bytes) {
    if (b === 0x28 || b === 0x29 || b === 0x5c) text += "\\" + String.fromCharCode(b);
    else if (b < 0x20 || b > 0x7e) text += "\\" + b.toString(8).padStart(3, "0");
    else text += String.fromCharCode(b);
  }
  return PDFString.of(text);
}

// ---- The standard security handler, as pdf.js reads it ---------------------------------------------------------------

/** Why a document can't be opened: it needs a password, its encryption is one pdf.js doesn't open, or the file can't be read. */
export class UnreadablePdf extends Error {
  constructor(readonly kind: "password" | "unsupported" | "damaged") {
    super(kind === "password" ? "A PDF that opens only with a password" : kind === "unsupported" ? "A PDF encrypted in a way pdf.js doesn't open" : "A PDF that can't be read");
  }
}

/** The 32 bytes that pad a password (ISO 32000, 7.6.4.3). */
const PAD = Uint8Array.from([0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41, 0x64, 0x00, 0x4e, 0x56, 0xff, 0xfa, 0x01, 0x08, 0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80, 0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a]);
const concat = (...parts: (Uint8Array | number[])[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
};
/** pdf.js reads `length` bytes from `data`, as zeros past its end. */
const firstBytes = (data: Uint8Array, length: number) => {
  const out = new Uint8Array(length);
  out.set(data.subarray(0, length));
  return out;
};

/** The file key of an RC4 or AES-128 document with an empty user password (pdf.js's #prepareKeyData), or null. */
function keyFromEmptyPassword(fileId: Uint8Array, owner: Uint8Array, user: Uint8Array, flags: number, revision: number | undefined, keyLength: number, encryptMetadata: boolean): Uint8Array | null {
  const r = revision ?? 0;
  const parts: (Uint8Array | number[])[] = [PAD, owner, [flags & 0xff, (flags >> 8) & 0xff, (flags >> 16) & 0xff, (flags >>> 24) & 0xff], fileId];
  if (r >= 4 && !encryptMetadata) parts.push([0xff, 0xff, 0xff, 0xff]);
  let hash = md5(concat(...parts));
  const bytes = keyLength >> 3;
  if (r >= 3) for (let j = 0; j < 50; j++) hash = md5(firstBytes(hash, bytes));
  const key = hash.subarray(0, bytes);
  let check: Uint8Array;
  if (r >= 3) {
    check = rc4(key, md5(concat(PAD, fileId)));
    const derived = new Uint8Array(key.length);
    for (let j = 1; j <= 19; j++) {
      for (let k = 0; k < key.length; k++) derived[k] = key[k] ^ j;
      check = rc4(derived, check);
    }
  } else check = rc4(key, PAD);
  return check.every((b, k) => user[k] === b) ? key : null;
}

/** The hash of revisions 5 (SHA-256) and 6 (ISO 32000-2's iterated hash), as pdf.js's PDF17 and PDF20 compute it. */
function hash2(revision6: boolean, password: Uint8Array, input: Uint8Array, userBytes: Uint8Array): Uint8Array {
  if (!revision6) return sha256(input);
  let k = sha256(input);
  let e: Uint8Array = Uint8Array.from([0]);
  for (let i = 0; i < 64 || e[e.length - 1] > i - 32; i++) {
    const once = concat(password, k, userBytes);
    const k1 = new Uint8Array(once.length * 64);
    for (let j = 0; j < 64; j++) k1.set(once, j * once.length);
    e = aesCbcEncrypt(k.subarray(0, 16), k.subarray(16, 32), k1);
    let sum = 0;
    for (let j = 0; j < 16; j++) sum += e[j];
    const pick = sum % 3;
    k = pick === 0 ? sha256(e) : pick === 1 ? sha384(e) : sha512(e);
  }
  return k.subarray(0, 32);
}

/** The file key of an AES-256 document with an empty user password (pdf.js's #createEncryptionKey20), or null. */
function keyFromEmptyPassword20(revision: number | undefined, user: Uint8Array, userEncryption: Uint8Array): Uint8Array | null {
  const r6 = revision === 6;
  const empty = new Uint8Array(0);
  const check = hash2(r6, empty, user.subarray(32, 40), empty);
  const stored = user.subarray(0, 32);
  if (check.length !== stored.length || !check.every((b, i) => b === stored[i])) return null;
  const k = hash2(r6, empty, user.subarray(40, 48), empty);
  // AES-256 decryption of UE with a zero IV and no padding removed.
  const aes = new Aes(aesKey(k, 32));
  const blocks = Math.floor(userEncryption.length / 16);
  const out = new Uint8Array(blocks * 16);
  let iv = new Uint8Array(16);
  for (let b = 0; b < blocks; b++) {
    const c = userEncryption.slice(16 * b, 16 * b + 16);
    const x = aes.decrypt(c);
    for (let i = 0; i < 16; i++) out[16 * b + i] = x[i] ^ iv[i];
    iv = c;
  }
  return out;
}

type Cipher = ((data: Uint8Array, stream: boolean) => Uint8Array) | null;

/** What decrypts each object's strings and streams, as pdf.js's CipherTransform does for that object. */
interface Decryption {
  /** The cipher for a crypt filter name (null: the default for strings or streams), for the object numbered num, gen. */
  cipher(kind: "string" | "stream" | "embedded" | { name: string }, num: number, gen: number): Cipher;
}

/** The standard security handler with an empty user password, as pdf.js's CipherTransformFactory reads it. */
function standardHandler(pdf: PDFContext, dict: PDFDict, fileId: Uint8Array): Decryption {
  const look = (v: unknown) => (v instanceof PDFRef ? pdf.lookup(v) : v);
  const get = (d: PDFDict, key: string) => look(d.get(PDFName.of(key)));
  const num = (v: unknown) => (v instanceof PDFNumber ? v.asNumber() : undefined);
  const nameOf = (v: unknown) => (v instanceof PDFName ? v.decodeText() : undefined);
  const str = (v: unknown) => (v instanceof PDFString || v instanceof PDFHexString ? stringBytes(v) : undefined);
  if (nameOf(get(dict, "Filter")) !== "Standard") throw new UnreadablePdf("unsupported");
  const v = num(get(dict, "V"));
  if (v === undefined || !Number.isInteger(v) || ![1, 2, 4, 5].includes(v)) throw new UnreadablePdf("unsupported");
  const cf = v >= 4 ? get(dict, "CF") : undefined;
  let keyLength = num(get(dict, "Length"));
  if (!keyLength) {
    if (v <= 3) keyLength = 40;
    else {
      const stm = nameOf(get(dict, "StmF"));
      if (cf instanceof PDFDict && stm !== undefined) {
        const handler = look(cf.get(PDFName.of(stm)));
        keyLength = (handler instanceof PDFDict ? num(get(handler, "Length")) : undefined) || 128;
        if (keyLength < 40) keyLength <<= 3;
      }
    }
  }
  if (keyLength === undefined || !Number.isInteger(keyLength) || keyLength < 40 || keyLength % 8 !== 0) throw new UnreadablePdf("unsupported");
  // Crypt filter names: Identity unless the dictionary names one.
  const filterName = (key: string, dflt: string) => {
    const x = get(dict, key);
    if (x === undefined) return dflt;
    const n = nameOf(x);
    if (n === undefined) throw new UnreadablePdf("unsupported");
    return n;
  };
  const stmf = v >= 4 ? filterName("StmF", "Identity") : "Identity";
  const strf = v >= 4 ? filterName("StrF", "Identity") : "Identity";
  const eff = v >= 4 ? filterName("EFF", stmf) : stmf;
  if (v >= 4 && !(cf instanceof PDFDict)) throw new UnreadablePdf("unsupported");
  const ownerBytes = str(get(dict, "O")), userBytes = str(get(dict, "U"));
  if (!ownerBytes || !userBytes) throw new UnreadablePdf("unsupported");
  const owner = ownerBytes.subarray(0, 32), user = userBytes.subarray(0, 32);
  const p = get(dict, "P");
  const flags = p instanceof PDFNumber ? p.asNumber() : 0;
  const revision = num(get(dict, "R"));
  const em = get(dict, "EncryptMetadata");
  const encryptMetadata = (v === 4 || v === 5) && !(em instanceof PDFBool && !em.asBoolean());
  let key: Uint8Array | null;
  if (v !== 5) key = keyFromEmptyPassword(fileId, owner, user, flags, revision, keyLength, encryptMetadata);
  else {
    const ue = str(get(dict, "UE"));
    if (!ue) throw new UnreadablePdf("unsupported");
    key = keyFromEmptyPassword20(revision, userBytes.subarray(0, 48), ue);
  }
  if (!key) {
    // Only embedded files are encrypted, and they open with a password: everything else reads as it is.
    const effFilter = cf instanceof PDFDict ? look(cf.get(PDFName.of(eff))) : undefined;
    if (!(v >= 4 && stmf === "Identity" && strf === "Identity" && effFilter instanceof PDFDict && nameOf(get(effFilter, "AuthEvent")) === "EFOpen")) throw new UnreadablePdf("password");
  } else if (v === 4 && key.length < 16) key = firstBytes(key, 16);
  const fileKey = key;
  /** The object's own key (pdf.js's #buildObjectKey). */
  const objectKey = (n: number, g: number, aes: boolean) => {
    if (!fileKey) return null;
    const parts: (Uint8Array | number[])[] = [fileKey, [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, g & 0xff, (g >> 8) & 0xff]];
    if (aes) parts.push([0x73, 0x41, 0x6c, 0x54]);
    return md5(concat(...parts)).subarray(0, Math.min(fileKey.length + 5, 16));
  };
  const resolve = (name: string, n: number, g: number): Cipher => {
    if (v < 4) {
      const k = objectKey(n, g, false);
      return k ? (data) => rc4(k, data) : null;
    }
    const filter = cf instanceof PDFDict ? look(cf.get(PDFName.of(name))) : undefined;
    const cfm = filter instanceof PDFDict ? nameOf(get(filter, "CFM")) : undefined;
    if (!cfm || cfm === "None") return (data) => data;
    if (!fileKey) return null;
    if (v === 5 || cfm === "AESV3") {
      const k = aesKey(fileKey, 32);
      return (data, stream) => aesDecryptLikePdfjs(k, data, stream);
    }
    if (cfm === "V2") {
      const k = objectKey(n, g, false)!;
      return (data) => rc4(k, data);
    }
    if (cfm === "AESV2") {
      const k = aesKey(objectKey(n, g, true)!, 16);
      return (data, stream) => aesDecryptLikePdfjs(k, data, stream);
    }
    return null;
  };
  // A crypt method pdf.js doesn't know, for strings or streams: it can't read any object.
  for (const name of [stmf, strf]) {
    const filter = cf instanceof PDFDict ? look(cf.get(PDFName.of(name))) : undefined;
    const cfm = filter instanceof PDFDict ? nameOf(get(filter, "CFM")) : undefined;
    if (v >= 4 && cfm && !["None", "V2", "AESV2", "AESV3"].includes(cfm)) throw new UnreadablePdf("unsupported");
  }
  return {
    cipher(kind, n, g) {
      const name = typeof kind === "object" ? kind.name : kind === "string" ? strf : kind === "embedded" ? eff : stmf;
      return resolve(name, n, g);
    },
  };
}

// ---- Decrypting a document as it's read ------------------------------------------------------------------------------

/** Every string in an object, decrypted in place (a dictionary's or array's values), or the string itself decrypted. */
function decryptStrings(o: PDFObject, cipher: Cipher): PDFObject {
  if (!cipher) return o;
  if (o instanceof PDFString || o instanceof PDFHexString) return stringOf(o, cipher(stringBytes(o), false));
  if (o instanceof PDFDict) {
    for (const [k, x] of o.entries()) {
      const d = decryptStrings(x, cipher);
      if (d !== x) o.set(k, d);
    }
  } else if (o instanceof PDFArray) {
    for (let i = 0; i < o.size(); i++) {
      const x = o.get(i);
      const d = decryptStrings(x, cipher);
      if (d !== x) o.set(i, d);
    }
  }
  return o;
}

/** A stream's bytes decrypted as pdf.js decrypts them: by its crypt filter if it names one first, else the default for streams (or embedded files). */
function decryptStream(s: PDFRawStream, d: Decryption, n: number, g: number): PDFRawStream {
  const dict = s.dict;
  const filterValue = dict.get(PDFName.of("Filter"));
  const filters = filterValue instanceof PDFArray ? filterValue.asArray() : filterValue === undefined ? [] : [filterValue];
  const crypt = filters.findIndex((f) => f instanceof PDFName && f.decodeText() === "Crypt");
  let cipher: Cipher;
  if (crypt < 0) {
    const type = dict.get(PDFName.of("Type"));
    cipher = d.cipher(type instanceof PDFName && type.decodeText() === "EmbeddedFile" ? "embedded" : "stream", n, g);
    return cipher ? PDFRawStream.of(dict, cipher(s.contents, true)) : s;
  }
  // A crypt filter: pdf.js decrypts with the one it names (Identity by default), in its place among the filters. Only
  // first is it the stream's own bytes it decrypts: elsewhere the stream is kept as it is.
  if (crypt > 0) return s;
  const parmsValue = dict.get(PDFName.of("DecodeParms"));
  const parms = parmsValue instanceof PDFArray ? parmsValue.get(0) : parmsValue;
  const nameValue = parms instanceof PDFDict ? parms.get(PDFName.of("Name")) : undefined;
  cipher = d.cipher({ name: nameValue instanceof PDFName ? nameValue.decodeText() : "Identity" }, n, g);
  if (!cipher) return s;
  const out = PDFRawStream.of(dict, cipher(s.contents, true));
  if (filterValue instanceof PDFArray && filterValue.size() > 1) {
    filterValue.remove(0);
    if (parmsValue instanceof PDFArray && parmsValue.size() > 0) parmsValue.remove(0);
  } else {
    dict.delete(PDFName.of("Filter"));
    dict.delete(PDFName.of("DecodeParms"));
  }
  return out;
}

interface ParserInternals {
  parseIndirectObjectHeader(): PDFRef;
  parseIndirectObject(): Promise<PDFRef>;
  parseObject(): PDFObject;
  parseDocument(): Promise<PDFContext>;
}

/**
 * The document, decrypted if it's encrypted, as pdf.js opens it for the signer. Throws UnreadablePdf when pdf.js would
 * need a password or doesn't open its encryption, and pdf-lib's own error when the file can't be read.
 */
export async function openOriginalV3(bytes: Uint8Array): Promise<PDFDocument> {
  const first = await PDFDocument.load(bytes, { updateMetadata: false, ignoreEncryption: true });
  if (!first.isEncrypted) return first;
  const ctx = first.context;
  const encryptRef = ctx.trailerInfo.Encrypt;
  const encrypt = encryptRef instanceof PDFRef ? ctx.lookup(encryptRef) : encryptRef;
  if (!(encrypt instanceof PDFDict)) throw new UnreadablePdf("damaged");
  const ids = ctx.trailerInfo.ID instanceof PDFRef ? ctx.lookup(ctx.trailerInfo.ID) : ctx.trailerInfo.ID;
  const id0 = ids instanceof PDFArray && ids.size() ? ids.get(0) : undefined;
  const fileId = id0 instanceof PDFString || id0 instanceof PDFHexString ? stringBytes(id0) : new Uint8Array(0);
  const handler = standardHandler(ctx, encrypt, fileId);
  // Objects pdf.js reads without decrypting: the encryption dictionary and what it refers to.
  const plain = new Set<string>();
  const keep = (v: unknown) => {
    if (v instanceof PDFRef) plain.add(`${v.objectNumber} ${v.generationNumber}`);
  };
  keep(encryptRef);
  for (const [, x] of encrypt.entries()) keep(x);
  const cf = encrypt.get(PDFName.of("CF"));
  const cfDict = cf instanceof PDFRef ? ctx.lookup(cf) : cf;
  if (cfDict instanceof PDFDict) for (const [, x] of cfDict.entries()) keep(x);

  // Read again, decrypting each indirect object as it's read (pdf-lib's own parser, so objects are kept exactly as
  // for any other document); an object stream is decrypted before the objects in it are read, and they aren't.
  const parser = PDFParser.forBytesWithOptions(bytes, ParseSpeeds.Slow, false, false) as unknown as ParserInternals;
  const header = parser.parseIndirectObjectHeader.bind(parser);
  const object = parser.parseObject.bind(parser);
  const indirect = parser.parseIndirectObject.bind(parser);
  let current: PDFRef | null = null;
  let inObject = false;
  let depth = 0;
  parser.parseIndirectObjectHeader = () => {
    const ref = header();
    current = ref;
    return ref;
  };
  parser.parseIndirectObject = async () => {
    inObject = true;
    try {
      return await indirect();
    } finally {
      inObject = false;
      current = null;
    }
  };
  parser.parseObject = () => {
    depth++;
    let o: PDFObject;
    try {
      o = object();
    } finally {
      depth--;
    }
    if (depth !== 0 || !inObject || !current) return o;
    const ref: PDFRef = current;
    current = null;
    if (plain.has(`${ref.objectNumber} ${ref.generationNumber}`)) return o;
    const n = ref.objectNumber, g = ref.generationNumber;
    if (o instanceof PDFRawStream) {
      const type = o.dict.get(PDFName.of("Type"));
      // A cross-reference stream isn't encrypted.
      if (type instanceof PDFName && type.decodeText() === "XRef") return o;
      decryptStrings(o.dict, handler.cipher("string", n, g));
      return decryptStream(o, handler, n, g);
    }
    return decryptStrings(o, handler.cipher("string", n, g));
  };
  const context = await parser.parseDocument();
  if (encryptRef instanceof PDFRef) context.delete(encryptRef);
  context.trailerInfo.Encrypt = undefined;
  const Doc = PDFDocument as unknown as new (context: PDFContext, ignoreEncryption: boolean, updateMetadata: boolean) => PDFDocument;
  return new Doc(context, true, false);
}
