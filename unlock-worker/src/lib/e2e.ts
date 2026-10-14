import type { VerifiedKey } from "@/lib/key-directory-client";
/**
 * Isomorphic end-to-end encryption primitives (browser + Node WebCrypto).
 *
 * Model: each user has an RSA-OAEP encryption keypair. The PRIVATE key is
 * exported and wrapped under a secret the user controls (a passkey-derived PRF
 * secret and/or a recovery phrase), then stored server-side as ciphertext only.
 * A document is encrypted once with a random AES key (the DEK); the DEK is
 * wrapped to each signer's PUBLIC key. The server never sees any private key or
 * the DEK in the clear.
 */

const subtle = globalThis.crypto.subtle;

// --- base64 (isomorphic) ---
export function b64encode(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return typeof btoa !== "undefined" ? btoa(bin) : Buffer.from(bin, "binary").toString("base64");
}
export function b64decode(s: string): Uint8Array {
  const bin = typeof atob !== "undefined" ? atob(s) : Buffer.from(s, "base64").toString("binary");
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return b;
}

// --- user encryption keypair (RSA-OAEP 2048) ---
export interface GeneratedKeypair {
  publicKeyB64: string; // spki
  privateKeyPkcs8: Uint8Array;
}
export async function generateEncryptionKeypair(): Promise<GeneratedKeypair> {
  const kp = await subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["encrypt", "decrypt"]
  );
  const pub = await subtle.exportKey("spki", kp.publicKey);
  const priv = await subtle.exportKey("pkcs8", kp.privateKey);
  return { publicKeyB64: b64encode(pub), privateKeyPkcs8: new Uint8Array(priv) };
}

// --- derive an AES-GCM wrapping key from an arbitrary secret ---
export async function deriveWrapKey(secret: Uint8Array, saltB64: string, iterations = 210000): Promise<CryptoKey> {
  const base = await subtle.importKey("raw", secret as unknown as BufferSource, "PBKDF2", false, ["deriveKey"]);
  return subtle.deriveKey(
    { name: "PBKDF2", salt: b64decode(saltB64) as unknown as BufferSource, iterations, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["wrapKey", "unwrapKey", "encrypt", "decrypt"]
  );
}

export function newSaltB64(): string {
  return b64encode(randomBytes(16));
}

// --- wrap / unwrap the private key under a wrapping key ---
export interface WrappedBlob {
  ct: string;
  iv: string;
}
export async function wrapPrivateKey(privateKeyPkcs8: Uint8Array, wrapKey: CryptoKey): Promise<WrappedBlob> {
  const iv = randomBytes(12);
  const ct = await subtle.encrypt({ name: "AES-GCM", iv: iv as unknown as BufferSource }, wrapKey, privateKeyPkcs8 as unknown as BufferSource);
  return { ct: b64encode(ct), iv: b64encode(iv) };
}
export async function unwrapPrivateKey(blob: WrappedBlob, wrapKey: CryptoKey): Promise<CryptoKey> {
  const pkcs8 = await subtle.decrypt(
    { name: "AES-GCM", iv: b64decode(blob.iv) as unknown as BufferSource },
    wrapKey,
    b64decode(blob.ct) as unknown as BufferSource
  );
  return subtle.importKey("pkcs8", pkcs8, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
}

/** Decrypt the wrapped private key to its raw PKCS#8 bytes, so it can be
 *  re-wrapped under an additional unlock method (e.g. adding a passkey to an
 *  existing key without changing the keypair). Throws if the wrap key is wrong. */
export async function unwrapPrivateKeyToPkcs8(blob: WrappedBlob, wrapKey: CryptoKey): Promise<Uint8Array> {
  const pkcs8 = await subtle.decrypt(
    { name: "AES-GCM", iv: b64decode(blob.iv) as unknown as BufferSource },
    wrapKey,
    b64decode(blob.ct) as unknown as BufferSource
  );
  return new Uint8Array(pkcs8);
}

// --- document encryption with a random DEK, and DEK wrapping to public keys ---
export async function encryptDocument(bytes: Uint8Array): Promise<{ dek: Uint8Array; ct: string; iv: string }> {
  const dek = randomBytes(32);
  const key = await subtle.importKey("raw", dek as unknown as BufferSource, "AES-GCM", false, ["encrypt"]);
  const iv = randomBytes(12);
  const ct = await subtle.encrypt({ name: "AES-GCM", iv: iv as unknown as BufferSource }, key, bytes as unknown as BufferSource);
  return { dek, ct: b64encode(ct), iv: b64encode(iv) };
}
/** Encrypt more data under an existing document key (a fresh random IV every time). */
export async function encryptWithKey(bytes: Uint8Array, dek: Uint8Array): Promise<{ ct: string; iv: string }> {
  const key = await subtle.importKey("raw", dek as unknown as BufferSource, "AES-GCM", false, ["encrypt"]);
  const iv = randomBytes(12);
  const ct = await subtle.encrypt({ name: "AES-GCM", iv: iv as unknown as BufferSource }, key, bytes as unknown as BufferSource);
  return { ct: b64encode(ct), iv: b64encode(iv) };
}
export async function decryptDocument(ctB64: string, ivB64: string, dek: Uint8Array): Promise<Uint8Array> {
  const key = await subtle.importKey("raw", dek as unknown as BufferSource, "AES-GCM", false, ["decrypt"]);
  const pt = await subtle.decrypt({ name: "AES-GCM", iv: b64decode(ivB64) as unknown as BufferSource }, key, b64decode(ctB64) as unknown as BufferSource);
  return new Uint8Array(pt);
}

/**
 * Encrypt a key to someone's public key. Only accepts a key checked against the
 * public key directory (key-directory-client verifyKeys), so nothing can be
 * encrypted to a key Attest substituted without it being on record.
 */
export async function wrapDEKToPublicKey(dek: Uint8Array, key: VerifiedKey): Promise<string> {
  const pub = await subtle.importKey("spki", b64decode(key.publicKey) as unknown as BufferSource, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
  const wrapped = await subtle.encrypt({ name: "RSA-OAEP" }, pub, dek as unknown as BufferSource);
  return b64encode(wrapped);
}
export async function unwrapDEKWithPrivateKey(wrappedB64: string, privateKey: CryptoKey): Promise<Uint8Array> {
  const dek = await subtle.decrypt({ name: "RSA-OAEP" }, privateKey, b64decode(wrappedB64) as unknown as BufferSource);
  return new Uint8Array(dek);
}

/**
 * Open a key proof (key-proof.ts): decrypt under the key-proof label only. A document key is wrapped with no label, so
 * it can never be decrypted here, whatever the server sends.
 */
export async function openKeyProof(sealedB64: string, privateKey: CryptoKey): Promise<string> {
  const label = new TextEncoder().encode("attest.key-proof.v1");
  const nonce = await subtle.decrypt({ name: "RSA-OAEP", label } as RsaOaepParams, privateKey, b64decode(sealedB64) as unknown as BufferSource);
  return b64encode(nonce);
}

// --- recovery phrase (Crockford base32, grouped) ---
const B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
export function generateRecoveryPhrase(): string {
  const bytes = randomBytes(20); // 160 bits
  let bits = "";
  for (const b of bytes) bits += b.toString(2).padStart(8, "0");
  let out = "";
  for (let i = 0; i < bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5).padEnd(5, "0"), 2)];
  return (out.match(/.{1,4}/g) ?? []).join("-");
}
export function recoveryPhraseToSecret(phrase: string): Uint8Array {
  const norm = phrase.toUpperCase().replace(/[^0-9A-Z]/g, "");
  const bytes = new Uint8Array(norm.length);
  for (let i = 0; i < norm.length; i++) bytes[i] = norm.charCodeAt(i);
  return bytes;
}

export function fingerprintPublicKey(publicKeyB64: string): string {
  // short human-comparable fingerprint of a public key
  return publicKeyB64.replace(/[^A-Za-z0-9]/g, "").slice(-16);
}

/** Import raw PKCS#8 bytes as the non-extractable, decrypt-only private key. */
export async function importPrivateKey(pkcs8: Uint8Array): Promise<CryptoKey> {
  return subtle.importKey("pkcs8", pkcs8 as unknown as BufferSource, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
}

/** Check that a private key matches a public key by a wrap/unwrap round trip. */
export async function keypairMatches(privateKey: CryptoKey, publicKeyB64: string): Promise<boolean> {
  const probe = randomBytes(32);
  try {
    // A self-test with the owner's own key: nothing is shared, so no directory check.
    const pub = await subtle.importKey("spki", b64decode(publicKeyB64) as unknown as BufferSource, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
    const out = await unwrapDEKWithPrivateKey(b64encode(await subtle.encrypt({ name: "RSA-OAEP" }, pub, probe as unknown as BufferSource)), privateKey);
    return out.length === probe.length && out.every((b, i) => b === probe[i]);
  } catch {
    return false;
  }
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const d = new Uint8Array(await subtle.digest("SHA-256", bytes as unknown as BufferSource));
  return Array.from(d, (b) => b.toString(16).padStart(2, "0")).join("");
}
