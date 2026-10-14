/**
 * Every account's signing key: an ECDSA P-256 key pair (WebCrypto, so every browser and the service worker have it),
 * made in the owner's browser the first time their key is unlocked. It signs what only its owner may say. Today that
 * is the list of the owner's devices that unlock documents for new signers (src/lib/unlock/device-list.ts): a list
 * Attest can't extend or roll back, because Attest never has the private key.
 *
 * The private key is protected exactly like the encryption key: it is encrypted (AES-256-GCM) under a key derived with
 * HKDF from the encryption private key itself, so whatever unlocks the encryption key (a passkey, the recovery phrase)
 * unlocks this one, nothing else does, and Attest stores only ciphertext. Opening it also proves the public key Attest
 * serves for it: the ciphertext names the public key as associated data, and a probe signed with the opened key must
 * verify under it, so a key pair Attest made can't be passed off as the owner's.
 *
 * Its public key is stored with the account and pinned by each device that unlocks automatically. It joins the public
 * key directory (and the confirmation email, and safety numbers) with email-confirmed keys; until then, the directory
 * lists the encryption key alone, as before.
 *
 * Shared by the browser, the service worker and the server.
 */

const subtle = () => globalThis.crypto.subtle;
const enc = (s: string) => new TextEncoder().encode(s);

export function b64(bytes: Uint8Array | ArrayBuffer): string {
  const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (const b of u) s += String.fromCharCode(b);
  return btoa(s);
}
export function unb64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ---- the private key, wrapped under the encryption key ---------------------------------------------------------------

export interface WrappedSigningKey {
  ct: string;
  iv: string;
}

/** The AES key the signing key is wrapped under: HKDF-SHA-256 from the RSA private exponent of the encryption key. */
async function wrapKeyFrom(encPkcs8: Uint8Array): Promise<CryptoKey> {
  const rsa = await subtle().importKey("pkcs8", encPkcs8 as unknown as BufferSource, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt"]);
  const d = (await subtle().exportKey("jwk", rsa)).d!;
  const raw = unb64(d.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (d.length % 4)) % 4));
  const base = await subtle().importKey("raw", raw as unknown as BufferSource, "HKDF", false, ["deriveKey"]);
  return subtle().deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: enc("attest.signing-key.v1") as unknown as BufferSource, info: enc("wrap") as unknown as BufferSource },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/** A new signing key for the encryption key whose private half is `encPkcs8`: its public key and its wrapped private key. */
export async function newSigningKey(encPkcs8: Uint8Array): Promise<{ signPublicKey: string; wrapped: WrappedSigningKey }> {
  const kp = (await subtle().generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const spki = new Uint8Array(await subtle().exportKey("spki", kp.publicKey));
  const pkcs8 = new Uint8Array(await subtle().exportKey("pkcs8", kp.privateKey));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle().encrypt(
    { name: "AES-GCM", iv: iv as unknown as BufferSource, additionalData: enc(`attest.signing-key.v1|${b64(spki)}`) as unknown as BufferSource },
    await wrapKeyFrom(encPkcs8),
    pkcs8 as unknown as BufferSource
  );
  return { signPublicKey: b64(spki), wrapped: { ct: b64(ct), iv: b64(iv) } };
}

export class SigningKeyError extends Error {}

/**
 * Open the signing key with the unlocked encryption key, and check it is the private half of `signPublicKey` (a probe
 * signed and verified). Throws SigningKeyError when it doesn't open or doesn't match: a wrap Attest made can't open.
 * The key comes back non-extractable, for signing only.
 */
export async function openSigningKey(encPkcs8: Uint8Array, signPublicKey: string, wrapped: WrappedSigningKey): Promise<CryptoKey> {
  let pkcs8: ArrayBuffer;
  try {
    pkcs8 = await subtle().decrypt(
      { name: "AES-GCM", iv: unb64(wrapped.iv) as unknown as BufferSource, additionalData: enc(`attest.signing-key.v1|${signPublicKey}`) as unknown as BufferSource },
      await wrapKeyFrom(encPkcs8),
      unb64(wrapped.ct) as unknown as BufferSource
    );
  } catch {
    throw new SigningKeyError("Your signing key doesn't open with your key.");
  }
  const key = await subtle().importKey("pkcs8", pkcs8, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const probe = `attest.signing-key.probe|${signPublicKey}`;
  if (!(await verifyText(signPublicKey, await signText(key, probe), probe))) {
    throw new SigningKeyError("Your signing key isn't the one your account lists.");
  }
  return key;
}

// ---- statements -----------------------------------------------------------------------------------------------------

const P256_N = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
const toHex = (u: Uint8Array) => Array.from(u, (b) => b.toString(16).padStart(2, "0")).join("");

/**
 * The one form of an ECDSA signature: (r, s) and (r, n - s) both verify, so a signature is kept with the smaller s.
 * What anyone commits to (the signature's hash) is then the same whichever form is handed around.
 */
export function canonicalSignature(signature: string): string {
  const sig = unb64(signature);
  if (sig.length !== 64) return signature;
  const s = BigInt(`0x${toHex(sig.slice(32))}`);
  if (s <= P256_N / BigInt(2)) return signature;
  const low = (P256_N - s).toString(16).padStart(64, "0");
  const out = new Uint8Array(64);
  out.set(sig.slice(0, 32));
  for (let i = 0; i < 32; i++) out[32 + i] = parseInt(low.slice(i * 2, i * 2 + 2), 16);
  return b64(out);
}

/** Sign a statement (UTF-8 text): ECDSA P-256 with SHA-256, r || s (64 bytes) in its canonical form, base64. */
export async function signText(key: CryptoKey, text: string): Promise<string> {
  return canonicalSignature(b64(await subtle().sign({ name: "ECDSA", hash: "SHA-256" }, key, enc(text) as unknown as BufferSource)));
}

/** Whether `signature` is `signPublicKey`'s signature of `text`. Never throws. */
export async function verifyText(signPublicKey: string, signature: string, text: string): Promise<boolean> {
  try {
    const sig = unb64(signature);
    if (sig.length !== 64) return false;
    const key = await subtle().importKey("spki", unb64(signPublicKey) as unknown as BufferSource, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    return await subtle().verify({ name: "ECDSA", hash: "SHA-256" }, key, sig as unknown as BufferSource, enc(text) as unknown as BufferSource);
  } catch {
    return false;
  }
}

const B64 = /^[A-Za-z0-9+/]+={0,2}$/;
/** A plausible base64 public key or ciphertext (no more than `max` characters). */
export const isB64 = (v: unknown, max = 4000): v is string => typeof v === "string" && v.length > 0 && v.length <= max && B64.test(v);
