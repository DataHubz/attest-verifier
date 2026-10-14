/**
 * Small, DOM-free helpers shared by the unlock code in pages, the service worker and the server: base64, hex digests,
 * and the text encoder. Nothing here keeps state.
 */

export const utf8 = (s: string) => new TextEncoder().encode(s);

export function b64(bytes: Uint8Array | ArrayBuffer): string {
  const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
  return btoa(s);
}

export function unb64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const hex = (b: ArrayBuffer) => Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, "0")).join("");

/** SHA-256 of UTF-8 text or of bytes, as lowercase hex. */
export async function sha256Hex(data: string | Uint8Array): Promise<string> {
  const bytes = typeof data === "string" ? utf8(data) : data;
  return hex(await globalThis.crypto.subtle.digest("SHA-256", bytes as unknown as BufferSource));
}

/** The id a device names itself with (made on the device, before Attest knows it). */
export function newDeviceId(): string {
  const B32 = "0123456789abcdefghjkmnpqrstvwxyz";
  const r = globalThis.crypto.getRandomValues(new Uint8Array(20));
  return `dev_${Array.from(r, (x) => B32[x & 31]).join("")}`;
}
export const isDeviceId = (v: unknown): v is string => typeof v === "string" && /^dev_[0-9a-hjkmnp-tv-z]{20}$/.test(v);
