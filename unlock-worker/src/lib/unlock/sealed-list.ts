import { b64, unb64, utf8 } from "@/lib/unlock/codec";

/**
 * The signer list a sending browser seals at Send (design 3.2 B2): which addresses this agreement goes to, and for each,
 * the key this sending device had pinned for that address ("none seen" when it had none). Automatic unlocking passes
 * the document key only to people on it, and only to the pinned key where there is one, so neither a recipient Attest
 * adds nor a key it swaps in for a returning signer is ever unlocked to without a person asked.
 *
 * Sealed with AES-256-GCM under HKDF(document key, "attest.signer-list.v1"), a key used for nothing else, with the
 * agreement id as associated data. Bound to whoever holds the document key: the sender, and any signer who already has
 * a copy (who could pass the document on anyway). A list is made only at Send, from what the sender typed, never from
 * what Attest's server returns.
 */

export interface SignerListEntry {
  /** Lowercase address. */
  email: string;
  /** SHA-256 of the key this sending device pinned for the address, or null when it had seen none. */
  pinned: string | null;
}
export interface SignerList {
  v: 1;
  agreementId: string;
  /** SHA-256 of the document (hex), as the agreement names it. */
  documentSha256: string;
  signers: SignerListEntry[];
  /** When it was sealed (ISO). */
  sealedAt: string;
}
export interface SealedSignerList {
  ct: string;
  iv: string;
}

export class SignerListError extends Error {}

const SALT = "attest.signer-list.v1";

async function listKey(dek: Uint8Array): Promise<CryptoKey> {
  const base = await globalThis.crypto.subtle.importKey("raw", dek as unknown as BufferSource, "HKDF", false, ["deriveKey"]);
  return globalThis.crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: utf8(SALT) as unknown as BufferSource, info: utf8("seal") as unknown as BufferSource },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}
const aad = (agreementId: string) => utf8(`${SALT}|${agreementId}`) as unknown as BufferSource;

export async function sealSignerList(dek: Uint8Array, list: SignerList): Promise<SealedSignerList> {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ct = await globalThis.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv as unknown as BufferSource, additionalData: aad(list.agreementId) }, await listKey(dek), utf8(JSON.stringify(list)) as unknown as BufferSource);
  return { ct: b64(ct), iv: b64(iv) };
}

/** Open the list sealed for `agreementId` with its document key. Throws SignerListError if it doesn't open or isn't for it. */
export async function openSignerList(dek: Uint8Array, sealed: SealedSignerList, agreementId: string): Promise<SignerList> {
  let text: string;
  try {
    const pt = await globalThis.crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(sealed.iv) as unknown as BufferSource, additionalData: aad(agreementId) }, await listKey(dek), unb64(sealed.ct) as unknown as BufferSource);
    text = new TextDecoder().decode(pt);
  } catch {
    throw new SignerListError("The signer list doesn't open with this document's key.");
  }
  let list: SignerList;
  try {
    list = JSON.parse(text) as SignerList;
  } catch {
    throw new SignerListError("The signer list is malformed.");
  }
  if (list.v !== 1 || list.agreementId !== agreementId || !Array.isArray(list.signers)) throw new SignerListError("The signer list is for another agreement.");
  for (const s of list.signers) {
    if (typeof s.email !== "string" || (s.pinned !== null && !/^[0-9a-f]{64}$/.test(String(s.pinned)))) throw new SignerListError("The signer list is malformed.");
  }
  return list;
}
