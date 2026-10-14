import { b64, unb64, utf8 } from "@/lib/unlock/codec";
import type { VerifiedDevice } from "@/lib/unlock/device-list";

/**
 * A device copy: an agreement's document key wrapped to one of the sender's unlock devices (RSA-OAEP with SHA-256),
 * under a label naming the agreement. The label keeps a device copy from ever being decrypted as anything else (a
 * document key wrapped to a person's key has no label, a key proof has its own), and from being presented as another
 * agreement's copy. Wrapping accepts only a device checked against the account's signed device list.
 */

export const deviceCopyLabel = (agreementId: string) => utf8(`attest.device-copy.v1|${agreementId}`);

export async function wrapToDevice(dek: Uint8Array, device: VerifiedDevice, agreementId: string): Promise<string> {
  const pub = await globalThis.crypto.subtle.importKey("spki", unb64(device.deviceKey) as unknown as BufferSource, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
  return b64(await globalThis.crypto.subtle.encrypt({ name: "RSA-OAEP", label: deviceCopyLabel(agreementId) } as RsaOaepParams, pub, dek as unknown as BufferSource));
}

export class DeviceCopyError extends Error {}

/** Open a device copy with this device's key. Throws DeviceCopyError when it isn't a copy for this agreement and key. */
export async function openDeviceCopy(wrapped: string, deviceKey: CryptoKey, agreementId: string): Promise<Uint8Array> {
  try {
    const dek = new Uint8Array(await globalThis.crypto.subtle.decrypt({ name: "RSA-OAEP", label: deviceCopyLabel(agreementId) } as RsaOaepParams, deviceKey, unb64(wrapped) as unknown as BufferSource));
    if (dek.length !== 32) throw new Error("length");
    return dek;
  } catch {
    throw new DeviceCopyError("This device copy doesn't open here.");
  }
}
