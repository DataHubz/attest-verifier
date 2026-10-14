import { signText, verifyText } from "@/lib/signing-key";
import { b64, sha256Hex } from "@/lib/unlock/codec";

/**
 * Requests a device makes on its own (from the service worker, with or without a web session) are signed by its device
 * credential, a non-extractable ECDSA P-256 key made on the device. The signature covers the method, the path with its
 * query, the time, a nonce, the body's SHA-256 and the device id; the server accepts each nonce once, within
 * REQUEST_WINDOW_MS of the device's clock (src/lib/unlock/server.ts).
 */

export const REQUEST_WINDOW_MS = 5 * 60_000;

export const H_DEVICE = "x-attest-device";
export const H_TIME = "x-attest-time";
export const H_NONCE = "x-attest-nonce";
export const H_SIGNATURE = "x-attest-signature";

export const requestStatement = (r: { method: string; path: string; time: string; nonce: string; bodySha256: string; deviceId: string }) =>
  ["attest.device-request.v1", r.method.toUpperCase(), r.path, r.time, r.nonce, r.bodySha256, r.deviceId].join("\n");

/** The headers that sign one request. `path` is the path with its query string, exactly as sent. */
export async function signDeviceRequest(credential: CryptoKey, deviceId: string, method: string, path: string, body = ""): Promise<Record<string, string>> {
  const time = String(Date.now());
  const nonce = b64(globalThis.crypto.getRandomValues(new Uint8Array(18)));
  const signature = await signText(credential, requestStatement({ method, path, time, nonce, bodySha256: await sha256Hex(body), deviceId }));
  return { [H_DEVICE]: deviceId, [H_TIME]: time, [H_NONCE]: nonce, [H_SIGNATURE]: signature };
}

/** Whether the headers are the credential's signature of this request (time and nonce are checked by the caller). */
export async function verifyDeviceRequest(credentialSpki: string, h: { deviceId: string; time: string; nonce: string; signature: string }, method: string, path: string, body: string): Promise<boolean> {
  if (!/^\d{10,16}$/.test(h.time) || !/^[A-Za-z0-9+/]{24}$/.test(h.nonce)) return false;
  return verifyText(credentialSpki, h.signature, requestStatement({ method, path, time: h.time, nonce: h.nonce, bodySha256: await sha256Hex(body), deviceId: h.deviceId }));
}
