import { canonicalJson } from "@/lib/canonical-json";
import { signText, verifyText } from "@/lib/signing-key";
import { isDeviceId, sha256Hex } from "@/lib/unlock/codec";

/**
 * The signed device list (design 3.2 A3): the versioned record of the devices that unlock documents for an account's
 * new signers, signed by the account's signing key (src/lib/signing-key.ts), which Attest never holds. Each entry names
 * a device by the hashes of its own keys (the device key, RSA-OAEP, that device copies are wrapped to; the device
 * credential, ECDSA P-256, that signs its requests) and expires 60 days after it was signed. The list names the account
 * key it belongs to, so a key reset turns every device off whatever the server says.
 *
 * Every device that verified a list remembers its version, and each enrolled device pins the signing key. A list that
 * doesn't verify, or is older than one seen, is refused with the alarm: Attest can neither add a device of its own nor
 * bring back one that was turned off.
 */

export const ENTRY_DAYS = 60;
const DAY = 86_400_000;
/** Entries are renewed at a passkey prompt once the soonest expiry is closer than this. */
export const RENEW_WHEN_DAYS_LEFT = 50;
/** A device unused this long is turned off at the next renewal (the server stops serving it at once). */
export const INACTIVE_DAYS = 90;

export interface DeviceEntry {
  id: string;
  /** SHA-256 (hex) of the device key's SPKI in base64: the key device copies are wrapped to. */
  key: string;
  /** SHA-256 (hex) of the device credential's SPKI in base64: the key that signs the device's requests. */
  credential: string;
  /** When this entry was signed (ISO). */
  issued: string;
  /** When it stops counting (ISO): ENTRY_DAYS after it was signed. */
  expires: string;
}
export interface DeviceList {
  v: 1;
  /** SHA-256 (hex) of the account's encryption public key (SPKI, base64): the key this list belongs to. */
  account: string;
  /** SHA-256 (hex) of the signing public key that signs this list. */
  signer: string;
  /** Strictly increasing with each list the account publishes. */
  version: number;
  issued: string;
  devices: DeviceEntry[];
}
export interface SignedDeviceList {
  body: string;
  signature: string;
}

const PREFIX = "attest.device-list.v1|";

export type DeviceListProblem = "malformed" | "signature" | "account" | "rollback";
export class DeviceListError extends Error {
  constructor(public readonly problem: DeviceListProblem, message: string) {
    super(message);
  }
}

const HEX64 = /^[0-9a-f]{64}$/;
const isIso = (v: unknown): v is string => typeof v === "string" && !Number.isNaN(Date.parse(v));

/** The list in `body`, if it has the right shape (no signature check). */
export function parseDeviceList(body: string): DeviceList | null {
  let v: DeviceList;
  try {
    v = JSON.parse(body) as DeviceList;
  } catch {
    return null;
  }
  if (!v || v.v !== 1 || !HEX64.test(String(v.account)) || !HEX64.test(String(v.signer)) || !Number.isInteger(v.version) || v.version < 1 || !isIso(v.issued) || !Array.isArray(v.devices)) return null;
  if (v.devices.length > 50) return null;
  const ids = new Set<string>();
  for (const d of v.devices) {
    if (!d || !isDeviceId(d.id) || ids.has(d.id) || !HEX64.test(String(d.key)) || !HEX64.test(String(d.credential)) || !isIso(d.issued) || !isIso(d.expires)) return null;
    ids.add(d.id);
  }
  // Signed bodies are canonical: anything else isn't a list a browser made.
  if (canonicalJson(v) !== body) return null;
  return v;
}

export async function signDeviceList(signingKey: CryptoKey, list: DeviceList): Promise<SignedDeviceList> {
  const body = canonicalJson(list);
  return { body, signature: await signText(signingKey, PREFIX + body) };
}

/**
 * Verify a signed list against the account's signing public key (pinned on an enrolled device, or opened with the
 * account key) and the account key it must belong to. `minVersion`: the newest version this device has seen; an older
 * list is a rollback. Throws DeviceListError.
 */
export async function verifyDeviceList(signed: SignedDeviceList, signPublicKey: string, opts: { account: string; minVersion?: number }): Promise<DeviceList> {
  const list = parseDeviceList(signed.body);
  if (!list) throw new DeviceListError("malformed", "The device list is malformed.");
  if (list.signer !== (await sha256Hex(signPublicKey)) || !(await verifyText(signPublicKey, signed.signature, PREFIX + signed.body))) {
    throw new DeviceListError("signature", "The device list isn't signed by this account's signing key.");
  }
  if (list.account !== opts.account) throw new DeviceListError("account", "The device list belongs to another key of this account.");
  if (opts.minVersion !== undefined && list.version < opts.minVersion) throw new DeviceListError("rollback", `The device list is older (version ${list.version}) than one this device has seen (version ${opts.minVersion}).`);
  return list;
}

/** Entries still counting at `now`. */
export const liveEntries = (list: DeviceList, now = Date.now()) => list.devices.filter((d) => Date.parse(d.expires) > now && Date.parse(d.issued) <= now + 5 * 60_000);

declare const checked: unique symbol;
/** A device whose key was checked against a verified list: device copies are wrapped only to these. */
export type VerifiedDevice = { readonly id: string; readonly deviceKey: string; readonly keyFp: string; readonly expires: string; readonly [checked]: true };

/**
 * The devices a document key may be wrapped to: every live entry of a verified list whose device key, as Attest serves
 * it, hashes to the key the entry names. A device Attest serves another key for is left out (and reported).
 */
export async function verifiedDevices(list: DeviceList, served: { id: string; deviceKey: string }[], now = Date.now()): Promise<{ devices: VerifiedDevice[]; mismatched: string[] }> {
  const devices: VerifiedDevice[] = [];
  const mismatched: string[] = [];
  for (const e of liveEntries(list, now)) {
    const s = served.find((x) => x.id === e.id);
    if (!s) continue;
    if ((await sha256Hex(s.deviceKey)) !== e.key) {
      mismatched.push(e.id);
      continue;
    }
    devices.push({ id: e.id, deviceKey: s.deviceKey, keyFp: e.key, expires: e.expires } as VerifiedDevice);
  }
  return { devices, mismatched };
}

/** A fresh entry, signed now, for ENTRY_DAYS. */
export function entryFor(d: { id: string; key: string; credential: string }, now = Date.now()): DeviceEntry {
  return { id: d.id, key: d.key, credential: d.credential, issued: new Date(now).toISOString(), expires: new Date(now + ENTRY_DAYS * DAY).toISOString() };
}

/**
 * The next version of a list: every kept device renewed for ENTRY_DAYS (with its next key where it registered one),
 * `drop` left out, `add` added. With no previous list, the first version.
 */
export function nextDeviceList(
  prev: DeviceList | null,
  base: { account: string; signer: string },
  change: { add?: { id: string; key: string; credential: string }[]; drop?: string[]; rotate?: Record<string, string> } = {},
  now = Date.now()
): DeviceList {
  const drop = new Set(change.drop ?? []);
  // A list for another account key, or signed by another key, carries nothing over.
  const carried = prev && prev.account === base.account && prev.signer === base.signer ? prev.devices.filter((d) => !drop.has(d.id) && Date.parse(d.expires) > now) : [];
  const devices = carried.map((d) => entryFor({ id: d.id, key: change.rotate?.[d.id] ?? d.key, credential: d.credential }, now));
  for (const a of change.add ?? []) {
    const i = devices.findIndex((d) => d.id === a.id);
    if (i >= 0) devices[i] = entryFor(a, now);
    else devices.push(entryFor(a, now));
  }
  return { v: 1, account: base.account, signer: base.signer, version: (prev?.version ?? 0) + 1, issued: new Date(now).toISOString(), devices };
}

/** Whether a list should be renewed now: an entry expiring within RENEW_WHEN_DAYS_LEFT days. */
export const needsRenewal = (list: DeviceList, now = Date.now()) => list.devices.some((d) => Date.parse(d.expires) - now < RENEW_WHEN_DAYS_LEFT * DAY);

// ---- a device's next key, registered for rotation --------------------------------------------------------------------

const NEXT_KEY = "attest.device-next-key.v1|";
/** What a device's credential signs to register its next device key. */
export const nextKeyStatement = (deviceId: string, nextKeyFp: string) => `${NEXT_KEY}${deviceId}|${nextKeyFp}`;
/** Whether `signature` is the device credential's registration of its next key (checked by the renewing browser). */
export async function verifyNextKey(credentialSpki: string, deviceId: string, nextKeySpki: string, signature: string): Promise<boolean> {
  return verifyText(credentialSpki, signature, nextKeyStatement(deviceId, await sha256Hex(nextKeySpki)));
}
