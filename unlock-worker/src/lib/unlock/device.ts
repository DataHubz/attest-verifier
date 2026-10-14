import { raiseUnlockAlarm, type DirectorySource, type ProofResponse } from "@/lib/key-directory-client";
import type { AgeSource, SlotAge } from "@/lib/key-age";
import { trustStore } from "@/lib/trust-store";
import { b64, sha256Hex } from "@/lib/unlock/codec";
import { openDeviceCopy } from "@/lib/unlock/device-copy";
import { DeviceListError, liveEntries, verifyDeviceList, type DeviceList, type SignedDeviceList } from "@/lib/unlock/device-list";
import { runUnlock, type Outcome, type PendingResponse, type RecentUnlock, type UnlockReport } from "@/lib/unlock/run";
import { signDeviceRequest } from "@/lib/unlock/signed-request";
import { signText } from "@/lib/signing-key";
import { nextKeyStatement } from "@/lib/unlock/device-list";

/**
 * This device as one that unlocks documents for its owner's new signers (design 3.2). DOM-free: the service worker and
 * the pages share it, through the trust store (src/lib/trust-store.ts).
 *
 * It holds only its own keys, made here and never exported: the device key(s) that device copies are wrapped to, and the
 * credential that signs its requests. It pins the account's signing public key and the newest device list version it
 * saw, so a list Attest made, or an older one bringing back a device that was turned off, is refused. No secret derived
 * from the account key is ever stored on the device.
 */

export interface DeviceState {
  id: string;
  /** The owner's address (lowercase), and the SHA-256 of the account key the device was turned on for. */
  email: string;
  account: string;
  /** The account's signing public key, pinned when the device was turned on. */
  signPublicKey: string;
  /** The newest signed device list version this device has seen. */
  listVersion: number;
  /** The device keys this device holds, by the SHA-256 of their public key; the current one is `keyFp`. */
  keys: Record<string, CryptoKey>;
  keyFp: string;
  deviceKeySpki: string;
  /** The next device key, registered with Attest and listed at a renewal, then switched to. */
  next: { key: CryptoKey; spki: string; fp: string; registered: boolean } | null;
  /** Keys replaced by a rotation, kept while a device copy may still be wrapped to them. */
  retired: Record<string, number>;
  credential: CryptoKey;
  credentialSpki: string;
  label: string;
  /** Lock-screen notifications leave the document's title out (D4). */
  hideTitles: boolean;
  enrolledAt: number;
}

const STATE = "device:self";

export async function deviceState(): Promise<DeviceState | null> {
  return (await trustStore().get<DeviceState>(STATE)) ?? null;
}
export async function saveDeviceState(s: DeviceState) {
  await trustStore().set(STATE, s);
}
export async function updateDeviceState(fn: (s: DeviceState) => DeviceState | undefined) {
  await trustStore().update<DeviceState>(STATE, (cur) => (cur ? fn(cur) : cur));
}
/**
 * Forget this device: its keys are deleted, so nothing wrapped to them opens here again. `off`: Attest turned it off (from
 * another device, at sign-out, after 90 days, a key reset, or it left the device list), noted for its Security page.
 */
export async function forgetDevice(off?: { reason: string }) {
  await trustStore().del(STATE);
  if (off) await trustStore().set(OFF_NOTE, { at: Date.now(), reason: off.reason });
}
const OFF_NOTE = "device:off";
/** When and why Attest last turned this device off, until it's turned on again. */
export async function turnedOffNote(): Promise<{ at: number; reason: string } | null> {
  return (await trustStore().get<{ at: number; reason: string }>(OFF_NOTE)) ?? null;
}
export async function clearTurnedOffNote() {
  await trustStore().del(OFF_NOTE);
}

/** New device keys: RSA-OAEP 2048 (decrypt only, non-extractable) and its public key, SPKI base64. */
export async function newDeviceKey(): Promise<{ key: CryptoKey; spki: string; fp: string }> {
  const kp = (await globalThis.crypto.subtle.generateKey({ name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, false, ["encrypt", "decrypt"])) as CryptoKeyPair;
  const spki = b64(await globalThis.crypto.subtle.exportKey("spki", kp.publicKey));
  return { key: kp.privateKey, spki, fp: await sha256Hex(spki) };
}
/** A new device credential: ECDSA P-256 (sign only, non-extractable) and its public key, SPKI base64. */
export async function newCredential(): Promise<{ key: CryptoKey; spki: string; fp: string }> {
  const kp = (await globalThis.crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])) as CryptoKeyPair;
  const spki = b64(await globalThis.crypto.subtle.exportKey("spki", kp.publicKey));
  return { key: kp.privateKey, spki, fp: await sha256Hex(spki) };
}

// ---- Attest's API, signed by this device ------------------------------------------------------------------------------

export class DeviceOffError extends Error {
  constructor(
    code: string,
    readonly reason: string = "turned_off"
  ) {
    super(code);
  }
}

/** A request signed by this device's credential (no cookie needed). Throws DeviceOffError when Attest no longer serves it. */
export async function deviceFetch(s: DeviceState, method: string, path: string, body?: unknown): Promise<Response> {
  const text = body === undefined ? "" : JSON.stringify(body);
  const headers: Record<string, string> = await signDeviceRequest(s.credential, s.id, method, path, text);
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(path, { method, headers, body: body === undefined ? undefined : text, credentials: "omit", cache: "no-store" });
  if (res.status === 403 || res.status === 401) {
    const err = ((await res.clone().json().catch(() => ({}))) as { error?: { code?: string; reason?: string } }).error;
    if (err?.code === "device_off" || err?.code === "unknown_device") throw new DeviceOffError(err.code, err.reason ?? "turned_off");
  }
  return res;
}

async function json<T>(res: Response): Promise<T> {
  const d = (await res.json().catch(() => ({}))) as T & { error?: { message?: string } };
  if (!res.ok) throw new Error(d.error?.message ?? `Attest answered ${res.status}`);
  return d;
}

/** The key directory, through this device's signed routes (the service worker may have no web session). */
export const deviceDirectory = (s: DeviceState): DirectorySource => ({
  proofs: async (emailHashes) => json<ProofResponse>(await deviceFetch(s, "POST", "/api/unlock/directory", { emailHashes })),
  refresh: async () => {
    await deviceFetch(s, "POST", "/api/unlock/directory", { refresh: true }).catch(() => null);
  },
});
export const deviceAges = (s: DeviceState): AgeSource => async (emailHashes) => (await json<{ ages: SlotAge[] }>(await deviceFetch(s, "POST", "/api/unlock/ages", { emailHashes }))).ages;

// ---- the device list, checked here ------------------------------------------------------------------------------------

/**
 * Check the account's newest signed list against the pinned signing key, the account key and the newest version seen
 * here, and remember its version. Throws DeviceListError (the alarm is raised for a list that doesn't verify or rolls
 * back), or DeviceOffError when the list no longer names this device with its keys.
 */
export async function checkOwnList(s: DeviceState, signed: SignedDeviceList | null): Promise<DeviceList> {
  if (!signed) throw new DeviceOffError("no list");
  let list: DeviceList;
  try {
    list = await verifyDeviceList(signed, s.signPublicKey, { account: s.account, minVersion: s.listVersion });
  } catch (e) {
    if (e instanceof DeviceListError && e.problem !== "malformed") await raiseUnlockAlarm(`device list: ${e.message}`).catch(() => {});
    throw e;
  }
  if (list.version > s.listVersion) await updateDeviceState((cur) => ({ ...cur, listVersion: Math.max(cur.listVersion, list.version) }));
  const credentialFp = await sha256Hex(s.credentialSpki);
  const mine = liveEntries(list).find((d) => d.id === s.id && d.credential === credentialFp);
  if (!mine) throw new DeviceOffError("not listed");
  // A renewal listed the next key: switch to it, and keep the old one while copies may still be wrapped to it.
  if (s.next && mine.key === s.next.fp && s.keyFp !== s.next.fp) {
    const next = s.next;
    await updateDeviceState((cur) => ({ ...cur, keys: { ...cur.keys, [next.fp]: next.key }, keyFp: next.fp, deviceKeySpki: next.spki, next: null, retired: { ...cur.retired, [cur.keyFp]: Date.now() } }));
  }
  return list;
}

/** Make and register the next device key (rotated in at the next renewal), when there is none yet. */
export async function prepareNextKey(s: DeviceState): Promise<void> {
  if (s.next?.registered) return;
  const next = s.next ?? { ...(await newDeviceKey()), registered: false };
  if (!s.next) await updateDeviceState((cur) => ({ ...cur, next }));
  const res = await deviceFetch(s, "PATCH", "/api/unlock/device", { nextKey: next.spki, nextKeySig: await signText(s.credential, nextKeyStatement(s.id, next.fp)) });
  if (res.ok) await updateDeviceState((cur) => (cur.next ? { ...cur, next: { ...cur.next, registered: true } } : cur));
}

/** Delete keys a rotation replaced once no device copy refers to them (or after 60 days). */
async function dropRetiredKeys(copyKeys: string[]) {
  const cutoff = Date.now() - 60 * 86_400_000;
  await updateDeviceState((cur) => {
    const retired = { ...cur.retired };
    const keys = { ...cur.keys };
    for (const [fp, since] of Object.entries(cur.retired)) {
      if (copyKeys.includes(fp) && since > cutoff) continue;
      delete retired[fp];
      delete keys[fp];
    }
    return { ...cur, keys, retired };
  });
}

// ---- the run ----------------------------------------------------------------------------------------------------------

export type DeviceRunResult =
  | { status: "done"; outcomes: Outcome[]; recent: RecentUnlock[]; label: string; hideTitles: boolean }
  | { status: "off"; reason: string }
  | { status: "none" }
  | { status: "error"; message: string };

async function withLock<T>(fn: () => Promise<T>, wait: boolean): Promise<T | null> {
  const locks = (globalThis as { navigator?: { locks?: LockManager } }).navigator?.locks;
  if (!locks) return fn();
  // Two tabs and the service worker never run at once on one device. A page's periodic check skips while another run
  // holds it; a push waits for it (and then sees what that run did).
  return (await locks.request("attest-unlock", wait ? {} : { ifAvailable: true }, async (lock) => (lock ? fn() : null))) as T | null;
}

/**
 * One automatic unlock run of this device (design 3.2 D): ask Attest what's pending (signed), check this device is
 * still on the account's signed list, then unlock what passes every check. At most until `deadline`.
 */
export async function runDeviceUnlock(opts: { deadline: number; wait?: boolean }): Promise<DeviceRunResult> {
  const s = await deviceState();
  if (!s) return { status: "none" };
  const r = await withLock(async (): Promise<DeviceRunResult> => {
    let pending: PendingResponse & { list: (SignedDeviceList & { version: number }) | null; copyKeys?: string[] };
    try {
      pending = await json(await deviceFetch(s, "GET", "/api/unlock/pending"));
    } catch (e) {
      if (e instanceof DeviceOffError) {
        await forgetDevice({ reason: e.reason });
        return { status: "off", reason: e.message };
      }
      return { status: "error", message: e instanceof Error ? e.message : "pending" };
    }
    try {
      await checkOwnList(s, pending.list);
    } catch (e) {
      if (e instanceof DeviceOffError) {
        // Not on the account's list any more (turned off, lapsed, or the key reset): this device deletes its keys.
        await deviceFetch(s, "DELETE", "/api/unlock/device?reason=turned_off").catch(() => null);
        await forgetDevice({ reason: "not_listed" });
        return { status: "off", reason: e.message };
      }
      return { status: "error", message: e instanceof Error ? e.message : "list" };
    }
    const now = (await deviceState()) ?? s;
    const outcomes = await runUnlock(
      {
        api: {
          grant: async (agreementId, grants) => json<{ granted: string[] }>(await deviceFetch(now, "POST", "/api/unlock/grant", { agreementId, grants })),
          report: async (agreementId, report: UnlockReport) => {
            await deviceFetch(now, "POST", "/api/unlock/report", { agreementId, ...report });
          },
        },
        openDek: async (a) => {
          if (!a.copy) return null;
          const key = now.keys[a.copy.key];
          if (!key) return null;
          return openDeviceCopy(a.copy.wrapped, key, a.id);
        },
        directory: deviceDirectory(now),
        ages: deviceAges(now),
        deadline: opts.deadline,
        alarm: async (detail) => {
          await raiseUnlockAlarm(detail);
          await deviceFetch(now, "POST", "/api/unlock/alarm", { reason: "unlock", detail }).catch(() => null);
        },
      },
      pending
    );
    if (pending.copyKeys) await dropRetiredKeys(pending.copyKeys).catch(() => {});
    if (Date.now() < opts.deadline - 3000) await prepareNextKey((await deviceState()) ?? now).catch(() => {});
    return { status: "done", outcomes, recent: pending.recent, label: now.label, hideTitles: now.hideTitles };
  }, opts.wait === true);
  return r ?? { status: "done", outcomes: [], recent: [], label: s.label, hideTitles: s.hideTitles };
}
