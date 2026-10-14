"use client";

import { smtVerify, type SmtProof } from "@/lib/smt";
import { migrateLegacyTrustState, trustStore } from "@/lib/trust-store";

/**
 * The browser's side of the public key directory. DOM-free: pages and the service worker that unlocks documents for
 * new signers (src/unlock-sw/sw.ts) run the same checks.
 *
 * Before anything is encrypted to someone, their key must be the one in their slot of a directory root that is
 * published on the AttestKeyDirectory contract, which this code reads straight from Horizen (not from Attest). The
 * root must be the newest one on Horizen, and never older than a root this device already checked, so a replaced key
 * can't come back through an old root. The only way to encrypt to someone is through a VerifiedKey, which only
 * verifyKeys() creates.
 *
 * And every signed-in browser audits its owner's own slot in every root published since its last check (auditOwnKey):
 * a key listed for you that isn't one of yours raises an alarm, so a substituted key can't go unnoticed.
 *
 * Keys seen before are also pinned on this device: a person's key changing since you last encrypted to them has to be
 * confirmed, and a key a newer one replaced is never taken again.
 *
 * All of this device's trust state lives in IndexedDB (src/lib/trust-store.ts), shared with the service worker.
 */

const CONTRACT = (process.env.NEXT_PUBLIC_KEY_DIRECTORY_CONTRACT ?? "").toLowerCase();
const RPC = process.env.NEXT_PUBLIC_HORIZEN_RPC_URL || "https://horizen.calderachain.xyz/http";
const SEL_COUNT = "0x06661abd";
const SEL_ROOT_AT = "0xca2869a0";

declare const verified: unique symbol;
/** A public key checked against the directory. Encryption to other people accepts only these. */
export type VerifiedKey = { readonly publicKey: string; readonly fingerprint: string; readonly emailHash: string; readonly [verified]: true };

export class KeyDirectoryError extends Error {}
/**
 * What Attest answered contradicts Horizen or this device's own record (a key that isn't the one listed, a root that
 * isn't the one on chain, a rollback, a root withheld for too long): never a passing condition, and never retried as if
 * it were. Other KeyDirectoryErrors (a root still being published, a directory or Horizen that can't be reached) are.
 */
export class KeyDirectoryRefusal extends KeyDirectoryError {}
/** Someone's key differs from the one this device saw for them before. */
export class KeyChangedError extends KeyDirectoryError {
  constructor(public readonly emailHash: string, public readonly pinned: string, public readonly now: string) {
    super("This person's encryption key changed since you last shared with them. Confirm it with them before sharing.");
  }
}
/**
 * Someone's key is one that a later key had replaced on this device (it saw the newer one): Attest's directory lists the
 * earlier key again. Nothing is encrypted to it, and the alarm is raised.
 */
export class KeyRolledBackError extends KeyDirectoryRefusal {
  constructor(public readonly emailHash: string, public readonly email: string | undefined, public readonly listed: string, public readonly newer: string) {
    super(`Attest's key directory lists an earlier key for ${email ?? "this person"} again, after this device saw it replaced. Nothing was shared, and DataHubz was notified.`);
  }
}

const hex = (b: ArrayBuffer) => Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, "0")).join("");
export async function sha256Hex(text: string): Promise<string> {
  return hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
}
export const emailHashOf = (email: string) => sha256Hex(email.trim().toLowerCase());
/** The key id used across Attest: sha256 of the public key as stored (spki, base64). */
export const keyFingerprintOf = (publicKeyB64: string) => sha256Hex(publicKeyB64);

export function keyDirectoryEnabled(): boolean {
  return /^0x[0-9a-f]{40}$/.test(CONTRACT);
}

/** Local development only, and only when asked for explicitly: no key directory, so nothing to check against. */
export function keyDirectoryDevSkip(): boolean {
  return process.env.NODE_ENV !== "production" && process.env.NEXT_PUBLIC_KEY_DIRECTORY_DEV_SKIP === "1" && !keyDirectoryEnabled();
}

// ---- the contract, read directly from Horizen ------------------------------------------

async function rpc<T>(method: string, params: unknown[]): Promise<T | undefined> {
  const res = await fetch(RPC, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  const j = (await res.json()) as { result?: T; error?: { message: string } };
  if (j.error) throw new KeyDirectoryError(`Horizen: ${j.error.message}`);
  return j.result;
}

async function ethCall(data: string): Promise<string> {
  const r = await rpc<string>("eth_call", [{ to: CONTRACT, data }, "latest"]);
  if (!r || r === "0x") throw new KeyDirectoryError("Horizen: no result");
  return r;
}

export async function chainRootCount(): Promise<number> {
  return Number(BigInt(await ethCall(SEL_COUNT)));
}

const rootCache = new Map<number, { root: string; entries: number }>();
/** How long to wait between asks while a just-published root becomes available (tests set it lower). */
let ROOT_WAIT_MS = 1000;
export function setRootWaitForTests(ms: number) {
  ROOT_WAIT_MS = ms;
}
export async function chainRootAt(seq: number): Promise<{ root: string; entries: number }> {
  const hit = rootCache.get(seq);
  if (hit) return hit;
  const out = await ethCall(SEL_ROOT_AT + seq.toString(16).padStart(64, "0"));
  const r = { root: out.slice(2, 66), entries: Number(BigInt(`0x${out.slice(66, 130)}`)) };
  rootCache.set(seq, r);
  return r;
}

const ROOT_PUBLISHED = "0x2c9dfae8c3ea3ac9ae0942080a02510233928ddd5d7881aa62fc3a6f26220e0b"; // RootPublished(uint256,bytes32,uint256,uint256)
/**
 * When root `seq` was published, read from Horizen: the transaction `txHash` (named by Attest) must be a successful
 * call on the AttestKeyDirectory contract whose RootPublished event is for this seq and the root the contract holds
 * there; its timestamp is the block's. Null when it isn't (or can't be read). Only the contract emits that event, once
 * per seq, so no other transaction can stand in for it.
 */
export async function rootPublishedAt(seq: number, txHash: string | null): Promise<number | null> {
  if (!txHash || !/^0x[0-9a-fA-F]{64}$/.test(txHash) || !keyDirectoryEnabled()) return null;
  try {
    const rc = await rpc<{ status: string; logs: { address: string; topics: string[]; data: string }[] }>("eth_getTransactionReceipt", [txHash]);
    if (!rc || rc.status !== "0x1") return null;
    const log = rc.logs.find((l) => l.address.toLowerCase() === CONTRACT && l.topics[0]?.toLowerCase() === ROOT_PUBLISHED && BigInt(l.topics[1] ?? "0x0") === BigInt(seq));
    if (!log) return null;
    const data = log.data.replace(/^0x/, "");
    if (data.slice(0, 64).toLowerCase() !== (await chainRootAt(seq)).root.toLowerCase()) return null;
    return Number(BigInt(`0x${data.slice(128, 192)}`)) * 1000;
  } catch {
    return null;
  }
}

// ---- where the directory's proofs come from ------------------------------------------------------------------------

export interface ProofResponse {
  seq: number;
  root: string;
  results: { emailHash: string; keyFp: string | null; proof: SmtProof }[];
}

/**
 * Attest's directory API. A page uses the signed-in routes; the service worker uses the same answers through requests
 * signed by its device credential (src/lib/unlock/device-api.ts). Nothing it returns is taken on trust: every proof is
 * checked here against a root read from Horizen.
 */
export interface DirectorySource {
  proofs(emailHashes: string[]): Promise<ProofResponse>;
  /** Ask Attest to publish a root covering keys set up moments ago (does nothing when it's up to date). */
  refresh(): Promise<void>;
}

async function postJson<T>(url: string, body: unknown): Promise<T> {
  const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const d = (await res.json().catch(() => ({}))) as T & { error?: { message?: string } };
  if (!res.ok) throw new KeyDirectoryError(d.error?.message ?? "The key directory couldn't be reached.");
  return d;
}

/** The signed-in routes. */
export const sessionDirectory: DirectorySource = {
  proofs: (emailHashes) => postJson<ProofResponse>("/api/keys/directory", { emailHashes }),
  refresh: async () => {
    await fetch("/api/keys/directory/refresh", { method: "POST" }).catch(() => {});
  },
};

// ---- this device's trust state -------------------------------------------------------------------------------------

async function store() {
  await migrateLegacyTrustState();
  return trustStore();
}

/** This device's pins: the key it last accepted for each address (by emailHash). */
async function pins(): Promise<Record<string, string>> {
  return (await (await store()).get<Record<string, string>>("pins")) ?? {};
}
/** Every key this device has accepted for each address, oldest first: a key replaced since must never come back. */
async function seenKeys(): Promise<Record<string, string[]>> {
  return (await (await store()).get<Record<string, string[]>>("seen")) ?? {};
}
async function savePin(h: string, fp: string) {
  const s = await store();
  await s.update<Record<string, string[]>>("seen", (cur) => {
    const seen = cur ?? {};
    const had = seen[h] ?? [];
    return had.includes(fp) ? seen : { ...seen, [h]: [...had, fp] };
  });
  await s.update<Record<string, string>>("pins", (cur) => ({ ...(cur ?? {}), [h]: fp }));
}
/** After the person confirmed the new key with its owner (e.g. safety number): accept it. */
export async function acceptChangedKey(e: { emailHash: string; now: string }) {
  await savePin(e.emailHash, e.now);
}
/** The key this device pinned for each of these addresses (by emailHash), or null where it has none. */
export async function pinnedFingerprints(emailHashes: string[]): Promise<Record<string, string | null>> {
  const p = await pins();
  return Object.fromEntries(emailHashes.map((h) => [h, p[h] ?? null]));
}
/** A key this device accepted for this address before, that a newer accepted key replaced: the newer one, else null. */
async function replacedHere(h: string, fp: string): Promise<string | null> {
  const p = await pins();
  const seen = (await seenKeys())[h] ?? [];
  return p[h] && p[h] !== fp && seen.includes(fp) ? p[h] : null;
}

// ---- verification before encrypting ---------------------------------------------------

export interface Party {
  email?: string;
  /** For parties known only by the sha256 of their address (sealed-bid reviewers). */
  emailHash?: string;
  publicKey: string;
}
/** A key proven to be the published one for its owner, but not (yet) cleared for encryption. */
export interface DirectoryKey {
  email?: string;
  emailHash: string;
  fingerprint: string;
  publicKey: string;
}

/** How long Attest may keep serving an older root than Horizen's newest (with other content) before it's an alarm. */
export const ROOT_WITHHELD_MS = 10 * 60_000;

/**
 * The first root on Horizen after `seq`, up to `newest`, with other content than `root` (null when every one is the
 * same root: a publication recorded twice). Over 32 roots ahead, the one right after `seq` stands for it.
 */
async function firstDifferingRoot(seq: number, newest: number, root: string): Promise<number | null> {
  if (newest - seq > 32) return seq + 1;
  for (let s = seq + 1; s <= newest; s++) if ((await chainRootAt(s)).root !== root) return s;
  return null;
}

/**
 * How long this device has seen root `seq` on Horizen (the first one after the root Attest serves with other content)
 * without Attest serving it or anything newer (0 the first time). Keyed to that root, not to the newest: publishing more
 * roots while withholding it doesn't restart the clock.
 */
async function directoryLag(seq: number): Promise<number> {
  const s = await store();
  const now = Date.now();
  const lag = await s.update<{ seq: number; since: number }>("rootLag", (cur) => (cur?.seq === seq ? cur : { seq, since: now }));
  return now - (lag?.since ?? now);
}

/** The newest directory root this device has checked (-1 before the first). */
export async function newestRootChecked(): Promise<number> {
  return (await (await store()).get<number>("rootSeen")) ?? -1;
}

/**
 * Check people's keys against the newest directory root published on Horizen (read from Horizen, never from Attest),
 * and never a root older than the newest this device has seen. Throws KeyDirectoryError if any key isn't the one
 * published for that person, or if Attest serves an older root than Horizen's newest (raising the alarm when it's a
 * rollback, or when it lasts). This alone doesn't clear a key for encryption (see verifyKeys).
 */
export async function directoryKeys(parties: Party[], source: DirectorySource = sessionDirectory): Promise<DirectoryKey[]> {
  if (!keyDirectoryEnabled()) throw new KeyDirectoryError("The key directory isn't configured, so keys can't be verified.");
  const withHash = await Promise.all(parties.map(async (p) => ({ ...p, h: p.emailHash ?? (await emailHashOf(p.email ?? "")), fp: await keyFingerprintOf(p.publicKey) })));
  const hashes = [...new Set(withHash.map((p) => p.h))];
  // No root published yet (the first key moments ago): publish, then ask again.
  let data = await source.proofs(hashes).catch(async () => {
    await source.refresh();
    return source.proofs(hashes);
  });
  // A key set up moments ago may not be in a published root yet: publish, then ask again.
  for (let attempt = 0; attempt < 2 && withHash.some((p) => data.results.find((r) => r.emailHash === p.h)?.keyFp !== p.fp); attempt++) {
    await source.refresh();
    data = await source.proofs(hashes);
  }
  // A root older than one this device already checked is a rollback, whatever else: refused at once.
  const seenBefore = await newestRootChecked();
  if (data.seq < seenBefore) {
    await raiseDirectoryAlarm(`Attest served root #${data.seq}; this device had checked root #${seenBefore}`);
    throw new KeyDirectoryRefusal("Attest answered with an older key directory root than one this device has already checked. Nothing was shared, and DataHubz was notified.");
  }
  // The newest root on chain, only. A root Horizen has just taken may not be served for a few seconds while its
  // publication completes: wait for it (up to about 12 seconds) rather than call it anything else. After the wait, a
  // served root that every newer root on chain repeats is the newest state and is accepted; an older root than this
  // device checked is a rollback (alarm); a newer root with other content still unserved after ROOT_WITHHELD_MS is
  // withheld (alarm). Until then the sender is asked to try again.
  let newest = (await chainRootCount()) - 1;
  for (let waited = 0; data.seq < newest && waited < 12_000; waited += ROOT_WAIT_MS) {
    await new Promise((r) => setTimeout(r, ROOT_WAIT_MS));
    data = await source.proofs(hashes);
    newest = (await chainRootCount()) - 1;
  }
  const s = await store();
  const seen = await newestRootChecked();
  if (data.seq < seen) {
    // A real rollback: this device already checked a newer root.
    await raiseDirectoryAlarm(`Attest served root #${data.seq}; this device had checked root #${seen}`);
    throw new KeyDirectoryRefusal("Attest answered with an older key directory root than one this device has already checked. Nothing was shared, and DataHubz was notified.");
  }
  const onChain = await chainRootAt(data.seq);
  if (onChain.root !== data.root) throw new KeyDirectoryRefusal("The key directory root doesn't match the one published on Horizen.");
  if (data.seq < newest) {
    const differing = await firstDifferingRoot(data.seq, newest, data.root);
    if (differing !== null) {
      const lag = await directoryLag(differing);
      if (lag > ROOT_WITHHELD_MS) {
        await raiseDirectoryAlarm(`Horizen holds root #${differing} (and up to #${newest}); Attest has served root #${data.seq} for ${Math.round(lag / 60_000)} minutes since this device saw it`);
        throw new KeyDirectoryRefusal("Attest isn't serving the newest key directory root published on Horizen. Nothing was shared, and DataHubz was notified.");
      }
      throw new KeyDirectoryError("Attest's key directory is still publishing a new root. Nothing was shared yet: try again in a minute.");
    }
  }
  await s.update<number>("rootSeen", (cur) => Math.max(cur ?? -1, data.seq));
  const out: DirectoryKey[] = [];
  for (const p of withHash) {
    const r = data.results.find((x) => x.emailHash === p.h);
    if (!r || r.keyFp !== p.fp || !(await smtVerify(p.h, p.fp, r.proof, data.root))) {
      throw new KeyDirectoryRefusal(`${p.email ?? "A recipient"}'s key isn't the one published in the key directory. Nothing was shared.`);
    }
    out.push({ ...(p.email ? { email: p.email } : {}), emailHash: p.h, fingerprint: p.fp, publicKey: p.publicKey });
  }
  return out;
}

export interface VerifyOptions {
  /** Where proofs come from (the signed-in routes by default). */
  source?: DirectorySource;
  /**
   * A release or share that will ask the sender first: a key that differs from the one this device pinned is
   * returned (in `changed`, not pinned yet) instead of throwing KeyChangedError. A key replaced since still throws.
   */
  allowChanged?: boolean;
  /** False: pin nothing (the caller pins only the keys it then encrypts to, with pinKeys). */
  pin?: boolean;
}

export interface ChangedKey {
  email?: string;
  emailHash: string;
  pinned: string;
  now: string;
}

/**
 * Check people's keys against the newest directory root on Horizen and this device's pins. Each party is identified by
 * email or by emailHash (sealed-bid reviewers). Throws KeyDirectoryError if any key isn't the one published for that
 * person, KeyRolledBackError if it is one a newer key replaced on this device, or KeyChangedError if it differs from
 * the key this device pinned (unless `allowChanged`, which returns it in `changed` instead and leaves it out of `keys`).
 */
export async function verifyKeysWithChanges(parties: Party[], opts: VerifyOptions = {}): Promise<{ keys: (VerifiedKey | null)[]; changed: ChangedKey[] }> {
  if (keyDirectoryDevSkip()) {
    console.warn("[attest] Development only: keys are NOT checked against a key directory.");
    const keys = await Promise.all(
      parties.map(async (p) => ({ publicKey: p.publicKey, fingerprint: await keyFingerprintOf(p.publicKey), emailHash: p.emailHash ?? (await emailHashOf(p.email ?? "")) }) as VerifiedKey)
    );
    return { keys, changed: [] };
  }
  const listed = await directoryKeys(parties, opts.source);
  const pinned = await pins();
  const keys: (VerifiedKey | null)[] = [];
  const changed: ChangedKey[] = [];
  for (const k of listed) {
    const newer = await replacedHere(k.emailHash, k.fingerprint);
    if (newer) {
      await raiseDirectoryAlarm(`a key replaced on this device (${k.fingerprint.slice(0, 16)}) is listed again for ${k.emailHash.slice(0, 16)}`);
      throw new KeyRolledBackError(k.emailHash, k.email, k.fingerprint, newer);
    }
    if (pinned[k.emailHash] && pinned[k.emailHash] !== k.fingerprint) {
      if (!opts.allowChanged) throw new KeyChangedError(k.emailHash, pinned[k.emailHash], k.fingerprint);
      changed.push({ ...(k.email ? { email: k.email } : {}), emailHash: k.emailHash, pinned: pinned[k.emailHash], now: k.fingerprint });
      keys.push(null);
      continue;
    }
    if (opts.pin !== false) await savePin(k.emailHash, k.fingerprint);
    keys.push({ publicKey: k.publicKey, fingerprint: k.fingerprint, emailHash: k.emailHash } as VerifiedKey);
  }
  return { keys, changed };
}

/** Pin keys this device encrypted to (after verifyKeysWithChanges with `pin: false`). */
export async function pinKeys(keys: VerifiedKey[]) {
  for (const k of keys) await savePin(k.emailHash, k.fingerprint);
}

/**
 * Check people's keys against the newest directory root published on Horizen. Each party is identified by email or by
 * emailHash (sealed-bid reviewers). Throws KeyDirectoryError if any key isn't the one published for that person, or
 * KeyChangedError if it differs from the key this device pinned.
 */
export async function verifyKeys(parties: Party[], opts: Omit<VerifyOptions, "allowChanged"> = {}): Promise<VerifiedKey[]> {
  return (await verifyKeysWithChanges(parties, opts)).keys as VerifiedKey[];
}

// ---- alarms ---------------------------------------------------------------------------------------------------------

export interface AuditAlarm {
  seq: number;
  listed: string | null;
  /**
   * unknown_key: a root lists a key for you that this device doesn't know as yours.
   * removed: your key disappeared from a root.
   * review: this device's first check found earlier keys it can't recognize (a
   * reset done on another device, or not): the latest root has your key.
   * directory: Attest's directory answered with an older root than this device checked, withheld the newest one, or
   * listed a key that a newer one replaced (in `detail`).
   * unlock: an automatic unlock found Attest's record didn't match what this device holds (in `detail`).
   */
  reason: "unknown_key" | "removed" | "review" | "directory" | "unlock";
  earlier?: string[];
  detail?: string;
}

/** Device-wide alarms (not about one owner's slot) are kept under this name. */
const DEVICE_ALARM = "alarm:device";

/** Tell every open page (and this one) about an alarm: a window event here, and a broadcast to the other contexts. */
function announce(alarm: AuditAlarm) {
  const g = globalThis as { window?: { dispatchEvent(e: Event): boolean }; BroadcastChannel?: typeof BroadcastChannel; CustomEvent?: typeof CustomEvent };
  try {
    if (g.window && g.CustomEvent) g.window.dispatchEvent(new g.CustomEvent("attest:key-alarm", { detail: alarm }));
  } catch {}
  try {
    if (g.BroadcastChannel) {
      const c = new g.BroadcastChannel("attest-trust");
      c.postMessage({ type: "key-alarm", alarm });
      c.close();
    }
  } catch {}
  for (const l of alarmListeners) {
    try {
      l(alarm);
    } catch {}
  }
}
const alarmListeners: ((a: AuditAlarm) => void)[] = [];
/** The service worker reports alarms to DataHubz itself (no page may be open). */
export function onAlarm(listener: (a: AuditAlarm) => void) {
  alarmListeners.push(listener);
}

async function raise(key: string, alarm: AuditAlarm): Promise<AuditAlarm> {
  await (await store()).set(key, alarm).catch(() => {});
  announce(alarm);
  return alarm;
}

/** Attest's directory misbehaved toward this device: an alarm for whoever uses it, and for DataHubz. */
export async function raiseDirectoryAlarm(detail: string): Promise<AuditAlarm> {
  return raise(DEVICE_ALARM, { seq: await newestRootChecked(), listed: null, reason: "directory", detail });
}

/** An automatic unlock found Attest's record didn't match this device's copy. */
export async function raiseUnlockAlarm(detail: string): Promise<AuditAlarm> {
  return raise(DEVICE_ALARM, { seq: await newestRootChecked(), listed: null, reason: "unlock", detail });
}

/** Dismiss this device's own alarm (once it was reported): the owner's slot alarms stay until acknowledged. */
export async function clearDeviceAlarm() {
  await (await store()).del(DEVICE_ALARM);
}

/** The alarm for this owner (their slot), else this device's own, else null. */
export async function currentAlarm(email: string): Promise<AuditAlarm | null> {
  const s = await store();
  return (await s.get<AuditAlarm>(`alarm:${await emailHashOf(email)}`)) ?? (await s.get<AuditAlarm>(DEVICE_ALARM)) ?? null;
}

// ---- the owner's audit --------------------------------------------------------------------

interface AuditState {
  seq: number; // next root to check
  present: boolean; // own slot seen filled
  known: string[]; // this owner's own key fingerprints, as seen by this device
}
const emptyAudit = (): AuditState => ({ seq: 0, present: false, known: [] });
async function loadAudit(h: string): Promise<AuditState> {
  return (await (await store()).get<AuditState>(`audit:${h}`)) ?? emptyAudit();
}
async function saveAudit(h: string, change: (s: AuditState) => AuditState) {
  await (await store()).update<AuditState>(`audit:${h}`, (cur) => change(cur ?? emptyAudit()));
}

/** How far this device's audit of the owner's slot has got: the next root it will check. */
export async function auditProgress(email: string): Promise<number> {
  return (await loadAudit(await emailHashOf(email))).seq;
}

/** Register one of the owner's own keys on this device (after unlocking it, or after a reset here). */
export async function rememberOwnKey(email: string, publicKey: string) {
  const h = await emailHashOf(email);
  const fp = await keyFingerprintOf(publicKey);
  await saveAudit(h, (s) => (s.known.includes(fp) ? s : { ...s, known: [...s.known, fp] }));
}

/**
 * Check the owner's own slot in every root published since this device's last check, reading each root from Horizen.
 * Returns an alarm (also stored, and announced with an "attest:key-alarm" event) if any root lists a key for the owner
 * that this device doesn't know as theirs, or drops their key.
 */
export async function auditOwnKey(email: string, ownPublicKey: string): Promise<AuditAlarm | null> {
  if (!keyDirectoryEnabled()) return null;
  await rememberOwnKey(email, ownPublicKey);
  const h = await emailHashOf(email);
  let s = await loadAudit(h);
  const firstAudit = s.seq === 0 && !s.present;
  const unrecognized: { seq: number; fp: string }[] = [];
  const total = await chainRootCount();
  let lastFp: string | null = null;
  while (s.seq < total) {
    const res = await fetch("/api/keys/directory/history", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ fromSeq: s.seq }) });
    if (!res.ok) return null; // try again next time; nothing is marked checked
    const { roots } = (await res.json()) as { roots: { seq: number; root: string; keyFp: string | null; proof: SmtProof }[] };
    if (!roots.length) return null;
    for (const r of roots) {
      if (r.seq !== s.seq) return null; // a gap: try again next time
      const onChain = await chainRootAt(r.seq);
      if (onChain.root !== r.root || !(await smtVerify(h, r.keyFp, r.proof, r.root))) return null; // not provable: retry later
      if (!r.keyFp && s.present) return raise(`alarm:${h}`, { seq: r.seq, listed: null, reason: "removed" });
      if (r.keyFp && !s.known.includes(r.keyFp)) {
        // A device's first check can't know keys used before a reset elsewhere: collect them for review.
        if (!firstAudit) return raise(`alarm:${h}`, { seq: r.seq, listed: r.keyFp, reason: "unknown_key" });
        unrecognized.push({ seq: r.seq, fp: r.keyFp });
      }
      lastFp = r.keyFp;
      const next = { seq: r.seq + 1, present: s.present || Boolean(r.keyFp) };
      await saveAudit(h, (cur) => ({ ...cur, ...next }));
      s = { ...s, ...next };
    }
  }
  if (firstAudit && unrecognized.length) {
    // The latest root must list a key this device knows is yours; otherwise it's an alarm, not history.
    if (!lastFp || !s.known.includes(lastFp)) return raise(`alarm:${h}`, { seq: total - 1, listed: lastFp, reason: "unknown_key" });
    const earlier = [...new Set(unrecognized.map((u) => u.fp))];
    return raise(`alarm:${h}`, { seq: unrecognized[0].seq, listed: earlier[0], reason: "review", earlier });
  }
  return null;
}

/** The owner confirmed the listed key(s) were theirs (reset on another device): trust them on this one. */
export async function acknowledgeOwnKey(email: string, fps: string | string[]) {
  const h = await emailHashOf(email);
  const add = Array.isArray(fps) ? fps : [fps];
  await saveAudit(h, (s) => ({ ...s, known: [...new Set([...s.known, ...add])] }));
  await (await store()).del(`alarm:${h}`);
}

// ---- safety numbers -----------------------------------------------------------------------

/** 60 digits in 12 groups, the same for both people: compare it to confirm each other's keys. */
export async function safetyNumber(a: { emailHash: string; fingerprint: string }, b: { emailHash: string; fingerprint: string }): Promise<string> {
  const [x, y] = [`${a.emailHash}:${a.fingerprint}`, `${b.emailHash}:${b.fingerprint}`].sort();
  const d = await sha256Hex(`attest.safety.v1|${x}|${y}`);
  const digits = BigInt(`0x${d}`).toString().padStart(60, "0").slice(-60);
  return digits.match(/.{5}/g)!.join(" ");
}
