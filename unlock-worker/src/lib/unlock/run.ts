import { keyAges, type AgeSource } from "@/lib/key-age";
import { emailHashOf, KeyDirectoryRefusal, pinKeys, verifyKeysWithChanges, type DirectorySource, type VerifiedKey } from "@/lib/key-directory-client";
import { wrapDEKToPublicKey } from "@/lib/e2e";
import { sha256Hex } from "@/lib/unlock/codec";
import { decide, type HoldReason } from "@/lib/unlock/policy";
import { openSignerList, SignerListError, type SealedSignerList } from "@/lib/unlock/sealed-list";

/**
 * One unlock run (design 3.2 D), the same in the service worker and in a page: for each agreement Attest says has a
 * ready signer without a copy, open the document key (a device copy with this device's key, or the sender's own copy
 * with their unlocked account key), open the sealed signer list, check every ready signer's key in this device (the
 * list's pin, the directory on Horizen with the newest-root rule, the key's age), and pass the document key only to
 * the keys the policy clears. Nothing is taken on Attest's word; a failed check stops that agreement (or that signer)
 * only. DOM-free: the caller supplies the API, how the document key opens, and the deadline.
 */

export interface ReadySigner {
  email: string;
  name: string | null;
  publicKey: string;
}
export interface PendingAgreement {
  id: string;
  title: string;
  documentSha256: string;
  /** The signer list sealed at Send; null for agreements sent without one (never unlocked automatically). */
  sealed: SealedSignerList | null;
  /** This device's copy of the document key (the device path), and the device key it is wrapped to. */
  copy?: { wrapped: string; key: string } | null;
  /** The sender's own copy of the document key (the account path, with their key unlocked in a tab). */
  creatorCopy?: string | null;
  ready: ReadySigner[];
}
export interface RecentUnlock {
  agreementId: string;
  title: string;
  signers: string[];
  /** The device that unlocked it ("your MacBook"), or null for a tab of the sender's. */
  by: string | null;
  at: string;
}
export interface PendingResponse {
  limits: { hour: number; day: number };
  agreements: PendingAgreement[];
  recent: RecentUnlock[];
}

export interface UnlockReport {
  outcome: "held" | "refused";
  signers: { email: string; reason: string; at?: string }[];
  detail?: string;
}

export interface UnlockApi {
  grant(agreementId: string, grants: Record<string, string>): Promise<{ granted: string[] }>;
  report(agreementId: string, report: UnlockReport): Promise<void>;
}

export interface UnlockEnv {
  api: UnlockApi;
  /** The agreement's document key, opened on this device. Throws when it can't be (`null`: no copy usable here). */
  openDek(a: PendingAgreement): Promise<Uint8Array | null>;
  directory: DirectorySource;
  ages: AgeSource;
  /** Epoch ms after which nothing more is started. */
  deadline: number;
  /** Raise the alarm (Attest's record didn't match this device's). */
  alarm(detail: string): Promise<void>;
}

type Person = { email: string; name: string | null };
export type Outcome =
  | { kind: "unlocked"; agreementId: string; title: string; signers: Person[] }
  | { kind: "held"; agreementId: string; title: string; signers: (Person & { reason: HoldReason; at?: string })[] }
  | { kind: "refused"; agreementId: string; title: string; detail: string }
  | { kind: "later"; agreementId: string; title: string; detail?: string }
  | { kind: "no_list"; agreementId: string; title: string; signers: Person[] }
  | { kind: "no_copy"; agreementId: string; title: string; signers: Person[] }
  | { kind: "limit"; agreementId: string; title: string; signers: Person[] };

const person = (r: ReadySigner): Person => ({ email: r.email, name: r.name });

async function unlockOne(env: UnlockEnv, a: PendingAgreement): Promise<Outcome[]> {
  const base = { agreementId: a.id, title: a.title };
  if (!a.sealed) return [{ kind: "no_list", ...base, signers: a.ready.map(person) }];
  const refuse = async (detail: string): Promise<Outcome[]> => {
    await env.alarm(`${a.id}: ${detail}`).catch(() => {});
    await env.api.report(a.id, { outcome: "refused", signers: a.ready.map((r) => ({ email: r.email, reason: "refused" })), detail }).catch(() => {});
    return [{ kind: "refused", ...base, detail }];
  };
  let dek: Uint8Array | null;
  try {
    dek = await env.openDek(a);
  } catch {
    return refuse("the document key Attest served for this agreement doesn't open on this device");
  }
  if (!dek) return [{ kind: "no_copy", ...base, signers: a.ready.map(person) }];
  let list;
  try {
    list = await openSignerList(dek, a.sealed, a.id);
  } catch (e) {
    return refuse(e instanceof SignerListError ? e.message : "the signer list doesn't open");
  }
  if (list.documentSha256 !== a.documentSha256) return refuse("the signer list names another document");

  const unlock: { r: ReadySigner; key: VerifiedKey }[] = [];
  const held: (Person & { reason: HoldReason; at?: string })[] = [];
  const refused: string[] = [];
  let later = false;
  let retryWhy: string | undefined;
  const checks = await Promise.all(
    a.ready.map(async (r) => {
      const entry = list.signers.find((s) => s.email === r.email.toLowerCase());
      const fingerprint = await sha256Hex(r.publicKey);
      const emailHash = await emailHashOf(r.email);
      if (!entry) return { r, entry, fingerprint, emailHash, directory: "refused" as const, key: null, changedHere: false };
      try {
        const { keys, changed } = await verifyKeysWithChanges([{ email: r.email, publicKey: r.publicKey }], { source: env.directory, allowChanged: true, pin: false });
        return { r, entry, fingerprint, emailHash, directory: "ok" as const, key: keys[0], changedHere: changed.length > 0 };
      } catch (e) {
        retryWhy = e instanceof Error ? e.message : String(e);
        return { r, entry, fingerprint, emailHash, directory: e instanceof KeyDirectoryRefusal ? ("refused" as const) : ("retry" as const), key: null, changedHere: false };
      }
    })
  );
  const needAges = checks.filter((c) => c.entry && c.directory === "ok" && c.entry.pinned === null && !c.changedHere).map((c) => ({ emailHash: c.emailHash, fingerprint: c.fingerprint }));
  const ages = needAges.length ? await keyAges(needAges, env.ages) : new Map();
  for (const c of checks) {
    const d = decide(c.entry, { fingerprint: c.fingerprint, directory: c.directory, changedHere: c.changedHere }, ages.get(c.emailHash));
    if (d.action === "unlock" && c.key) unlock.push({ r: c.r, key: c.key });
    else if (d.action === "hold") held.push({ ...person(c.r), reason: d.reason, ...(d.at ? { at: d.at } : {}) });
    else if (d.action === "refuse") refused.push(`${c.r.email}: ${d.reason === "not_listed" ? "not on the signer list sealed at Send" : "key refused by the directory check"}`);
    else later = true;
  }
  const out: Outcome[] = [];
  if (refused.length) {
    await env.alarm(`${a.id}: ${refused.join("; ")}`).catch(() => {});
    await env.api.report(a.id, { outcome: "refused", signers: refused.map((x) => ({ email: x.split(":")[0], reason: "refused" })), detail: refused.join("; ") }).catch(() => {});
    out.push({ kind: "refused", ...base, detail: refused.join("; ") });
  }
  if (held.length) {
    await env.api.report(a.id, { outcome: "held", signers: held.map((h) => ({ email: h.email, reason: h.reason, ...(h.at ? { at: h.at } : {}) })) }).catch(() => {});
    out.push({ kind: "held", ...base, signers: held });
  }
  if (unlock.length) {
    const grants: Record<string, string> = {};
    for (const u of unlock) grants[u.r.email] = await wrapDEKToPublicKey(dek, u.key);
    const { granted } = await env.api.grant(a.id, grants);
    await pinKeys(unlock.filter((u) => granted.includes(u.r.email)).map((u) => u.key));
    if (granted.length) out.push({ kind: "unlocked", ...base, signers: unlock.filter((u) => granted.includes(u.r.email)).map((u) => person(u.r)) });
    if (granted.length < unlock.length) later = true;
  }
  if (later) out.push({ kind: "later", ...base, ...(retryWhy ? { detail: retryWhy } : {}) });
  return out;
}

/**
 * Run over what Attest says is pending, within the limits it states (the server enforces them too) and the deadline.
 * Agreements not reached in time, or over the limits, come back as "later" or "limit".
 */
export async function runUnlock(env: UnlockEnv, pending: PendingResponse): Promise<Outcome[]> {
  const out: Outcome[] = [];
  let budget = Math.max(0, Math.min(pending.limits.hour, pending.limits.day));
  for (const a of pending.agreements) {
    const base = { agreementId: a.id, title: a.title };
    if (Date.now() >= env.deadline) {
      out.push({ kind: "later", ...base });
      continue;
    }
    if (a.sealed && budget < a.ready.length) {
      out.push({ kind: "limit", ...base, signers: a.ready.map(person) });
      continue;
    }
    try {
      const r = await unlockOne(env, a);
      for (const o of r) if (o.kind === "unlocked") budget -= o.signers.length;
      out.push(...r);
    } catch (e) {
      out.push({ kind: "later", ...base, detail: e instanceof Error ? e.message : String(e) });
    }
  }
  return out;
}
