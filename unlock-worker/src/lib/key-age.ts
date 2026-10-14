"use client";

import { smtVerify, type SmtProof } from "@/lib/smt";
import { chainRootAt, chainRootCount, keyDirectoryDevSkip, keyDirectoryEnabled, rootPublishedAt } from "@/lib/key-directory-client";

/**
 * Whether someone's key was set up or reset in the last 14 days, as the key directory on Horizen shows it (never by a
 * date Attest supplies). Attest returns, for each person, their slot in the newest root published at least 14 days ago
 * (or the first root) and in the root after it, and where their current key first appears since; this code checks
 * every root against the contract, every slot against its root, and the roots' publishing times from their
 * transactions' RootPublished events. What it can't check counts as "unchecked". DOM-free: the service worker that
 * unlocks documents for new signers runs it too (src/lib/unlock/policy.ts holds a reset or an unchecked age for a tap).
 *
 * What it doesn't see: a key replaced and listed again within the same 14 days, on a device that never saw the newer
 * key (the slot 14 days ago and now are the same key). That person's own browser raises the alarm for it.
 */

export const RECENT_KEY_DAYS = 14;
const RECENT_MS = RECENT_KEY_DAYS * 86_400_000;

/**
 * recent false: the key was already listed 14 days ago. new: first listed since, as the address's first key. reset: first
 * listed since, replacing another key. unchecked: what Attest returned couldn't be checked on Horizen.
 */
export type KeyAge = { recent: false } | { recent: true; kind: "new" | "reset" | "unchecked"; at?: string };

export interface SlotAge {
  emailHash: string;
  keyFp: string | null;
  newest: number;
  before: { seq: number; root: string; txHash: string | null; keyFp: string | null; proof: SmtProof };
  next: { seq: number; txHash: string | null } | null;
  since: { seq: number; root: string; txHash: string | null; proof: SmtProof; prev: { seq: number; root: string; keyFp: string | null; proof: SmtProof } } | null;
}

async function check(a: SlotAge | undefined, h: string, fp: string, now: number): Promise<KeyAge> {
  const unchecked: KeyAge = { recent: true, kind: "unchecked" };
  if (!a || a.keyFp !== fp || a.before.seq > a.newest) return unchecked;
  // The newest root Attest counts from must be Horizen's newest (else a root after `before` could be hidden).
  if (a.newest !== (await chainRootCount()) - 1) return unchecked;
  const cutoff = now - RECENT_MS;
  if ((await chainRootAt(a.before.seq)).root !== a.before.root || !(await smtVerify(h, a.before.keyFp, a.before.proof, a.before.root))) return unchecked;
  // `before` was published at least 14 days ago (the first root may be newer: then it stands for "since the start").
  if (a.before.seq > 0) {
    const t = await rootPublishedAt(a.before.seq, a.before.txHash);
    if (t === null || t > cutoff) return unchecked;
  }
  // ...and it is the newest root that old: the one after it was published since.
  if (a.before.seq < a.newest) {
    if (!a.next || a.next.seq !== a.before.seq + 1) return unchecked;
    const t = await rootPublishedAt(a.next.seq, a.next.txHash);
    if (t === null || t <= cutoff) return unchecked;
  }
  if (a.before.keyFp === fp) return { recent: false };
  // Recent. When it first appeared, and whether it replaced another key, checked the same way: the root where it
  // appears and the one before it, both proven. Without that proof a reset can't be told from a first key (a key
  // published and reset within the 14 days leaves the slot 14 days ago empty): unchecked.
  const s = a.since;
  if (
    !s ||
    s.seq <= a.before.seq ||
    s.prev.seq !== s.seq - 1 ||
    s.prev.keyFp === fp ||
    (await chainRootAt(s.seq)).root !== s.root ||
    (await chainRootAt(s.prev.seq)).root !== s.prev.root ||
    !(await smtVerify(h, fp, s.proof, s.root)) ||
    !(await smtVerify(h, s.prev.keyFp, s.prev.proof, s.prev.root))
  ) {
    return unchecked;
  }
  const t = await rootPublishedAt(s.seq, s.txHash);
  const replaced = Boolean(a.before.keyFp) || Boolean(s.prev.keyFp);
  return { recent: true, kind: replaced ? "reset" : "new", ...(t !== null ? { at: new Date(t).toISOString() } : {}) };
}

/** Where the slot ages come from: the signed-in route by default; the service worker's signed route otherwise. */
export type AgeSource = (emailHashes: string[]) => Promise<SlotAge[]>;
export const sessionAges: AgeSource = async (emailHashes) => {
  const res = await fetch("/api/keys/directory/age", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ emailHashes }) });
  return res.ok ? (((await res.json()) as { ages?: SlotAge[] }).ages ?? []) : [];
};

let agesForTests: ((parties: { emailHash: string; fingerprint: string }[]) => Map<string, KeyAge>) | null = null;
/** Tests of the unlock policy without a key directory set the ages it sees. */
export function setKeyAgesForTests(fn: typeof agesForTests) {
  agesForTests = fn;
}

/** The age of each person's current key (by emailHash), checked on Horizen. */
export async function keyAges(parties: { emailHash: string; fingerprint: string }[], source: AgeSource = sessionAges, now = Date.now()): Promise<Map<string, KeyAge>> {
  if (agesForTests) return agesForTests(parties);
  const out = new Map<string, KeyAge>();
  if (!parties.length) return out;
  if (!keyDirectoryEnabled()) {
    // Local development without a key directory (the same switch as verifyKeys): nothing to check against.
    for (const p of parties) out.set(p.emailHash, keyDirectoryDevSkip() ? { recent: false } : { recent: true, kind: "unchecked" });
    return out;
  }
  let ages: SlotAge[] = [];
  try {
    ages = await source([...new Set(parties.map((p) => p.emailHash))]);
  } catch {}
  for (const p of parties) {
    out.set(p.emailHash, await check(ages.find((a) => a.emailHash === p.emailHash), p.emailHash, p.fingerprint, now).catch((): KeyAge => ({ recent: true, kind: "unchecked" })));
  }
  return out;
}
