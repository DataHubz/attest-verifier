import type { Outcome, RecentUnlock } from "@/lib/unlock/run";

/**
 * The notifications a device shows after an unlock run (design 3.2 D, step 5), built from what Attest's API answered
 * and what the run did, never assumed. One per agreement, except "Unlocked for …", one per agreement and signers, so a
 * later unlock doesn't replace an earlier one in the notice centre (review F-16). A name the sender typed is shown next to
 * the address, never alone (review F-09). With `hideTitles` (D4), a lock screen shows "a document" instead of the title.
 * DOM-free (the service worker uses it).
 */

export interface Notice {
  title: string;
  body: string;
  /** One notice per agreement. */
  tag: string;
  /** Where a tap goes. */
  url: string;
}

const who = (p: { name: string | null; email: string }) => (p.name && p.name.trim() && !p.name.includes("@") ? `${p.name.trim()} (${p.email})` : p.email);
const names = (list: string[]) => (list.length <= 2 ? list.join(" and ") : `${list.slice(0, -1).join(", ")} and ${list[list.length - 1]}`);
const day = (iso?: string) => (iso ? new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric", timeZone: "UTC" }).format(new Date(iso)) : null);
const link = (agreementId: string) => `/dashboard/agreements?agreement=${encodeURIComponent(agreementId)}`;

const unlockedTag = (agreementId: string, emails: string[]) => `unlocked-${agreementId}-${[...emails].map((e) => e.toLowerCase()).sort().join(",")}`;

export function noticesFor(outcomes: Outcome[], recent: RecentUnlock[], opts: { hideTitles: boolean }): Notice[] {
  const doc = (title: string) => (opts.hideTitles ? "a document" : `"${title}"`);
  const out: Notice[] = [];
  const seen = new Set<string>();
  for (const o of outcomes) {
    const tag = `unlock-${o.agreementId}`;
    const url = link(o.agreementId);
    let n: Notice | null = null;
    if (o.kind === "unlocked") {
      const people = names(o.signers.map(who));
      n = { title: `Unlocked for ${people}`, body: opts.hideTitles ? `${people} can open and sign it now.` : `${o.title} · ${people} can open and sign it now.`, tag: unlockedTag(o.agreementId, o.signers.map((s) => s.email)), url };
    } else if (o.kind === "held") {
      const h = o.signers[0];
      const p = who(h);
      const why = h.reason === "reset" ? `${p}'s key was reset${day(h.at) ? ` on ${day(h.at)}` : ""}.` : h.reason === "changed" ? `${p}'s key isn't the one you used before.` : `Your device couldn't confirm when ${p}'s key was set up.`;
      n = { title: `Check ${p}'s key`, body: `${why} Tap to check and unlock ${doc(o.title)}.`, tag, url };
    } else if (o.kind === "refused") {
      n = { title: `Didn't unlock ${doc(o.title)}`, body: "Attest's record didn't match your copy. Nothing was shared. Tap for details.", tag, url };
    } else if (o.kind === "later" || o.kind === "limit") {
      n = { title: `Tap to finish unlocking ${doc(o.title)}`, body: o.kind === "limit" ? "This device unlocked many documents in a short time, so the rest wait for you." : "It takes a moment longer than usual. Tap to open Attest, and it finishes there.", tag, url };
    } else if (o.kind === "no_list" || o.kind === "no_copy") {
      n = { title: `${names(o.signers.map(who))} ${o.signers.length === 1 ? "is" : "are"} ready for ${doc(o.title)}`, body: "Tap to unlock it.", tag, url };
    }
    if (n && !seen.has(tag)) {
      seen.add(tag);
      out.push(n);
    }
  }
  for (const r of recent) {
    const tag = unlockedTag(r.agreementId, r.signers);
    if (seen.has(tag) || seen.has(`unlock-${r.agreementId}`)) continue;
    seen.add(tag);
    const people = names(r.signers);
    out.push({ title: `Unlocked for ${people}${r.by ? ` by your ${r.by}` : ""}`, body: opts.hideTitles ? `${people} can open and sign it now.` : `${r.title} · ${people} can open and sign it now.`, tag, url: link(r.agreementId) });
  }
  return out;
}
