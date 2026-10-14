import type { KeyAge } from "@/lib/key-age";
import type { SignerListEntry } from "@/lib/unlock/sealed-list";

/**
 * When a device may pass a document key to a new signer without asking anyone (design 3.2 D, step 7). Pure: the checks
 * that feed it (the sealed list, the directory on Horizen, the key's age) run in src/lib/unlock/run.ts.
 *
 * Automatic only when the key passed every check and is either the key the sending device pinned for that address, or,
 * where it had seen none, a key already listed 14 days ago or the address's first key. Anything else waits for a tap,
 * because the tap's question is the check: a key unlike the pinned one, a reset in the last 14 days, an age that
 * couldn't be read on Horizen. A ready signer the sealed list doesn't name is never unlocked to: Attest added them.
 */

export type HoldReason = "changed" | "reset" | "unchecked";
export type RefuseReason = "not_listed" | "directory";

export type Decision =
  | { action: "unlock" }
  | { action: "hold"; reason: HoldReason; at?: string }
  | { action: "refuse"; reason: RefuseReason }
  | { action: "later" };

export interface SignerCheck {
  /** SHA-256 of the key Attest serves for the signer. */
  fingerprint: string;
  /** The directory check: passed, refused (Attest contradicted Horizen or this device), or to retry. */
  directory: "ok" | "refused" | "retry";
  /** This device pinned another key for the address (directory "ok" but not taken). */
  changedHere?: boolean;
}

export function decide(entry: SignerListEntry | undefined, check: SignerCheck, age: KeyAge | undefined): Decision {
  if (!entry) return { action: "refuse", reason: "not_listed" };
  if (check.directory === "refused") return { action: "refuse", reason: "directory" };
  if (check.directory === "retry") return { action: "later" };
  if (entry.pinned !== null && entry.pinned !== check.fingerprint) return { action: "hold", reason: "changed" };
  if (check.changedHere) return { action: "hold", reason: "changed" };
  if (entry.pinned === check.fingerprint) return { action: "unlock" };
  // None seen when it was sent: the key must be no newer than 14 days, or the address's first.
  if (!age) return { action: "hold", reason: "unchecked" };
  if (!age.recent) return { action: "unlock" };
  if (age.kind === "new") return { action: "unlock" };
  return { action: "hold", reason: age.kind, ...(age.at ? { at: age.at } : {}) };
}
