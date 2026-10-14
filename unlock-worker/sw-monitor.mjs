#!/usr/bin/env node
// The unlock worker monitor (design 3.5, Phase 1 item 9). Anyone can run it; it needs nothing from Attest but the file
// Attest serves, and nothing from this repository: plain Node 18+, no dependencies.
//
// It fetches the worker Attest serves at /sw.js (as a browser updating it does, bypassing caches), hashes it, reads its
// version from its first line, and asks Horizen whether Attest's platform organization anchored
// sha256("attest.unlock-worker.v1|" + version + "|" + sha256(file)) on AttestRegistryV3. A worker that isn't anchored
// is one nobody can check against the published, reproducible source (src/unlock-sw/sw.ts, built with
// scripts/unlock/build-sw.mjs): the monitor says so and exits 1.
//
//   node scripts/unlock/sw-monitor.mjs [--origin https://attest.datahubz.com] [--rpc <horizen rpc>] [--every <minutes>]
//                                      [--expect <sha256>]   (also require this exact build)
//
// Run it from outside Attest's infrastructure, on a schedule (--every): the page can't vouch for the worker, because a
// hostile build would serve the page too. Exit code 1 (or a line with "ok": false) is the alert.
import { createHash } from "node:crypto";

const args = Object.fromEntries(process.argv.slice(2).reduce((a, v, i, all) => (v.startsWith("--") ? [...a, [v.slice(2), all[i + 1]?.startsWith("--") ? true : (all[i + 1] ?? true)]] : a), []));
const ORIGIN = String(args.origin ?? "https://attest.datahubz.com").replace(/\/+$/, "");
const RPC = String(args.rpc ?? "https://horizen.calderachain.xyz/http");
const REGISTRY = String(args.registry ?? "0xF44Ed281005c7d506Dc50829a3E24655837FBF75");
// Attest's platform organization wallet, the one every verifier pins for builds it serves.
const PLATFORM = String(args.wallet ?? "0xdEa7B859DcBd34deB8dc910b5b36d6ACdBeC6F3a");

const sha256 = (b) => createHash("sha256").update(b).digest("hex");
// The first four bytes of keccak256("anchoredAt(address,bytes32)") (cast sig "anchoredAt(address,bytes32)").
const SELECTOR = "0xf8c2919d";

async function anchoredAt(valueHex) {
  const data = SELECTOR + PLATFORM.slice(2).toLowerCase().padStart(64, "0") + valueHex.padStart(64, "0");
  const res = await fetch(RPC, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_call", params: [{ to: REGISTRY, data }, "latest"] }) });
  const j = await res.json();
  if (!j.result) throw new Error(`Horizen: ${j.error?.message ?? "no result"}`);
  return Number(BigInt(j.result));
}

async function once() {
  const at = new Date().toISOString();
  const res = await fetch(`${ORIGIN}/sw.js`, { cache: "no-store", headers: { "Service-Worker": "script", "Cache-Control": "no-cache" } });
  if (!res.ok) return { ok: false, at, problem: `GET ${ORIGIN}/sw.js answered ${res.status}` };
  const bytes = Buffer.from(await res.arrayBuffer());
  const hash = sha256(bytes);
  const version = /Attest unlock worker (\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)/.exec(bytes.subarray(0, 300).toString("utf8"))?.[1] ?? null;
  if (!version) return { ok: false, at, sha256: hash, problem: "the served worker doesn't name its version" };
  const value = sha256(`attest.unlock-worker.v1|${version}|${hash}`);
  const when = await anchoredAt(value);
  const expected = args.expect ? String(args.expect).toLowerCase() === hash : true;
  if (!when) return { ok: false, at, version, sha256: hash, value, problem: "this build isn't anchored on Horizen by Attest's platform organization" };
  if (!expected) return { ok: false, at, version, sha256: hash, value, anchoredAt: new Date(when * 1000).toISOString(), problem: `the served build isn't the one expected (${args.expect})` };
  return { ok: true, at, version, sha256: hash, value, anchoredAt: new Date(when * 1000).toISOString() };
}

const every = Number(args.every ?? 0);
for (;;) {
  let r;
  try {
    r = await once();
  } catch (e) {
    r = { ok: false, at: new Date().toISOString(), problem: e instanceof Error ? e.message : String(e) };
  }
  console.log(JSON.stringify(r));
  if (!every) process.exit(r.ok ? 0 : 1);
  await new Promise((s) => setTimeout(s, every * 60_000));
}
