// Horizen proofs (test/horizen/game-52.json: real proofs from an archive of Attest's registries on Horizen, at the
// block Horizen's dispute game #52 on Base claims). The verifier's own code, loaded from src/main.js and
// src/horizen-proof.mts, checks them with Base's answers mocked: no network. A valid proof verifies; a changed node,
// header, value, slot or account, another game, a game for another chain or one its challenger won are refused; a
// game that hasn't resolved is reported as pending; a lookup the proof doesn't cover goes to Attest's archive.
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { transform } from "esbuild";
import { keccak_256 } from "@noble/hashes/sha3";

const source = readFileSync(new URL("../src/horizen-proof.mts", import.meta.url), "utf8");
const proof = await import("data:text/javascript;base64," + Buffer.from((await transform(source, { loader: "ts", format: "esm" })).code).toString("base64"));
const fx = JSON.parse(readFileSync(new URL("horizen/game-52.json", import.meta.url), "utf8"));
const clone = () => JSON.parse(JSON.stringify(fx.bundle));

const W = (n) => BigInt(n).toString(16).padStart(64, "0");
const A = (a) => a.replace(/^0x/, "").toLowerCase().padStart(64, "0");
const BASE_REGISTRY = "0xa4b9c8faecf6adaed5bdc6136d3ab55f8791b80e";
const PORTAL = "0x78e794d10a355468a0e7a14aa1a9f9a253d78784";
const FACTORY = "0x4e2c464380fb26b0c5f9b90edf754c4e2a8d1a90";
const GAME = fx.bundle.game.address.toLowerCase();

// Base as the mocks answer it; each case changes what it needs.
let base, archive, horizenUp;
const reset = () => {
  base = { factory: FACTORY, gameType: 1, createdAt: fx.game.createdAt, proxy: GAME, rootClaim: fx.game.rootClaim, l2Block: fx.bundle.block.number, l2Chain: 26514, status: 2, blacklisted: 0, anchors: {}, registered: {} };
  archive = { status: 404, body: null, asked: [] };
  horizenUp = false;
};
const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const result = (r) => json(200, { jsonrpc: "2.0", id: 1, result: r });
function baseCall(to, data) {
  const sel = data.slice(0, 10), a1 = data.slice(10, 74);
  if (to === PORTAL && sel === "0xf2b4e617") return "0x" + A(base.factory);
  if (to === PORTAL && sel === "0x45884d32") return "0x" + W(a1 === A(GAME) ? base.blacklisted : 0);
  if (to === FACTORY && sel === "0xbb8aa1fc") return "0x" + W(base.gameType) + W(base.createdAt) + A(base.proxy);
  if (to === GAME && sel === "0xbcef3b55") return "0x" + A(base.rootClaim);
  if (to === GAME && sel === "0x8b85902b") return "0x" + W(base.l2Block);
  if (to === GAME && sel === "0xd6ae3cd5") return "0x" + W(base.l2Chain);
  if (to === GAME && sel === "0x200d2ed2") return "0x" + W(base.status);
  if (to === BASE_REGISTRY && sel === "0xf8c2919d") return "0x" + W(base.anchors[`0x${a1.slice(24)} ${data.slice(74)}`] || 0);
  if (to === BASE_REGISTRY && sel === "0xaaea3d9c") return "0x" + W(base.registered[`0x${a1.slice(24)}`] || 0);
  if (to === BASE_REGISTRY && sel === "0x1947aee4") return "0x" + W(0);
  return "0x" + W(0);
}
async function fetchMock(url, init) {
  url = String(url);
  if (url.startsWith("https://attest.datahubz.com/api/horizen/proofs")) {
    archive.asked.push(url);
    return archive.status === 200 ? json(200, archive.body) : new Response("", { status: archive.status });
  }
  const body = JSON.parse(init.body);
  if (url.startsWith("https://horizen.calderachain.xyz")) {
    if (!horizenUp) throw new TypeError("fetch failed");
    if (body.method === "eth_chainId") return result("0x6792");
    const data = body.params[0].data.toLowerCase(), sel = data.slice(0, 10);
    if (sel === "0xf8c2919d") return result("0x" + W(`0x${data.slice(34, 74)}` === fx.v3.wallet && `0x${data.slice(74)}` === fx.v3.value ? fx.v3.at : 0));
    if (sel === "0xaaea3d9c") return result("0x" + W(1789000000));
    return result("0x" + W(0));
  }
  if (url === "https://mainnet.base.org") {
    if (body.method === "eth_chainId") return result("0x2105");
    if (body.method === "eth_call") return result(baseCall(body.params[0].to.toLowerCase(), body.params[0].data.toLowerCase()));
    return result(null);
  }
  throw new TypeError(`unexpected fetch ${url}`);
}

const element = () => ({ addEventListener() {}, querySelectorAll: () => [], set textContent(_v) {}, set innerHTML(_v) {}, set placeholder(_v) {}, value: "" });
const context = vm.createContext({
  window: { AttestLibs: { horizen: { ...proof, keccak: (b) => keccak_256(b) } } },
  document: { getElementById: element }, TextEncoder, TextDecoder, crypto, atob, btoa, fetch: fetchMock, URL, Blob, Response, AbortSignal, console,
});
vm.runInContext(readFileSync(new URL("../src/main.js", import.meta.url), "utf8"), context, { filename: "main.js" });
const run = async (code, input) => {
  context.input = input;
  return vm.runInContext(`(async () => { ${code} })()`, context);
};
const fresh = (bundles) => run("carried = input; proofProblems = new Set(); results = []; baseCache.clear(); archiveCache.clear(); nodes.clear(); statusCache.clear();", bundles);
const checked = (b) => run("return provenBundle(input).then((p) => ({ state: p.state, why: p.why || '' }));", b);
const attestedOn = (value, wallet, chainId) => run("return attested(input.value, input.wallet, input.chainId);", { value, wallet, chainId });

let failed = 0, passed = 0;
const test = async (name, f) => {
  reset();
  await fresh([]);
  try { await f(); passed++; console.log(`ok   ${name}`); } catch (e) { failed++; console.log(`FAIL ${name}: ${e.message}`); }
};
const assert = (ok, msg) => { if (!ok) throw new Error(msg); };
const at = (s) => new Date(s * 1000).toISOString();
const flip = (hex, i) => hex.slice(0, i) + (hex[i] === "0" ? "1" : "0") + hex.slice(i + 1);
const refused = async (b, why) => {
  await fresh([b]);
  const p = await checked(b);
  assert(p.state === "bad", `accepted (${p.state})`);
  if (why) assert(p.why.includes(why), `refused for another reason: ${p.why}`);
  const r = await attestedOn(fx.v3.value, fx.v3.wallet, 26514);
  assert(!r.anchored && r.via === "archive", "a refused proof was used");
};

await test("a valid proof verifies: V3 anchor by the platform wallet, at its proven time", async () => {
  const b = clone();
  await fresh([b]);
  assert((await checked(b)).state === "ok", "proof refused");
  const r = await attestedOn(fx.v3.value, fx.v3.wallet, 26514);
  assert(r.anchored && r.ok && r.via === "proof" && r.chainId === 26514 && r.at === at(fx.v3.at), JSON.stringify(r));
});

await test("a V2 anchor is found by value, with its proven anchorer and the anchorer's status", async () => {
  await fresh([clone()]);
  const r = await attestedOn(fx.v2.value, null, 26514);
  assert(r.anchored && r.wallet === fx.v2.wallet && r.at === at(fx.v2.at) && r.via === "proof", JSON.stringify(r));
});

await test("a value with no chain named is looked up on Base, then in Horizen's history", async () => {
  await fresh([clone()]);
  const r = await attestedOn(fx.v3.value, fx.v3.wallet, null);
  assert(r.anchored && r.ok && r.chainId === 26514, JSON.stringify(r));
});

await test("a Base anchor is read from Base, with the wallet's registration on Base", async () => {
  base.anchors[`${fx.v3.wallet} ${fx.v3.value.slice(2)}`] = 1793000000;
  base.registered[fx.v3.wallet] = 1792900000;
  await fresh([]);
  const r = await attestedOn(fx.v3.value, fx.v3.wallet, null);
  assert(r.anchored && r.ok && r.chainId === 8453 && r.via === "node", JSON.stringify(r));
});

await test("an anchor named by its Horizen transaction verifies with Horizen stopped, and says the transaction wasn't read", async () => {
  await fresh([clone()]);
  const r = await run("return onChain('The receipt', input.value, { txHash: input.txHash, chainId: 26514 }).then((x) => ({ x, results }));", { value: fx.v3.value.slice(2), txHash: fx.v3.txHash });
  assert(r.x && r.x.wallet === fx.v3.wallet, JSON.stringify(r.results));
  assert(r.results.length === 1 && r.results[0].state === "ok" && /not read: Horizen stopped/.test(r.results[0].detail) && /dispute game #52/.test(r.results[0].detail), JSON.stringify(r.results));
});

await test("a Horizen node, while one answers, is read like Base's", async () => {
  horizenUp = true;
  await fresh([]);
  const r = await attestedOn(fx.v3.value, fx.v3.wallet, 26514);
  assert(r.anchored && r.ok && r.via === "node" && r.at === at(fx.v3.at), JSON.stringify(r));
});

await test("receipt evidence v3 carrying a Horizen proof verifies end to end", async () => {
  const ev = { format: "attest.receipt_evidence.v3", receipt: { id: "rcpt_01TEST", sha256: fx.v3.value.slice(2) }, anchor: { type: "value", chainId: 26514, txHash: fx.v3.txHash, from: fx.v3.wallet }, horizen: clone() };
  const r = await run("return verify(input, { pdf: null, outer: null }).then(() => results);", ev);
  const anchor = r.find((x) => x.title.startsWith("The receipt"));
  assert(anchor && anchor.state === "ok" && !r.some((x) => x.state === "bad" || x.state === "warn"), JSON.stringify(r));
});

await test("an anchor on another chain fails, and a newer format is reported as newer", async () => {
  const r = await run("return verify(input, { pdf: null, outer: null }).then(() => results);", { format: "attest.receipt_evidence.v3", receipt: { id: "rcpt_01TEST", sha256: fx.v3.value.slice(2) }, anchor: { type: "value", chainId: 1, txHash: fx.v3.txHash, from: fx.v3.wallet } });
  assert(r.some((x) => x.state === "bad" && /not on Base or Horizen/.test(x.title)), JSON.stringify(r));
  const n = await run("return verify(input, { pdf: null, outer: null }).then(() => results);", { format: "attest.receipt_evidence.v4" });
  assert(n.length === 1 && /newer evidence format/.test(n[0].title), JSON.stringify(n));
});

await test("a changed byte in a storage proof node is refused", async () => {
  const b = clone();
  const s = b.accounts[0].storage[0];
  s.proof[1] = flip(s.proof[1], s.proof[1].length - 3);
  await refused(b);
});

await test("a changed byte in an account proof node is refused", async () => {
  const b = clone();
  b.accounts[0].accountProof[2] = flip(b.accounts[0].accountProof[2], 40);
  await refused(b);
});

await test("a changed header is refused", async () => {
  const b = clone();
  b.block.headerRlp = flip(b.block.headerRlp, 200);
  await refused(b, "doesn't hash");
});

await test("a changed value is refused", async () => {
  const b = clone();
  b.accounts[0].storage[0].value = "0x" + (BigInt(fx.v3.at) + 1n).toString(16);
  await refused(b, "the proof gives");
});

await test("a slot that isn't the one its meaning names is refused", async () => {
  const b = clone();
  const [x, y] = b.accounts[0].storage;
  [x.slot, y.slot] = [y.slot, x.slot];
  await refused(b, "isn't at the slot");
});

await test("a proof of an account other than Attest's registries is refused", async () => {
  const b = clone();
  b.accounts[0].address = "0x0000000000000000000000000000000000000016";
  await refused(b, "not one of Attest's registries");
});

await test("a game outside the pinned factory is refused", async () => {
  const b = clone();
  b.game.factory = "0x0000000000000000000000000000000000000001";
  await refused(b, "pinned dispute game factory");
});

await test("a game the factory lists under another address is refused", async () => {
  base.proxy = "0x00000000000000000000000000000000000000aa";
  await refused(clone(), "the factory's game #52");
});

await test("a game of another type (permissionless) is refused", async () => {
  base.gameType = 0;
  await refused(clone(), "not Horizen's permissioned type");
});

await test("a game whose root claim is another output root is refused", async () => {
  base.rootClaim = flip(fx.game.rootClaim, 10);
  await refused(clone(), "claims output root");
});

await test("a game its challenger won is refused", async () => {
  base.status = 1;
  await refused(clone(), "won by its challenger");
});

await test("a blacklisted game is refused", async () => {
  base.blacklisted = 1;
  await refused(clone(), "blacklisted");
});

await test("a portal that names another factory is refused", async () => {
  base.factory = "0x00000000000000000000000000000000000000bb";
  await refused(clone(), "no longer names the pinned");
});

await test("a game for another chain is refused", async () => {
  base.l2Chain = 10;
  await refused(clone(), "is for chain 10");
});

await test("a proof that says it is of another chain is refused", async () => {
  const b = clone();
  b.chainId = 1;
  await refused(b, "not of Horizen");
});

await test("a game that hasn't resolved is reported as pending, with when it resolves", async () => {
  base.status = 0;
  await fresh([clone()]);
  const r = await run("return onChain('The receipt', input.value, { wallet: input.wallet, chainId: 26514 }).then((x) => ({ x, results }));", { value: fx.v3.value.slice(2), wallet: fx.v3.wallet });
  const w = r.results[0];
  assert(r.x && w.state === "warn" && w.title.includes(at(fx.game.createdAt + 302400).replace("T", " ").replace(/\.\d+Z$/, " UTC")), JSON.stringify(r.results));
});

await test("a lookup the carried proof doesn't cover goes to Attest's archive, checked the same way", async () => {
  const b = clone();
  b.accounts[0].storage = b.accounts[0].storage.filter((s) => !s.meaning.startsWith("anchoredAt"));
  archive = { status: 200, body: clone(), asked: [] };
  await fresh([b]);
  const r = await attestedOn(fx.v3.value, fx.v3.wallet, 26514);
  assert(r.anchored && r.ok && r.via === "archive" && archive.asked.length === 1 && archive.asked[0].includes(`q=${fx.v3.wallet}:${fx.v3.value.slice(2)}`), JSON.stringify(r));
});

await test("a refused proof from the archive isn't used", async () => {
  const b = clone();
  b.accounts[0].storage[0].value = "0x1";
  archive = { status: 200, body: b, asked: [] };
  await fresh([]);
  let threw = false;
  try { await attestedOn(fx.v3.value, fx.v3.wallet, 26514); } catch { threw = true; }
  assert(threw, "an anchor was reported from a refused proof");
});

await test("with no Horizen node, proof or archive, the check says it couldn't run, never 'not anchored'", async () => {
  archive.status = 503;
  await fresh([]);
  const r = await run("return onChain('The receipt', input.value, { wallet: input.wallet }).then(() => results);", { value: fx.v3.value.slice(2), wallet: fx.v3.wallet });
  assert(r.length === 1 && r[0].state === "warn" && /Horizen stopped/.test(r[0].detail), JSON.stringify(r));
});

console.log(`horizen: ${passed}/${passed + failed} as expected`);
process.exit(failed ? 1 : 0);
