// The signed-copy structure corpus (test/structure/manifest.json): every case read by the verifier's own
// readSealedCopy, loaded from src/main.js. Genuine copies must be read; each forged one must be refused, for its reason.
import { readFileSync } from "node:fs";
import vm from "node:vm";

const element = () => ({ addEventListener() {}, set textContent(_v) {}, set innerHTML(_v) {}, set placeholder(_v) {}, value: "" });
const context = vm.createContext({ window: {}, document: { getElementById: element }, TextEncoder, TextDecoder, crypto, atob, btoa, fetch, URL, Blob, Response, console });
vm.runInContext(readFileSync(new URL("../src/main.js", import.meta.url), "utf8"), context, { filename: "main.js" });
const manifest = JSON.parse(readFileSync(new URL("structure/manifest.json", import.meta.url), "utf8"));
let failed = 0;
for (const c of manifest) {
  const bytes = new Uint8Array(readFileSync(new URL(`structure/${c.file}`, import.meta.url)));
  context.input = { bytes, length: c.length };
  const r = vm.runInContext(`(() => { try { return { ok: true, names: readSealedCopy(input.bytes, input.length).map((f) => f.name) }; } catch (e) { return { ok: false, why: e.message, pdf: e instanceof PdfError }; } })()`, context);
  const good = c.expect === "ok" ? r.ok : !r.ok && r.pdf && r.why.includes(c.expect);
  if (!good) { failed++; console.log(`FAIL ${c.name}: expected ${c.expect}, got ${JSON.stringify(r)}`); }
}
console.log(`structure: ${manifest.length - failed}/${manifest.length} as expected`);
process.exit(failed ? 1 : 0);
