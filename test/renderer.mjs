// Renderer v2 determinism: the fixture cases (a document with a script, an open action and named destinations; one with
// every kind of active content and links that aren't to the web; twenty signers with tiny fields and sixty steps;
// in each variant, the certificate too) must render
// to the exact bytes Attest's app renders (test/renderer/expected.json, SHA-256), with no active content left.
import { build } from "esbuild";
import { readFileSync, rmSync } from "node:fs";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import path from "node:path";

const file = path.join(path.dirname(new URL(import.meta.url).pathname), `.renderer-${process.pid}.cjs`);
// pdf-lib stays external, so the documents this test loads are of the same classes the renderer checks.
await build({ entryPoints: ["src/renderer/v2.ts"], bundle: true, platform: "node", format: "cjs", outfile: file, logLevel: "error", external: ["pdf-lib", "@pdf-lib/fontkit", "qrcode"] });
const require = createRequire(import.meta.url);
const { renderV2, activeContent } = require(file);
const { PDFDocument } = require("pdf-lib");
rmSync(file);
const fonts = { sans: readFileSync("src/fonts/instrument-sans-400.ttf"), bold: readFileSync("src/fonts/instrument-sans-600.ttf"), mono: readFileSync("src/fonts/jetbrains-mono-400.ttf") };
const { cases } = JSON.parse(readFileSync("test/renderer/cases.json", "utf8"));
const expected = JSON.parse(readFileSync("test/renderer/expected.json", "utf8"));
let failed = 0;
// The detector itself: the hostile original carries active content of every kind it looks for.
const hostile = cases.find((c) => c.name === "hostile-full");
const found = new Set(activeContent(await PDFDocument.load(Buffer.from(hostile.input.original, "base64"))));
if (found.size < 8) { failed++; console.log(`FAIL the detector finds only ${[...found].join(", ")} in the hostile original`); }
for (const c of cases) {
  const bytes = await renderV2({ ...c.input, original: c.input.original === null ? null : new Uint8Array(Buffer.from(c.input.original, "base64")), fonts: { sans: new Uint8Array(fonts.sans), bold: new Uint8Array(fonts.bold), mono: new Uint8Array(fonts.mono) } });
  const h = createHash("sha256").update(bytes).digest("hex");
  if (h !== expected[c.name]) { failed++; console.log(`FAIL ${c.name}: ${h}, expected ${expected[c.name]}`); }
  const left = activeContent(await PDFDocument.load(bytes));
  if (left.length) { failed++; console.log(`FAIL ${c.name}: active content left (${[...new Set(left)].join(", ")})`); }
}
console.log(`renderer: ${cases.length - failed}/${cases.length} byte for byte`);
process.exit(failed ? 1 : 0);
