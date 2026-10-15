// Renderer determinism, on the pinned libraries: the fixture cases must render to the exact bytes Attest's app renders, with no active content
// left. Renderer v2 (test/renderer): a document with a script, an open action and named destinations; one with every
// kind of active content and links that aren't to the web; twenty signers with tiny fields and sixty steps; in each
// variant, the certificate too. Renderer v3 (test/renderer/v3): the same cases, a tester's agreement whose fields reach
// into the labels above them and sit on their lines, and a field of every size the composer makes and smaller.
import { build } from "esbuild";
import { readFileSync, rmSync } from "node:fs";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import path from "node:path";

const require = createRequire(import.meta.url);
const { PDFDocument } = require("pdf-lib");
// The renderers' bytes depend on these libraries: pinned exactly in package.json, and resolved at those versions.
const pkg = JSON.parse(readFileSync("package.json", "utf8"));
let pinned = 0;
for (const [name, version] of [["pdf-lib", "1.17.1"], ["@pdf-lib/fontkit", "1.1.1"], ["qrcode", "1.5.4"]]) {
  const resolved = JSON.parse(readFileSync(require.resolve(`${name}/package.json`), "utf8")).version;
  if (pkg.devDependencies[name] !== version || resolved !== version) { pinned++; console.log(`FAIL ${name}: package.json ${pkg.devDependencies[name]}, resolved ${resolved}, must be exactly ${version}`); }
}
console.log(`renderer libraries: ${3 - pinned}/3 pinned and resolved exactly`);
const fonts = { sans: readFileSync("src/fonts/instrument-sans-400.ttf"), bold: readFileSync("src/fonts/instrument-sans-600.ttf"), mono: readFileSync("src/fonts/jetbrains-mono-400.ttf"), noto: readFileSync("src/fonts/noto-sans-400.ttf"), notoBold: readFileSync("src/fonts/noto-sans-700.ttf") };
let failed = 0;
let total = 0;
for (const [version, dir] of [["v2", "test/renderer"], ["v3", "test/renderer/v3"]]) {
  const file = path.join(path.dirname(new URL(import.meta.url).pathname), `.renderer-${version}-${process.pid}.cjs`);
  // pdf-lib stays external, so the documents this test loads are of the same classes the renderer checks.
  await build({ entryPoints: [`src/renderer/${version}.ts`], bundle: true, platform: "node", format: "cjs", outfile: file, logLevel: "error", external: ["pdf-lib", "@pdf-lib/fontkit", "qrcode"] });
  const mod = require(file);
  rmSync(file);
  const render = version === "v2" ? mod.renderV2 : mod.renderV3;
  const { activeContent } = mod;
  const { cases } = JSON.parse(readFileSync(`${dir}/cases.json`, "utf8"));
  const expected = JSON.parse(readFileSync(`${dir}/expected.json`, "utf8"));
  let bad = 0;
  // The detector itself: the hostile original carries active content of every kind it looks for.
  const hostile = cases.find((c) => c.name === "hostile-full");
  const found = new Set(activeContent(await PDFDocument.load(Buffer.from(hostile.input.original, "base64"))));
  if (found.size < 8) { bad++; console.log(`FAIL ${version}: the detector finds only ${[...found].join(", ")} in the hostile original`); }
  for (const c of cases) {
    const own = { sans: new Uint8Array(fonts.sans), bold: new Uint8Array(fonts.bold), mono: new Uint8Array(fonts.mono), ...(version === "v3" ? { noto: new Uint8Array(fonts.noto), notoBold: new Uint8Array(fonts.notoBold) } : {}) };
    const bytes = await render({ ...c.input, original: c.input.original === null ? null : new Uint8Array(Buffer.from(c.input.original, "base64")), fonts: own });
    const h = createHash("sha256").update(bytes).digest("hex");
    if (h !== expected[c.name]) { bad++; console.log(`FAIL ${version} ${c.name}: ${h}, expected ${expected[c.name]}`); }
    const left = activeContent(await PDFDocument.load(bytes));
    if (left.length) { bad++; console.log(`FAIL ${version} ${c.name}: active content left (${[...new Set(left)].join(", ")})`); }
  }
  console.log(`renderer ${version}: ${cases.length - bad}/${cases.length} byte for byte`);
  failed += bad;
  total += cases.length;
}
process.exit(failed || pinned ? 1 : 0);
