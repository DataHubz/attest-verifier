// Renderer determinism, on the pinned libraries: the fixture cases must render to the exact bytes Attest's app renders, with no active content
// left. Renderer v2 (test/renderer): a document with a script, an open action and named destinations; one with every
// kind of active content and links that aren't to the web; twenty signers with tiny fields and sixty steps; in each
// variant, the certificate too. Renderer v3 (test/renderer/v3): the same cases, a tester's agreement whose fields reach
// into the labels above them and sit on their lines, a field of every size the composer makes and smaller, turned,
// cropped and offset pages, pages whose content tries to change what follows it or leaves a text object, path, clip,
// marked content or compatibility section open, content in every filter and predictor pdf.js decodes, annotations of
// every kind (drawn as pdf.js prints them, or not), form fields whose appearance pdf.js generates (drawn as pdf.js draws
// them), encrypted documents, and files that can't be read or decrypted, each given a copy.
// Renderer v3's cases are rendered again with every built-in newer than ES2020 removed and a wrong Math.sumPrecise
// installed: the same bytes, so a browser without them re-makes the same copy.
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
  // (For renderer v3 that document isn't clean, so its case is named notclean-hostile-full there.)
  const hostile = cases.find((c) => c.name === "hostile-full" || c.name === "notclean-hostile-full");
  const found = new Set(activeContent(await PDFDocument.load(Buffer.from(hostile.input.original, "base64"))));
  if (found.size < 8) { bad++; console.log(`FAIL ${version}: the detector finds only ${[...found].join(", ")} in the hostile original`); }
  for (const c of cases) {
    const own = { sans: new Uint8Array(fonts.sans), bold: new Uint8Array(fonts.bold), mono: new Uint8Array(fonts.mono), ...(version === "v3" ? { noto: new Uint8Array(fonts.noto), notoBold: new Uint8Array(fonts.notoBold) } : {}) };
    const input = { ...c.input, original: c.input.original === null ? null : new Uint8Array(Buffer.from(c.input.original, "base64")), fonts: own };
    const bytes = await render(input);
    const h = createHash("sha256").update(bytes).digest("hex");
    if (h !== expected[c.name]) { bad++; console.log(`FAIL ${version} ${c.name}: ${h}, expected ${expected[c.name]}`); }
    const left = activeContent(await PDFDocument.load(bytes));
    if (left.length) { bad++; console.log(`FAIL ${version} ${c.name}: active content left (${[...new Set(left)].join(", ")})`); }
  }
  console.log(`renderer ${version}: ${cases.length - bad}/${cases.length} byte for byte`);
  failed += bad;
  total += cases.length;
  if (version !== "v3") continue;
  // The same bytes in an older engine: every case again, with every built-in newer than ES2020 removed and
  // Math.sumPrecise present but wrong (renderer v3 sums glyph widths itself, as pdf.js's Math.sumPrecise does).
  const typed = Object.getPrototypeOf(Uint8Array.prototype);
  const recent = [
    [Math, "sumPrecise"], [Math, "f16round"], [String.prototype, "replaceAll"], [String.prototype, "at"], [String.prototype, "isWellFormed"], [String.prototype, "toWellFormed"],
    ...["at", "findLast", "findLastIndex", "toSorted", "toReversed", "toSpliced", "with"].map((k) => [Array.prototype, k]),
    ...["at", "findLast", "findLastIndex", "toSorted", "toReversed", "with"].map((k) => [typed, k]),
    [Uint8Array, "fromBase64"], [Uint8Array, "fromHex"], [Uint8Array.prototype, "toBase64"], [Uint8Array.prototype, "toHex"], [Uint8Array.prototype, "setFromBase64"], [Uint8Array.prototype, "setFromHex"],
    [Object, "hasOwn"], [Object, "groupBy"], [Map, "groupBy"], [Promise, "withResolvers"], [Promise, "try"], [Array, "fromAsync"], [globalThis, "structuredClone"], [RegExp, "escape"], [Error, "isError"],
    ...["union", "intersection", "difference", "symmetricDifference", "isSubsetOf", "isSupersetOf", "isDisjointFrom"].map((k) => [Set.prototype, k]),
    ...(globalThis.Iterator ? ["map", "filter", "take", "drop", "flatMap", "reduce", "toArray", "forEach", "some", "every", "find"].map((k) => [globalThis.Iterator.prototype, k]) : []),
  ];
  const saved = recent.filter(([o, k]) => Object.prototype.hasOwnProperty.call(o, k)).map(([o, k]) => [o, k, Object.getOwnPropertyDescriptor(o, k)]);
  for (const [o, k] of saved) delete o[k];
  Object.defineProperty(Math, "sumPrecise", { value: () => 1234.5, configurable: true, writable: true });
  let old = 0;
  try {
    for (const c of cases) {
      const own = { sans: new Uint8Array(fonts.sans), bold: new Uint8Array(fonts.bold), mono: new Uint8Array(fonts.mono), noto: new Uint8Array(fonts.noto), notoBold: new Uint8Array(fonts.notoBold) };
      const input = { ...c.input, original: c.input.original === null ? null : new Uint8Array(Buffer.from(c.input.original, "base64")), fonts: own };
      let h;
      try { h = createHash("sha256").update(await render(input)).digest("hex"); } catch (e) { h = String(e); }
      if (h !== expected[c.name]) { old++; console.log(`FAIL v3 ${c.name} without recent built-ins: ${h.slice(0, 120)}, expected ${expected[c.name]}`); }
    }
  } finally {
    delete Math.sumPrecise;
    for (const [o, k, d] of saved) Object.defineProperty(o, k, d);
  }
  console.log(`renderer v3 without the ${saved.length} built-ins newer than ES2020 this engine has, and a wrong Math.sumPrecise: ${cases.length - old}/${cases.length} byte for byte`);
  failed += old;
  total += cases.length;
}
process.exit(failed || pinned ? 1 : 0);
