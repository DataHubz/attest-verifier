// Builds attest-verifier.html: the page (src/page.html), its logic (src/main.js) and the libraries it uses
// (src/libs.mjs, bundled with esbuild from the exact versions in package-lock.json), in one self-contained file.
// Reproducible: the same sources and lockfile produce the same bytes, so anyone can compare its SHA-256 with a release.
import { build } from "esbuild";
import { readFileSync, writeFileSync, readdirSync, existsSync } from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";

// Packages that declare browser versions of their files in "browser" (alongside "exports", which bundlers follow
// first): use those files, as their authors intend for browsers. Without it, Node-only code (Buffer, node:crypto)
// would be bundled.
function browserFiles() {
  const map = new Map();
  const visit = (dir) => {
    for (const name of readdirSync(dir)) {
      const pkgDir = path.join(dir, name);
      if (name.startsWith("@")) { visit(pkgDir); continue; }
      const pj = path.join(pkgDir, "package.json");
      if (!existsSync(pj)) continue;
      const browser = JSON.parse(readFileSync(pj, "utf8")).browser;
      if (browser && typeof browser === "object")
        for (const [from, to] of Object.entries(browser))
          if (from.startsWith("./") && typeof to === "string") map.set(path.resolve(pkgDir, from), path.resolve(pkgDir, to));
      if (existsSync(path.join(pkgDir, "node_modules"))) visit(path.join(pkgDir, "node_modules"));
    }
  };
  visit(path.resolve("node_modules"));
  return map;
}
const remap = browserFiles();
const browserField = {
  name: "browser-field",
  setup(b) {
    b.onLoad({ filter: /\.(c|m)?js$/ }, (args) => {
      const to = remap.get(args.path);
      return to ? { contents: readFileSync(to, "utf8"), resolveDir: path.dirname(to), loader: "js" } : undefined;
    });
  },
};

const libs = await build({
  plugins: [browserField],
  entryPoints: ["src/libs.mjs"],
  bundle: true,
  minify: true,
  format: "iife",
  platform: "browser",
  target: "es2020",
  legalComments: "eof",
  // Single-file page: modules that resolve paths from their own URL resolve them from the page.
  define: { "process.env.NODE_ENV": '"production"', "import.meta.url": "document.baseURI" },
  write: false,
  metafile: true,
  logLevel: "error",
});

// Every bundled package's license, embedded at the end of the file (several licenses require their notice to
// travel with every copy).
function notices(metafile) {
  const pkgs = new Map();
  for (const input of Object.keys(metafile.inputs)) {
    const m = /node_modules\/((?:@[^/]+\/)?[^/]+)\//.exec(input.split("node_modules/").length > 2 ? "node_modules/" + input.split("node_modules/").pop() : input);
    if (!m) continue;
    const dir = input.slice(0, input.lastIndexOf("node_modules/" + m[1]) + ("node_modules/" + m[1]).length);
    if (!pkgs.has(dir)) pkgs.set(dir, m[1]);
  }
  const out = [];
  for (const [dir, name] of [...pkgs].sort((a, b) => a[1].localeCompare(b[1]))) {
    const pj = JSON.parse(readFileSync(path.join(dir, "package.json"), "utf8"));
    const file = readdirSync(dir).find((f) => /^(licen[sc]e|copying)(\.|$)/i.test(f));
    const text = file ? readFileSync(path.join(dir, file), "utf8").trim() : `License: ${pj.license}`;
    out.push(`${name}@${pj.version} (${pj.license})\n\n${text}`);
  }
  return out.join("\n\n");
}
const thirdParty = notices(libs.metafile).replace(/--/g, "- -");
const safe = (js) => js.replace(/<\/script/gi, "<\\/script");
const page = readFileSync("src/page.html", "utf8")
  .replace("/*LIBS*/", () => safe(libs.outputFiles[0].text))
  .replace("/*MAIN*/", () => safe(readFileSync("src/main.js", "utf8")))
  .replace("</html>", () => `<!--\nThird-party software bundled in this file, and its licenses:\n\n${thirdParty}\n-->\n</html>`);
writeFileSync("attest-verifier.html", page);
console.log(`attest-verifier.html ${page.length} bytes, sha256 ${createHash("sha256").update(page).digest("hex")}`);
