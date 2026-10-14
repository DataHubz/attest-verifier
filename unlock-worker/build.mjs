// Build Attest's unlock worker from this folder: the same source, esbuild 0.28.2 and configuration as Attest's
// production build, so it gives the same bytes. Prints the version and the SHA-256 to compare with what Attest serves
// at https://attest.datahubz.com/sw.js and with the anchor on Horizen (see README.md).
//   npm install && node build.mjs [out.js]
import { build } from "esbuild";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const version = /UNLOCK_WORKER_VERSION = "([^"]+)"/.exec(readFileSync("src/unlock-sw/sw.ts", "utf8"))[1];
const r = await build({
  entryPoints: ["src/unlock-sw/sw.ts"],
  bundle: true,
  write: false,
  format: "iife",
  target: ["es2020"],
  platform: "browser",
  charset: "utf8",
  legalComments: "none",
  logLevel: "warning",
  tsconfig: "tsconfig.json",
  define: {
    "process.env.NODE_ENV": "\"production\"",
    "process.env.NEXT_PUBLIC_KEY_DIRECTORY_CONTRACT": "\"0x36ec83986e59F2936E6dcbf35ddA239C879d0Bf5\"",
    "process.env.NEXT_PUBLIC_HORIZEN_RPC_URL": "\"\"",
    "process.env.NEXT_PUBLIC_KEY_DIRECTORY_DEV_SKIP": "\"\""
  },
  banner: { js: `/* Attest unlock worker ${version}. Source: src/unlock-sw/sw.ts, built with scripts/unlock/build-sw.mjs (esbuild). */` },
});
const bytes = r.outputFiles[0].contents;
const sha = createHash("sha256").update(bytes).digest("hex");
if (process.argv[2]) writeFileSync(process.argv[2], bytes);
const value = createHash("sha256").update(`attest.unlock-worker.v1|${version}|${sha}`).digest("hex");
console.log(JSON.stringify({ version, sha256: sha, anchoredValue: value }));
