// Cross-checks src/groth16.mjs against snarkjs on every proof in the given evidence files, and on altered copies.
import { readFileSync } from "node:fs";
import * as snarkjs from "snarkjs";
import { verifyGroth16 } from "./src/groth16.mjs";
const cases = [];
for (const f of process.argv.slice(2)) {
  const e = JSON.parse(readFileSync(f, "utf8"));
  const z = e.verificationKey ? e : e.proof || e.zkProof || (e.findingsClosure && { ...e.findingsClosure });
  if (z && z.verificationKey) cases.push([f.split("/").pop(), z.verificationKey, z.publicSignals, z.proof]);
}
let bad = 0;
for (const [name, vk, sig, proof] of cases) {
  const variants = [
    ["as issued", sig, proof],
    ["signal +1", [String(BigInt(sig[0]) + 1n), ...sig.slice(1)], proof],
    ["last signal changed", [...sig.slice(0, -1), String(BigInt(sig[sig.length - 1]) ^ 1n)], proof],
    ["A and C swapped", sig, { ...proof, pi_a: proof.pi_c, pi_c: proof.pi_a }],
    ["signal out of field", [...sig.slice(0, -1), "21888242871839275222246405745257275088548364400416034343698204186575808495618"], proof],
  ];
  for (const [label, s, p] of variants) {
    const mine = verifyGroth16(vk, s, p);
    let ref; try { ref = await snarkjs.groth16.verify(vk, s, p, { info() {}, debug() {}, warn() {}, error() {} }); } catch { ref = false; }
    if (mine !== ref) bad++;
    console.log(`${mine === ref ? "same" : "DIFFERENT"}  ${String(mine).padEnd(5)} ${name}: ${label}`);
  }
}
process.exit(bad ? 1 : 0);
