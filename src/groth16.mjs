// Groth16 verification over BN254 (alt_bn128), for proofs and keys in snarkjs JSON form. The pairing is
// @noble/curves (MIT, audited); this file is the Groth16 equation:
//   e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1,   vk_x = IC[0] + sum(s_i * IC[i+1])
import { bn254 } from "@noble/curves/bn254";

const { Fp2, Fp12, Fr } = bn254.fields;
const G1 = bn254.G1.ProjectivePoint;
const G2 = bn254.G2.ProjectivePoint;

function g1([x, y, z]) {
  if (BigInt(z) === 0n) return G1.ZERO;
  const p = G1.fromAffine({ x: BigInt(x), y: BigInt(y) });
  p.assertValidity();
  return p;
}
function g2([x, y, z]) {
  if (BigInt(z[0]) === 0n && BigInt(z[1]) === 0n) return G2.ZERO;
  const p = G2.fromAffine({ x: Fp2.fromBigTuple([BigInt(x[0]), BigInt(x[1])]), y: Fp2.fromBigTuple([BigInt(y[0]), BigInt(y[1])]) });
  p.assertValidity();
  return p;
}

/** true when `proof` is a valid Groth16 proof for `publicSignals` under `vk`. Malformed input is invalid. */
export function verifyGroth16(vk, publicSignals, proof) {
  try {
    if (vk.protocol !== "groth16" || (vk.curve && vk.curve !== "bn128")) return false;
    if (!Array.isArray(publicSignals) || publicSignals.length !== vk.IC.length - 1) return false;
    const s = publicSignals.map((x) => BigInt(x));
    if (s.some((x) => x < 0n || x >= Fr.ORDER)) return false;
    let vkx = g1(vk.IC[0]);
    for (let i = 0; i < s.length; i++) if (s[i] !== 0n) vkx = vkx.add(g1(vk.IC[i + 1]).multiply(s[i]));
    const A = g1(proof.pi_a), B = g2(proof.pi_b), C = g1(proof.pi_c);
    const result = bn254.pairingBatch([
      { g1: A.negate(), g2: B },
      { g1: g1(vk.vk_alpha_1), g2: g2(vk.vk_beta_2) },
      { g1: vkx, g2: g2(vk.vk_gamma_2) },
      { g1: C, g2: g2(vk.vk_delta_2) },
    ]);
    return Fp12.eql(result, Fp12.ONE);
  } catch {
    return false;
  }
}
