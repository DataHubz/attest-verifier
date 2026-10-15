// The characters renderer v3 ("attest.render.v3") prints. Shared, byte for byte, with the open verifier
// (DataHubz/attest-verifier, src/renderer/charset-v3.ts). Frozen with v3: a later renderer adds scripts (CJK and
// others) with a charset of its own, and v3 stays as it is.
//
// Latin with its extensions and IPA, Greek, Cyrillic with its supplement, Vietnamese (Latin Extended Additional),
// combining marks, punctuation and spaces, superscripts and subscripts, currency, letterlike symbols and number forms,
// the Latin ligatures and U+FFFD: every character Noto Sans 2.015, regular and bold, has in those blocks
// (public/fonts/pdf/noto-sans-400.ttf and noto-sans-700.ttf, cut to these by scripts/fonts/noto-subset.py), and no
// control, format, line or paragraph separator.

/** First and last code point of each run of printable characters, in order. */
export const PRINTABLE_V3: readonly number[] = [0x20,0x7e,0xa0,0xac,0xae,0x377,0x37a,0x37f,0x384,0x38a,0x38c,0x38c,0x38e,0x3a1,0x3a3,0x3e1,0x3f0,0x52f,0x1e00,0x1eff,0x2000,0x200a,0x2010,0x2027,0x202f,0x205f,0x2070,0x2071,0x2074,0x208e,0x2090,0x209c,0x20a0,0x20c0,0x2100,0x215f,0x2183,0x2184,0x2189,0x2189,0xfb00,0xfb06,0xfffd,0xfffd];

/** Whether renderer v3 prints this character (a code point). */
export function printableV3(cp: number): boolean {
  let lo = 0;
  let hi = PRINTABLE_V3.length / 2 - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (cp < PRINTABLE_V3[2 * mid]) hi = mid - 1;
    else if (cp > PRINTABLE_V3[2 * mid + 1]) lo = mid + 1;
    else return true;
  }
  return false;
}

/**
 * The characters of a text renderer v3 can't print, each once, in the order they first appear: after composing it
 * (NFC), a character it prints, or whose decomposition it prints, is fine.
 */
export function unprintableV3(text: string): string[] {
  const out: string[] = [];
  for (const ch of text.normalize("NFC")) {
    if (printableV3(ch.codePointAt(0)!) || [...ch.normalize("NFD")].every((c) => printableV3(c.codePointAt(0)!))) continue;
    if (!out.includes(ch)) out.push(ch);
  }
  return out;
}
