// Shared with the signing viewer's generated pdf.js worker and the standalone verifier.
// Bound XFA work explicitly: a native recursion limit differs between browsers and machines.
export const XFA_MAX_DEPTH = 1000;

export function xfaTextContent<T>(root: T, children: (node: T) => T[] | null | undefined, value: (node: T) => string | undefined): string {
  const out: string[] = [];
  const stack: [T, number][] = [[root, 0]];
  while (stack.length) {
    const [node, depth] = stack.pop()!;
    if (depth > XFA_MAX_DEPTH) throw new RangeError("XFA text nesting limit exceeded");
    const items = children(node);
    if (!items) out.push(value(node) || "");
    else for (let i = items.length - 1; i >= 0; i--) stack.push([items[i], depth + 1]);
  }
  return out.join("");
}
