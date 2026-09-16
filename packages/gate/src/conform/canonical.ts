// Canonical JSON, implemented from docs/RECEIPTS.md § Canonicalization.
//
// WRITTEN FROM THE SPEC, NOT COPIED FROM THE GATE, AND THAT IS THE POINT.
//
// A conformance checker that imports the reference implementation's
// canonicalizer does not test conformance to the specification. It tests
// agreement with one implementation, and it would pass a candidate that
// matched our bug and fail one that matched the written rule. The whole value
// of this tool is that a second implementer can be told "you are wrong" by
// something that is not simply us.
//
// The cost is that this copy can drift from the gate. That is handled by test,
// not by hope: test/parity.test.ts asserts this produces byte-identical output
// to the gate's jcs() over gate-generated receipts. If they ever disagree, one
// of them contradicts docs/RECEIPTS.md and that is a finding, not a merge
// conflict to paper over.
//
// The four rules, verbatim from the document:
//   - Object keys are sorted by their UTF-16 code units.
//   - No insignificant whitespace.
//   - Standard JSON string escaping.
//   - Keys whose value is undefined are omitted.

/** Thrown when a value has no canonical form under the spec. */
export class NotCanonicalizable extends Error {}

export function canonicalJson(value: unknown): string {
  if (value === undefined) throw new NotCanonicalizable("undefined has no canonical form");
  if (value === null) return "null";

  const t = typeof value;
  if (t === "boolean" || t === "string") return JSON.stringify(value);
  if (t === "number") {
    if (!Number.isFinite(value as number)) {
      throw new NotCanonicalizable(`non-finite number ${String(value)} has no canonical form`);
    }
    return JSON.stringify(value);
  }
  if (t === "bigint" || t === "function" || t === "symbol") {
    throw new NotCanonicalizable(`${t} has no canonical form`);
  }

  if (Array.isArray(value)) {
    // An array element that is undefined becomes null under JSON semantics
    // rather than being omitted; omitting it would change the array's length.
    return "[" + value.map((v) => (v === undefined ? "null" : canonicalJson(v))).join(",") + "]";
  }

  const obj = value as Record<string, unknown>;
  // Default Array.prototype.sort compares UTF-16 code units, which is what the
  // document specifies. Not locale-aware, deliberately.
  const keys = Object.keys(obj).sort();
  const parts: string[] = [];
  for (const k of keys) {
    if (obj[k] === undefined) continue; // "keys whose value is undefined are omitted"
    parts.push(JSON.stringify(k) + ":" + canonicalJson(obj[k]));
  }
  return "{" + parts.join(",") + "}";
}
