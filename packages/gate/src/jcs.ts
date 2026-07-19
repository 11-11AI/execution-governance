// Canonical JSON serialization, RFC 8785 style: object keys sorted, no
// insignificant whitespace, standard JSON escaping. Signer and verifier must
// serialize identically or signatures will not verify, so this is load bearing.
// Keys are sorted by their UTF-16 code units, which matches JSON.stringify key
// handling for the ASCII field names used in receipts.

export function jcs(value: unknown): string {
  return serialize(value);
}

function serialize(v: unknown): string {
  if (v === null) return "null";
  const t = typeof v;
  if (t === "number") {
    if (!Number.isFinite(v as number)) throw new Error("cannot canonicalize a non-finite number");
    return JSON.stringify(v);
  }
  if (t === "boolean" || t === "string") return JSON.stringify(v);
  if (t === "bigint") throw new Error("cannot canonicalize a bigint");
  if (t === "undefined" || t === "function" || t === "symbol") {
    throw new Error(`cannot canonicalize a value of type ${t}`);
  }
  if (Array.isArray(v)) {
    return "[" + v.map((x) => serialize(x === undefined ? null : x)).join(",") + "]";
  }
  const obj = v as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const parts: string[] = [];
  for (const k of keys) {
    if (obj[k] === undefined) continue; // omit undefined, matching JSON semantics
    parts.push(JSON.stringify(k) + ":" + serialize(obj[k]));
  }
  return "{" + parts.join(",") + "}";
}
