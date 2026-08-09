// Ed25519 verification of a control-plane decision against its published JWKS.
//
// WHY THIS EXISTS
// ---------------
// A remote policy engine returns "allow" over HTTP. Without verification, the
// only thing standing between an attacker and an allow is whoever can answer
// that URL: a compromised proxy, a DNS hijack, a misconfigured egress, or a
// local process listening on the same port. The transport is not the
// authorization; the signature is.
//
// This is the one place the gate stops trusting the network and starts
// trusting a key.
//
// FAIL-CLOSED, WITHOUT EXCEPTION
// ------------------------------
// Every failure here returns false, and false means deny:
//   - JWKS unreachable, non-200, or unparseable
//   - no key matching the decision's kid
//   - missing signature, missing signed_fields
//   - signature does not verify
//
// An unreachable JWKS denying is deliberate and is the behaviour people find
// surprising. It is the same rule as the rest of this package: a decision that
// cannot be verified has not been made. "The key server was down" is not a
// reason to run an action.
//
// CANONICALISATION IS NOT JCS HERE
// --------------------------------
// The control plane signs `JSON.stringify(obj)` where obj is built by walking
// `signed_fields` IN ORDER. That is insertion order, not sorted order, so it is
// deliberately NOT the JCS canonicalisation this package uses for receipts.
// Verification has to reconstruct the object in exactly that order or every
// signature fails. This is a fact about the server's wire format, confirmed
// against the live API rather than assumed, and it is written down here because
// "just canonicalise it" is the obvious wrong fix when signatures start failing.
import { createPublicKey, verify as edVerify } from "node:crypto";

export interface SignedDecisionEnvelope {
  signed_fields?: unknown;
  ed25519_signature?: { kid?: string; value?: string };
  [k: string]: unknown;
}

export interface JwksVerifyOptions {
  jwksUrl: string;
  fetchImpl: typeof fetch;
  timeoutMs: number;
}

interface JwkKey {
  kid?: string;
  kty?: string;
  crv?: string;
  x?: string;
}

/**
 * Fetch the JWKS and return the Ed25519 key matching `kid`.
 *
 * A named kid MUST be present in the JWKS. A missing named kid is an error, not
 * a reason to try another key -- otherwise revocation does nothing, since a
 * decision signed by a retired key would still verify against a current one.
 *
 * Only an envelope with no kid at all falls back to the first key, which is a
 * convenience for single-key deployments and a real weakness in multi-key ones.
 * Publish a kid.
 */
async function jwksKey(kid: string | null, o: JwksVerifyOptions) {
  const res = await o.fetchImpl(o.jwksUrl, { signal: AbortSignal.timeout(o.timeoutMs) });
  if (!res.ok) throw new Error(`jwks HTTP ${res.status}`);
  const body = (await res.json()) as { keys?: JwkKey[] };
  const keys = Array.isArray(body?.keys) ? body.keys : [];
  // If the decision names a kid, that kid must exist. Falling back to "the
  // first key" when a named kid is missing would defeat both revocation and
  // rotation: a decision signed by a retired key, or one naming a kid that was
  // never published, would still verify against whatever key happens to be
  // listed first. Only an envelope carrying NO kid may fall back, and that is
  // for single-key deployments.
  const k = kid ? keys.find((x) => x.kid === kid) : keys[0];
  if (!k?.x) throw new Error(kid ? `jwks has no key for kid ${kid}` : "jwks has no usable key");
  if (k.kty && k.kty !== "OKP") throw new Error(`unsupported jwk kty ${k.kty}`);
  if (k.crv && k.crv !== "Ed25519") throw new Error(`unsupported jwk crv ${k.crv}`);
  return createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: k.x }, format: "jwk" });
}

/**
 * True only if the envelope carries a signature that verifies against the
 * published JWKS. Never throws: every failure path is a false, and the caller
 * turns false into a deny.
 */
export async function verifySignedDecision(
  envelope: SignedDecisionEnvelope,
  o: JwksVerifyOptions,
): Promise<boolean> {
  try {
    const sig = envelope?.ed25519_signature;
    const fields = envelope?.signed_fields;
    if (!sig?.value || !Array.isArray(fields) || fields.length === 0) return false;

    const pub = await jwksKey(sig.kid ?? null, o);

    // Rebuilt in signed_fields order. See the note above: not sorted, not JCS.
    const obj: Record<string, unknown> = {};
    for (const f of fields) {
      if (typeof f !== "string") return false;
      obj[f] = envelope[f];
    }

    return edVerify(
      null,
      Buffer.from(JSON.stringify(obj), "utf8"),
      pub,
      Buffer.from(sig.value, "base64url"),
    );
  } catch {
    return false;
  }
}

/** Default JWKS location for a control-plane URL: its origin + the well-known path. */
export function defaultJwksUrl(controlPlaneUrl: string): string {
  const u = new URL(controlPlaneUrl);
  return `${u.origin}/.well-known/jwks.json`;
}
