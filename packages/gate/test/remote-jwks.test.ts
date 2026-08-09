// The remote engine must not believe an unverified decision.
//
// These tests sign with a REAL Ed25519 key and serve a REAL JWKS through an
// injected fetch. Nothing about the verification itself is mocked: a test that
// stubs `verifySignedDecision` would pass whether or not the signature check
// works, which is the failure mode this file exists to prevent.
import { describe, expect, it } from "vitest";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { RemotePolicyEngine } from "../src/engines/remote.js";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const jwk = publicKey.export({ format: "jwk" }) as { x: string };

const KID = "test-key-1";
const JWKS = { keys: [{ kid: KID, kty: "OKP", crv: "Ed25519", x: jwk.x }] };

/** Build a decision body signed exactly the way the control plane signs it. */
function signedDecision(
  decision: "allow" | "deny",
  opts: { kid?: string; tamperAfterSigning?: boolean } = {},
) {
  const body: Record<string, unknown> = {
    decision,
    reason: `remote says ${decision}`,
    policyVersion: "remote-1",
  };
  const signed_fields = ["decision", "reason", "policyVersion"];
  // Reconstructed in signed_fields ORDER, not sorted. Matches the server.
  const obj: Record<string, unknown> = {};
  for (const f of signed_fields) obj[f] = body[f];
  const value = edSign(null, Buffer.from(JSON.stringify(obj), "utf8"), privateKey).toString(
    "base64url",
  );
  if (opts.tamperAfterSigning) body.decision = "allow";
  return { ...body, signed_fields, ed25519_signature: { kid: opts.kid ?? KID, value } };
}

function fetchImpl(decisionBody: unknown, o: { jwks?: unknown; jwksStatus?: number } = {}) {
  return (async (url: string | URL) => {
    const u = String(url);
    if (u.includes("jwks")) {
      if (o.jwksStatus && o.jwksStatus !== 200) {
        return new Response("nope", { status: o.jwksStatus });
      }
      return new Response(JSON.stringify(o.jwks ?? JWKS), { status: 200 });
    }
    return new Response(JSON.stringify(decisionBody), { status: 200 });
  }) as unknown as typeof fetch;
}

const REQ = { sessionId: "s", tool: "t", args: {} };
const engine = (body: unknown, extra = {}, fetchOpts = {}) =>
  new RemotePolicyEngine({
    url: "https://cp.example.com/v1/execute",
    apiKey: "k",
    fetchImpl: fetchImpl(body, fetchOpts),
    ...extra,
  });

describe("RemotePolicyEngine signature verification", () => {
  it("allows a correctly signed allow", async () => {
    const r = await engine(signedDecision("allow")).evaluate(REQ);
    expect(r.decision).toBe("allow");
  });

  it("passes through a correctly signed deny", async () => {
    const r = await engine(signedDecision("deny")).evaluate(REQ);
    expect(r.decision).toBe("deny");
    expect(r.reason).toContain("remote says deny");
  });

  // The attack this whole feature exists to stop: something that can answer the
  // URL returns a well-formed allow with no signature at all.
  it("DENIES an unsigned allow", async () => {
    const r = await engine({
      decision: "allow",
      reason: "trust me",
      policyVersion: "x",
    }).evaluate(REQ);
    expect(r.decision).toBe("deny");
    expect(r.reason).toContain("did not verify");
  });

  it("DENIES an allow whose body was changed after signing", async () => {
    const body = signedDecision("deny", { tamperAfterSigning: true });
    expect(body.decision).toBe("allow"); // the tamper is real
    const r = await engine(body).evaluate(REQ);
    expect(r.decision).toBe("deny");
    expect(r.reason).toContain("did not verify");
  });

  it("DENIES when the signature is from a key the JWKS does not publish", async () => {
    const other = generateKeyPairSync("ed25519");
    const otherJwk = other.publicKey.export({ format: "jwk" }) as { x: string };
    const r = await engine(
      signedDecision("allow"),
      {},
      {
        jwks: { keys: [{ kid: KID, kty: "OKP", crv: "Ed25519", x: otherJwk.x }] },
      },
    ).evaluate(REQ);
    expect(r.decision).toBe("deny");
  });

  it("DENIES when the kid is not in the JWKS", async () => {
    const r = await engine(signedDecision("allow", { kid: "unknown-kid" })).evaluate(REQ);
    expect(r.decision).toBe("deny");
  });

  // The behaviour people find surprising, asserted so it cannot regress
  // quietly: a key server that is down denies. A decision that cannot be
  // verified has not been made.
  it("DENIES when the JWKS endpoint is unreachable", async () => {
    const r = await engine(signedDecision("allow"), {}, { jwksStatus: 503 }).evaluate(REQ);
    expect(r.decision).toBe("deny");
    expect(r.reason).toContain("did not verify");
  });

  it("names the JWKS url in the denial, so the failure is diagnosable", async () => {
    const r = await engine({ decision: "allow", reason: "x", policyVersion: "y" }).evaluate(REQ);
    expect(r.reason).toContain("https://cp.example.com/.well-known/jwks.json");
  });

  it("derives the JWKS url from the control-plane origin, not its path", async () => {
    const r = await engine({ decision: "allow", reason: "x", policyVersion: "y" }).evaluate(REQ);
    expect(r.reason).not.toContain("/v1/execute/.well-known");
  });

  it("honours an explicit jwksUrl", async () => {
    const r = await engine(
      { decision: "allow", reason: "x", policyVersion: "y" },
      {
        jwksUrl: "https://keys.example.org/jwks.json",
      },
    ).evaluate(REQ);
    expect(r.reason).toContain("https://keys.example.org/jwks.json");
  });

  it("requireSignature:false restores the old, trusting behaviour", async () => {
    const r = await engine(
      { decision: "allow", reason: "unsigned", policyVersion: "x" },
      {
        requireSignature: false,
      },
    ).evaluate(REQ);
    expect(r.decision).toBe("allow");
  });

  it("verification is ON by default", async () => {
    // Same body, same engine options, minus the opt-out. Proves the default
    // rather than asserting it in a comment.
    const r = await engine({ decision: "allow", reason: "unsigned", policyVersion: "x" }).evaluate(
      REQ,
    );
    expect(r.decision).toBe("deny");
  });
});
