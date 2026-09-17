#!/usr/bin/env node
// Does the PUBLISHED package carry a provenance attestation that links back to
// this repository?
//
// WHY THIS EXISTS
//
// Moving publication into CI was justified almost entirely by the provenance
// attestation: a verifiable link from the published tarball to the commit and
// workflow that built it, checkable by a third party without asking us. Nothing
// checked that the attestation was actually there. A claim with no check on it
// is the exact defect shape this work exists to remove, and it would have been
// the one the gate itself introduced.
//
// WHY NOT JUST `npm audit signatures`
//
// Because it cannot fail for the reason that matters. Run against a tree
// holding this package today it prints:
//
//     3 packages have verified registry signatures
//     1 package has a verified attestation
//
// and exits 0. That one attestation is @noble/hashes. Ours has none at all.
// A bare exit-code check on that command would report green precisely when the
// property it is supposed to guarantee is absent. So the attestation is looked
// up for THIS package by name and version, and `npm audit signatures` is used
// for the cryptographic half rather than the existence half.
//
// THREE OUTCOMES
//   exit 0  attestation present, verified, and pointing at this repository
//   exit 1  absent, unverifiable, or pointing somewhere else
//   exit 3  COULD NOT RUN: registry or attestation service unreachable
// Callers must treat 3 as red. A check that cannot see must not report a pass.
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";

// The package directory is overridable ONLY so the three outcomes can be
// exercised against a package that already publishes with provenance; CI passes
// no argument and gets the real one.
const PKG_DIR = process.argv[2] || "node_modules/@11ai/execution-governance";
const EXPECTED_REPO = (
  process.env.GITHUB_REPOSITORY || "11-11AI/execution-governance"
).toLowerCase();

const fail = (m, ...rest) => {
  console.error(`FAIL: ${m}`);
  rest.forEach((r) => console.error(`  ${r}`));
  process.exit(1);
};
const unmeasurable = (m, ...rest) => {
  console.error(`COULD NOT RUN: ${m}`);
  rest.forEach((r) => console.error(`  ${r}`));
  process.exit(3);
};

let manifest;
try {
  manifest = JSON.parse(readFileSync(`${PKG_DIR}/package.json`, "utf8"));
} catch {
  unmeasurable(`${PKG_DIR} is not installed here, so there is nothing to check.`);
}
const { name, version } = manifest;
console.log(`checking provenance for ${name}@${version}`);

// --- 1. Is an attestation recorded for this exact version? -----------------
const NETWORK =
  /ENOTFOUND|ETIMEDOUT|ECONNREFUSED|ECONNRESET|EAI_AGAIN|network|socket hang up|503|502|504/i;
let distAtt;
try {
  const out = execFileSync("npm", ["view", `${name}@${version}`, "dist.attestations", "--json"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
  distAtt = out === "" ? null : JSON.parse(out);
} catch (e) {
  const err = String(e.stderr ?? e.message ?? "");
  if (NETWORK.test(err))
    unmeasurable(
      "the registry did not answer when asked for the attestation record.",
      err.trim().split("\n").slice(-2).join(" | "),
    );
  if (/E404/.test(err)) fail(`${name}@${version} is not on the registry at all.`);
  unmeasurable(
    "could not read the attestation record from the registry.",
    err.trim().split("\n").slice(-2).join(" | "),
  );
}

if (!distAtt || !distAtt.url) {
  fail(
    `${name}@${version} has NO provenance attestation.`,
    "The registry records only ordinary signatures for it, which every package gets",
    "and which say nothing about where it was built.",
    "A version published by hand cannot have one. Publish through release.yml,",
    "which passes --provenance, and do not add a path that publishes without it.",
  );
}
console.log(`  attestation recorded: ${distAtt.url}`);

// --- 2. Does it point at THIS repository? ----------------------------------
let bundle;
try {
  const res = await fetch(distAtt.url);
  if (!res.ok) unmeasurable(`the attestation service answered ${res.status} for ${distAtt.url}`);
  bundle = await res.json();
} catch (e) {
  unmeasurable("could not fetch the attestation bundle.", String(e.message ?? e));
}

const slsa = (bundle.attestations ?? []).find((a) =>
  String(a.predicateType).includes("slsa.dev/provenance"),
);
if (!slsa)
  fail(
    "the attestation bundle carries no SLSA provenance statement.",
    `found: ${(bundle.attestations ?? []).map((a) => a.predicateType).join(", ") || "nothing"}`,
  );

let repo;
try {
  const payload = JSON.parse(
    Buffer.from(slsa.bundle.dsseEnvelope.payload, "base64").toString("utf8"),
  );
  repo = payload?.predicate?.buildDefinition?.externalParameters?.workflow?.repository;
} catch (e) {
  fail("the SLSA provenance statement could not be parsed.", String(e.message ?? e));
}
if (!repo) fail("the SLSA provenance names no source repository.");

const got = String(repo)
  .replace(/^https?:\/\/github\.com\//i, "")
  .replace(/\.git$/, "")
  .toLowerCase();
if (got !== EXPECTED_REPO) {
  fail(
    "the provenance does not link to this repository.",
    `expected  ${EXPECTED_REPO}`,
    `actual    ${got}  (${repo})`,
    "An attestation pointing somewhere else proves the artifact was built somewhere else.",
  );
}
console.log(`  provenance links to ${repo}`);

// --- 3. Is it cryptographically valid? -------------------------------------
// This is the half `npm audit signatures` is genuinely good at: it verifies the
// bundle against Sigstore rather than merely observing that a URL exists.
try {
  const out = execFileSync("npm", ["audit", "signatures"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  console.log(
    out
      .trim()
      .split("\n")
      .map((l) => `  | ${l}`)
      .join("\n"),
  );
} catch (e) {
  const combined = String(e.stdout ?? "") + String(e.stderr ?? "");
  if (NETWORK.test(combined))
    unmeasurable(
      "npm audit signatures could not reach the registry or Sigstore.",
      combined.trim().split("\n").slice(-3).join(" | "),
    );
  fail(
    "npm audit signatures rejected an attestation in this tree.",
    combined.trim().split("\n").slice(-6).join(" | "),
  );
}

console.log(`ok: ${name}@${version} carries verified provenance linking to ${EXPECTED_REPO}`);
