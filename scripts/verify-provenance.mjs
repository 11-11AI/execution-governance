#!/usr/bin/env node
// Does the PUBLISHED package carry a provenance attestation that links back to
// this repository?
//
// WHY THIS EXISTS
//
// Moving publication into CI was justified almost entirely by the provenance
// attestation: a verifiable link from the published tarball to the commit and
// workflow that built it, checkable by a third party without asking us. Nothing
// checked the attestation was actually there. A claim with no check on it is the
// defect shape this work exists to remove, and it would have been the one the
// gate itself introduced.
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
// OUTCOMES
//   exit 0  PASS            attestation present, verified, bound to this repo
//   exit 0  NOT_APPLICABLE  version predates the provenance requirement
//   exit 1  FAIL            claimed and absent, or present and pointing elsewhere
//   exit 3  COULD NOT RUN   registry or attestation service unreachable
//
// NOT_APPLICABLE is not a softened FAIL. See scripts/provenance-policy.mjs for
// why the two are kept apart and where the floor is set.
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import {
  PROVENANCE_REQUIRED_FROM,
  Outcome,
  EXIT,
  classifyProvenance,
} from "./provenance-policy.mjs";

// Overridable ONLY so the outcomes can be exercised against a package that
// already publishes with provenance; CI passes no argument and gets the real one.
const PKG_DIR = process.argv[2] || "node_modules/@11ai/execution-governance";
const EXPECTED_REPO = process.env.GITHUB_REPOSITORY || "11-11AI/execution-governance";
const NETWORK =
  /ENOTFOUND|ETIMEDOUT|ECONNREFUSED|ECONNRESET|EAI_AGAIN|network|socket hang up|503|502|504/i;

function report(result) {
  const code = EXIT[result.outcome];
  const head = result.outcome === Outcome.PASS ? "ok" : result.outcome;
  console.log(`${head}: ${result.lines[0]}`);
  for (const l of result.lines.slice(1)) console.log(`  ${l}`);
  if (result.outcome === Outcome.NOT_APPLICABLE) {
    console.log(`  provenance is required from ${PROVENANCE_REQUIRED_FROM} onward.`);
  }
  process.exit(code);
}

let manifest;
try {
  manifest = JSON.parse(readFileSync(`${PKG_DIR}/package.json`, "utf8"));
} catch {
  report({
    outcome: Outcome.COULD_NOT_RUN,
    reason: "not-installed",
    lines: [`${PKG_DIR} is not installed here, so there is nothing to check.`],
  });
}
const { name, version } = manifest;
console.log(
  `checking provenance for ${name}@${version} (required from ${PROVENANCE_REQUIRED_FROM})`,
);

// --- gather: is an attestation recorded for this exact version? ------------
let distAtt = null;
let reachable = true;
try {
  const out = execFileSync("npm", ["view", `${name}@${version}`, "dist.attestations", "--json"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
  distAtt = out === "" ? null : JSON.parse(out);
} catch (e) {
  const err = String(e.stderr ?? e.message ?? "");
  if (/E404/.test(err)) {
    report({
      outcome: Outcome.FAIL,
      reason: "not-published",
      lines: [`${name}@${version} is not on the registry at all.`],
    });
  }
  reachable = false;
  if (!NETWORK.test(err)) {
    // Still unmeasurable rather than a pass: the question was not answered.
    console.log(
      `  (registry error was not recognisably a network fault: ${err.trim().split("\n").slice(-1)[0]})`,
    );
  }
}

// --- gather: which repository does it name? --------------------------------
let attRepo = null;
if (reachable && distAtt?.url) {
  try {
    const res = await fetch(distAtt.url);
    if (!res.ok) {
      reachable = false;
    } else {
      const bundle = await res.json();
      const slsa = (bundle.attestations ?? []).find((a) =>
        String(a.predicateType).includes("slsa.dev/provenance"),
      );
      if (slsa) {
        const payload = JSON.parse(
          Buffer.from(slsa.bundle.dsseEnvelope.payload, "base64").toString("utf8"),
        );
        attRepo =
          payload?.predicate?.buildDefinition?.externalParameters?.workflow?.repository ?? null;
      }
      if (attRepo === null) {
        report({
          outcome: Outcome.FAIL,
          reason: "no-slsa-statement",
          lines: [
            "an attestation exists but carries no SLSA provenance naming a source repository.",
            `bundle: ${distAtt.url}`,
          ],
        });
      }
    }
  } catch {
    reachable = false;
  }
}

const result = classifyProvenance({
  version,
  hasAttestation: Boolean(distAtt?.url),
  attestationRepo: attRepo,
  expectedRepo: EXPECTED_REPO,
  requiredFrom: PROVENANCE_REQUIRED_FROM,
  registryReachable: reachable,
});

// --- the cryptographic half, only when there is something to verify --------
if (result.outcome === Outcome.PASS) {
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
    if (NETWORK.test(combined)) {
      report({
        outcome: Outcome.COULD_NOT_RUN,
        reason: "sigstore-unreachable",
        lines: ["npm audit signatures could not reach the registry or Sigstore."],
      });
    }
    report({
      outcome: Outcome.FAIL,
      reason: "signature-invalid",
      lines: [
        "npm audit signatures rejected an attestation in this tree.",
        combined.trim().split("\n").slice(-6).join(" | "),
      ],
    });
  }
}

report(result);
