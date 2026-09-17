#!/usr/bin/env node
// Does this package's current version already exist on the registry?
//
// THE FOOT-GUN THIS EXISTS FOR
//
// release.yml fires on any v* tag. No tags exist for 0.3.0, 0.4.0 or 0.4.1,
// because all three were hand-published. Pushing v0.4.1 to tidy up the record
// would start a release of a version that is already public. npm would reject
// the publish, but only after the workflow had run every gate, and the failure
// would read as a broken release rather than as "that tag should not exist".
//
// So the question is asked before anything is published, and a version that is
// already on the registry is a CLEAN NO-OP: the workflow succeeds and publishes
// nothing. Re-running a release must be boring.
//
// FAIL CLOSED, AND SAY WHICH
//
// Three outcomes, never two. "The registry did not answer" is not "the version
// is absent", and treating it as absent is how you publish twice. If the
// question cannot be answered, this exits non-zero and says COULD NOT RUN.
// That is the same rule the product sells: absence of evidence is not a pass.
import { readFileSync, appendFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";

const dir = process.argv[2];
if (!dir) {
  console.error("usage: check-registry-version.mjs <package-dir>");
  process.exit(2);
}

const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
const { name, version } = pkg;

/** @returns {{state: "published"|"absent"|"unknown", versions?: string[], why?: string}} */
function lookup() {
  try {
    const out = execFileSync("npm", ["view", name, "versions", "--json"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const parsed = JSON.parse(out);
    const versions = Array.isArray(parsed) ? parsed : [parsed];
    return { state: versions.includes(version) ? "published" : "absent", versions };
  } catch (e) {
    const stderr = String(e.stderr ?? "");
    // A package that has never been published at all is a real answer, not a
    // failure to get one: nothing is published, so this version is not either.
    if (/E404|404 Not Found/.test(stderr)) return { state: "absent", versions: [] };
    return {
      state: "unknown",
      why: stderr.trim().split("\n").slice(-3).join(" | ") || String(e.message),
    };
  }
}

const r = lookup();
const emit = (shouldPublish) => {
  if (process.env.GITHUB_OUTPUT) {
    appendFileSync(process.env.GITHUB_OUTPUT, `should_publish=${shouldPublish}\n`);
    appendFileSync(process.env.GITHUB_OUTPUT, `version=${version}\n`);
  }
};

if (r.state === "unknown") {
  console.error(`COULD NOT RUN: the registry did not answer for ${name}.`);
  console.error(`  ${r.why}`);
  console.error("  Not treating this as 'not published'. Refusing to continue.");
  process.exit(1);
}

if (r.state === "published") {
  console.log(`ALREADY PUBLISHED: ${name}@${version} is on the registry.`);
  console.log("  Publishing nothing for this package. This is a clean no-op, not a failure.");
  console.log("  If you meant to release, bump the version; a tag alone does not make a release.");
  emit(false);
  process.exit(0);
}

console.log(
  `NOT PUBLISHED: ${name}@${version} is not on the registry (${r.versions.length} version(s) there).`,
);
emit(true);
process.exit(0);
