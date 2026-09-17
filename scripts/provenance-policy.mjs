// When must a published version carry a provenance attestation, and what does
// its absence mean?
//
// THE DISTINCTION THIS FILE EXISTS FOR
//
// 0.4.1 has no attestation. That is not a failure: it was published by hand,
// before this repository published anything from CI, and no claim of provenance
// was ever made for it. FAIL means the claim was made and the evidence is
// absent. NOT_APPLICABLE means no claim was made. Merging those two facts is
// exactly the coercion this product refuses to perform on its users' evidence,
// and it should not be looser about itself than it is about them.
//
// The alternatives were both wrong. A permanently red job trains people to
// ignore it. A deferred schedule is a gate that has to be switched on later,
// which is the unconnected gate this whole branch exists to remove.

/**
 * The first version that MUST carry a provenance attestation.
 *
 * 0.4.1 was the last hand-published release, so 0.4.2 is the smallest version
 * that can only have come from CI. Choosing the floor this way rather than
 * guessing the next version number means it stays correct whether the next
 * release is 0.4.2, 0.5.0 or 1.0.0: everything at or above it must prove where
 * it was built.
 *
 * An exact semver string, deliberately. Not a date, not a comparison against
 * when the workflow landed, not a heuristic. If this is ever unset, empty or
 * unparseable that is a FAIL in itself -- the escape hatch must not be openable
 * by leaving a value blank.
 */
export const PROVENANCE_REQUIRED_FROM = "0.4.2";

export const Outcome = Object.freeze({
  PASS: "PASS",
  NOT_APPLICABLE: "NOT_APPLICABLE",
  FAIL: "FAIL",
  COULD_NOT_RUN: "COULD_NOT_RUN",
});

/** NOT_APPLICABLE and PASS both exit 0; FAIL and COULD_NOT_RUN are both red. */
export const EXIT = Object.freeze({
  [Outcome.PASS]: 0,
  [Outcome.NOT_APPLICABLE]: 0,
  [Outcome.FAIL]: 1,
  [Outcome.COULD_NOT_RUN]: 3,
});

export function parseSemver(v) {
  const m = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(
    String(v ?? "").trim(),
  );
  if (!m) return null;
  return { major: +m[1], minor: +m[2], patch: +m[3], pre: m[4] ?? null };
}

/** Standard semver precedence, including prerelease ordering. */
export function compareSemver(a, b) {
  const x = parseSemver(a);
  const y = parseSemver(b);
  if (!x || !y) throw new Error(`unparseable version: ${!x ? a : b}`);
  for (const k of ["major", "minor", "patch"]) {
    if (x[k] !== y[k]) return x[k] < y[k] ? -1 : 1;
  }
  // 1.0.0-rc.1 precedes 1.0.0.
  if (x.pre === null && y.pre === null) return 0;
  if (x.pre === null) return 1;
  if (y.pre === null) return -1;
  const xs = x.pre.split(".");
  const ys = y.pre.split(".");
  for (let i = 0; i < Math.max(xs.length, ys.length); i++) {
    const a1 = xs[i];
    const b1 = ys[i];
    if (a1 === undefined) return -1;
    if (b1 === undefined) return 1;
    const an = /^\d+$/.test(a1);
    const bn = /^\d+$/.test(b1);
    if (an && bn) {
      if (+a1 !== +b1) return +a1 < +b1 ? -1 : 1;
    } else if (an !== bn) {
      return an ? -1 : 1;
    } else if (a1 !== b1) {
      return a1 < b1 ? -1 : 1;
    }
  }
  return 0;
}

const norm = (r) =>
  String(r ?? "")
    .replace(/^https?:\/\/github\.com\//i, "")
    .replace(/\.git$/, "")
    .toLowerCase();

/**
 * Decide the outcome from facts already gathered. Pure: no network, no disk,
 * so every branch below is reachable from a test.
 */
export function classifyProvenance({
  version,
  hasAttestation,
  attestationRepo = null,
  expectedRepo,
  // NO DEFAULT VALUE, DELIBERATELY. `requiredFrom = PROVENANCE_REQUIRED_FROM`
  // would make an explicitly-passed undefined resolve to the real constant,
  // because that is what JS default parameters do. A caller that believes it is
  // supplying a floor and supplies nothing would then be waved through with the
  // right answer by accident. The floor must be passed, and a missing one is a
  // failure, not a fallback.
  requiredFrom,
  registryReachable = true,
}) {
  // FIRST, always. A blank or malformed floor must not be able to wave
  // anything through, so it is rejected before any version is compared.
  const floor = parseSemver(requiredFrom);
  if (!floor) {
    return {
      outcome: Outcome.FAIL,
      reason: "bad-constant",
      lines: [
        `PROVENANCE_REQUIRED_FROM is not an exact semver string: ${JSON.stringify(requiredFrom)}`,
        "Provenance cannot be required from a version that cannot be read, and an",
        "unreadable floor must not be treated as 'not required yet'.",
      ],
    };
  }

  if (!registryReachable) {
    return {
      outcome: Outcome.COULD_NOT_RUN,
      reason: "registry-unreachable",
      lines: [
        "the registry or attestation service did not answer, so provenance was never checked",
      ],
    };
  }

  if (!parseSemver(version)) {
    return {
      outcome: Outcome.FAIL,
      reason: "bad-version",
      lines: [`the installed version is not an exact semver string: ${JSON.stringify(version)}`],
    };
  }

  const required = compareSemver(version, requiredFrom) >= 0;

  if (!hasAttestation) {
    if (required) {
      return {
        outcome: Outcome.FAIL,
        reason: "absent",
        lines: [
          `${version} is at or above ${requiredFrom} and carries NO provenance attestation.`,
          "Every version from that floor onward is published through release.yml with",
          "--provenance, so this one claims a build it cannot show. Do not add a path",
          "that publishes without it.",
        ],
      };
    }
    return {
      outcome: Outcome.NOT_APPLICABLE,
      reason: "predates-requirement",
      lines: [
        `${version} predates ${requiredFrom}, the first version required to carry provenance.`,
        "No claim of provenance was made for it, so its absence is not evidence of",
        "anything and is not being reported as a failure.",
      ],
    };
  }

  // An attestation that EXISTS is checked whatever the version: once the claim
  // is made, the evidence has to hold. Being below the floor excuses silence,
  // not a wrong answer.
  if (norm(attestationRepo) !== norm(expectedRepo)) {
    return {
      outcome: Outcome.FAIL,
      reason: "wrong-repository",
      lines: [
        "the provenance attestation does not link to this repository.",
        `expected  ${norm(expectedRepo)}`,
        `actual    ${norm(attestationRepo)}  (${attestationRepo})`,
        "An attestation naming another repository proves the artifact was built",
        "somewhere else. This is a different fact from provenance being absent.",
      ],
    };
  }

  return {
    outcome: Outcome.PASS,
    reason: "verified",
    lines: [`${version} carries provenance linking to ${norm(expectedRepo)}`],
  };
}
