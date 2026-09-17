// The provenance state model.
//
// Four outcomes, and the two that look alike must never be merged. 0.4.1 has no
// attestation because none was ever claimed for it; a future 0.5.0 with no
// attestation would be claiming a build it cannot show. Same missing file,
// opposite meanings. Collapsing them either turns a real failure green or leaves
// a permanently red job that everyone learns to ignore.
//
// This is the rule the product enforces on its users' evidence. It should not be
// looser about itself than it is about them.
import { describe, it, expect } from "vitest";
import {
  PROVENANCE_REQUIRED_FROM,
  Outcome,
  EXIT,
  classifyProvenance,
  compareSemver,
  parseSemver,
} from "../../scripts/provenance-policy.mjs";

const REPO = "11-11AI/execution-governance";
const base = {
  expectedRepo: REPO,
  requiredFrom: PROVENANCE_REQUIRED_FROM,
  registryReachable: true,
};

describe("the provenance floor", () => {
  it("is an exact semver string, not a date or a heuristic", () => {
    expect(parseSemver(PROVENANCE_REQUIRED_FROM)).not.toBeNull();
    expect(PROVENANCE_REQUIRED_FROM).toMatch(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/);
  });

  // THE GUARD ON THE `-0`. A comment can be ignored; a red build cannot.
  //
  // A prerelease sorts below its own release, so a plain "0.4.2" floor puts
  // 0.4.2-rc.1 BELOW it -- and a release candidate is exactly what gets cut for
  // the first release through a new pipeline. The floor must therefore itself
  // be a prerelease, and the lowest one, so every shape of that version is at
  // or above it.
  it("carries a prerelease component, so prereleases of the floor are not below it", () => {
    const parsed = parseSemver(PROVENANCE_REQUIRED_FROM)!;
    expect(
      parsed.pre,
      "the floor must be a prerelease such as 0.4.2-0; see the comment on the constant",
    ).not.toBeNull();
    for (const pre of ["-0", "-alpha.1", "-rc.1", "-beta", ""]) {
      const v = `${parsed.major}.${parsed.minor}.${parsed.patch}${pre}`;
      expect(
        compareSemver(v, PROVENANCE_REQUIRED_FROM),
        `${v} must not sort below the floor`,
      ).toBeGreaterThanOrEqual(0);
    }
  });

  // 0.4.1 was the last hand-published release. The floor must be above it, or
  // the check would demand provenance from a version that could not have it.
  it("sits above the last hand-published version", () => {
    expect(compareSemver(PROVENANCE_REQUIRED_FROM, "0.4.1")).toBeGreaterThan(0);
  });
});

describe("the six outcomes", () => {
  it("1. below the floor and absent is NOT_APPLICABLE, exit 0", () => {
    const r = classifyProvenance({ ...base, version: "0.4.1", hasAttestation: false });
    expect(r.outcome).toBe(Outcome.NOT_APPLICABLE);
    expect(r.reason).toBe("predates-requirement");
    expect(EXIT[r.outcome]).toBe(0);
    expect(r.lines.join(" ")).toContain("0.4.2");
  });

  it("2. at or above the floor and absent is FAIL, red", () => {
    // The prereleases are listed explicitly and first. A release candidate for
    // the first CI release is the realistic first use of this pipeline, and
    // with a plain "0.4.2" floor every one of these returned NOT_APPLICABLE
    // with exit 0.
    for (const v of [
      "0.4.2-0",
      "0.4.2-alpha.1",
      "0.4.2-rc.1",
      "0.4.2",
      "0.5.0",
      "0.5.0-rc.1",
      "1.0.0",
    ]) {
      const r = classifyProvenance({ ...base, version: v, hasAttestation: false });
      expect(r.outcome, `${v} should fail`).toBe(Outcome.FAIL);
      expect(r.reason).toBe("absent");
      expect(EXIT[r.outcome]).toBe(1);
    }
  });

  it("3. present but pointing elsewhere is FAIL, and distinct from absence", () => {
    const r = classifyProvenance({
      ...base,
      version: "0.4.2",
      hasAttestation: true,
      attestationRepo: "https://github.com/someone-else/their-repo",
    });
    expect(r.outcome).toBe(Outcome.FAIL);
    expect(r.reason).toBe("wrong-repository");
    // The whole point: an attestation naming another repo is a different fact
    // from no attestation, and the log must not blur them.
    expect(r.reason).not.toBe("absent");
    expect(r.lines.join(" ")).toContain("someone-else/their-repo");
  });

  it("4. present and bound to this repository is PASS, exit 0", () => {
    const r = classifyProvenance({
      ...base,
      version: "0.4.2",
      hasAttestation: true,
      attestationRepo: `https://github.com/${REPO}`,
    });
    expect(r.outcome).toBe(Outcome.PASS);
    expect(EXIT[r.outcome]).toBe(0);
  });

  it("5. an unreachable registry is COULD_NOT_RUN, exit 3, never a pass", () => {
    const r = classifyProvenance({
      ...base,
      version: "0.4.2",
      hasAttestation: false,
      registryReachable: false,
    });
    expect(r.outcome).toBe(Outcome.COULD_NOT_RUN);
    expect(EXIT[r.outcome]).toBe(3);
    expect(EXIT[r.outcome]).not.toBe(0);
  });

  // The escape hatch must not be openable by leaving a value blank.
  it("6. an unset, empty or unparseable floor is itself a FAIL", () => {
    for (const bad of [undefined, null, "", "   ", "latest", "v0.4.2", "0.4", "2026-09-17"]) {
      const r = classifyProvenance({
        ...base,
        requiredFrom: bad as unknown as string,
        version: "0.4.1",
        hasAttestation: false,
      });
      expect(r.outcome, `floor ${JSON.stringify(bad)} should fail`).toBe(Outcome.FAIL);
      expect(r.reason).toBe("bad-constant");
      expect(EXIT[r.outcome]).toBe(1);
    }
  });
});

describe("NOT_APPLICABLE is not a softened FAIL", () => {
  it("keeps a different exit code from FAIL", () => {
    expect(EXIT[Outcome.NOT_APPLICABLE]).not.toBe(EXIT[Outcome.FAIL]);
    expect(EXIT[Outcome.NOT_APPLICABLE]).toBe(0);
    expect(EXIT[Outcome.FAIL]).toBe(1);
  });

  it("reads differently in the output", () => {
    const na = classifyProvenance({ ...base, version: "0.4.1", hasAttestation: false });
    const fail = classifyProvenance({ ...base, version: "0.4.2", hasAttestation: false });
    expect(na.lines.join(" ")).toContain("No claim of provenance was made");
    expect(fail.lines.join(" ")).toContain("claims a build it cannot show");
    expect(na.reason).not.toBe(fail.reason);
  });

  // THE ONE THAT MATTERS. If this ever passes for a version at or above the
  // floor, the requirement has silently become optional.
  it("is UNREACHABLE for any version at or above the floor", () => {
    // LITERAL VERSION STRINGS, NOT A COMPUTED SET.
    //
    // The previous version of this sweep filtered its own inputs with
    //     if (compareSemver(v, FLOOR) < 0) continue;
    // which used the comparison under test to decide what to test. The failing
    // cases removed themselves: 0.4.2-rc.1 was in the list and was skipped
    // every run. A sweep that derives its inputs from the thing it is testing
    // cannot find this class of bug, so these are hardcoded.
    const atOrAbove = [
      "0.4.2-0",
      "0.4.2-alpha.1",
      "0.4.2-rc.1",
      "0.4.2",
      "0.4.3",
      "0.4.10",
      "0.5.0-rc.1",
      "0.5.0",
      "0.9.9",
      "1.0.0-rc.1",
      "1.0.0",
      "1.0.1",
      "2.0.0",
      "10.0.0",
    ];
    for (const v of atOrAbove) {
      for (const hasAttestation of [true, false]) {
        for (const repo of [`https://github.com/${REPO}`, "https://github.com/elsewhere/x", null]) {
          const r = classifyProvenance({
            ...base,
            requiredFrom: PROVENANCE_REQUIRED_FROM,
            version: v,
            hasAttestation,
            attestationRepo: repo,
          });
          expect(
            r.outcome,
            `${v} attested=${hasAttestation} repo=${repo} must not be NOT_APPLICABLE`,
          ).not.toBe(Outcome.NOT_APPLICABLE);
        }
      }
    }
  });

  // The other half, also literal: these predate the requirement and must stay
  // NOT_APPLICABLE, so the fix above cannot be "call everything a failure".
  it("remains reachable for versions genuinely below the floor", () => {
    for (const v of ["0.1.0", "0.2.1", "0.3.0", "0.4.0", "0.4.1-rc.1", "0.4.1"]) {
      const r = classifyProvenance({
        ...base,
        requiredFrom: PROVENANCE_REQUIRED_FROM,
        version: v,
        hasAttestation: false,
      });
      expect(r.outcome, `${v} predates the floor`).toBe(Outcome.NOT_APPLICABLE);
      expect(EXIT[r.outcome]).toBe(0);
    }
  });

  it("an attestation that exists is checked even below the floor", () => {
    // Being below the floor excuses silence, not a wrong answer: once the claim
    // is made, the evidence has to hold.
    const r = classifyProvenance({
      ...base,
      version: "0.4.1",
      hasAttestation: true,
      attestationRepo: "https://github.com/elsewhere/x",
    });
    expect(r.outcome).toBe(Outcome.FAIL);
    expect(r.reason).toBe("wrong-repository");
  });
});

describe("semver comparison", () => {
  it("orders releases and prereleases correctly", () => {
    expect(compareSemver("0.4.2", "0.4.1")).toBe(1);
    expect(compareSemver("0.4.10", "0.4.9")).toBe(1);
    expect(compareSemver("1.0.0", "0.9.9")).toBe(1);
    expect(compareSemver("1.0.0-rc.1", "1.0.0")).toBe(-1);
    expect(compareSemver("1.0.0-rc.2", "1.0.0-rc.1")).toBe(1);
    expect(compareSemver("0.4.2", "0.4.2")).toBe(0);
  });
});
