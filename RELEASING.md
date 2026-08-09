# Releasing

Both packages publish to npm under the @11ai scope with public access.

**Publishing is done by CI, on a tag. Do not publish from a laptop.**
`.github/workflows/release.yml` publishes both packages when a `v*` tag is
pushed, using npm trusted publishing. There is no `NPM_TOKEN`: the workflow
authenticates over OIDC, and npm is configured to trust **that file, at that
path**. Two consequences worth knowing before you change anything:

- Renaming or moving `release.yml` breaks the trust binding and every publish
  fails.
- Adding an `NPM_TOKEN` does not fix a failing publish. A token is rejected
  under trusted publishing, so reaching for one makes the failure worse.

Provenance is automatic, which is what puts the verified-provenance badge on the
npm page.

## Preflight

```
npm ci
npm run build
npm run lint
npm test
```

All tests must be green. The conformance table and the adversarial vector count print in the test output.

## Verify the tarballs

```
bash scripts/verify-tarball.sh
```

This packs both packages, installs them into a throwaway project, and runs the quickstart from the packed tarballs. Each tarball includes dist, README, LICENSE, and NOTICE.

## Publish

1. Bump the version in **both** `packages/gate/package.json` and
   `packages/mcp-gate/package.json`. They are versioned in lockstep, and
   `release.yml` fails the run before publishing anything if either manifest
   disagrees with the tag.
2. Update `CHANGELOG.md`: move `Unreleased` into a dated section, and add the
   comparison link at the bottom.
3. Merge to `main`.
4. Tag and push:

```
git tag v0.1.2
git push origin v0.1.2
```

That is the whole publish. CI then re-runs build, lint, test and the tarball
check, verifies the tag against both manifests, and publishes the SDK first
because `@11ai/mcp-gate` depends on it.

The gates re-run on the tag rather than trusting the CI result from the merge,
because a tag is not evidence that CI passed on that commit, and a broken
release cannot be un-installed by whoever already has it. `npm unpublish` is
unavailable after 72 hours.

### Publishing by hand

Don't. It bypasses provenance, and the packages are configured for trusted
publishing rather than tokens, so it will not work as written in older versions
of this document.

## Tag history

`v0.1.0` is tagged. **0.1.1 was published to npm but never tagged**, so there is
a hole in the tag history where a real release shipped. Tagging `v0.1.1`
retroactively at `01c5e00` would close it. Every release from here is tagged by
definition, since the tag is what triggers the publish.
