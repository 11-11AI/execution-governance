# Releasing

Both packages publish to npm under the @11ai scope with public access. Publishing is manual. CI does not publish.

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

Publish the SDK first, since the proxy depends on it.

```
npm login
npm publish -w @11ai/execution-governance --access public
npm publish -w @11ai/mcp-gate --access public
```

## After publish

```
git tag v0.1.0
git push --tags
```
