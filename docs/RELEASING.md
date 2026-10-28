# Releasing

The GitHub Action runs `dist/action/index.js` straight from the tagged commit, so the bundle in
that commit is what users get. Users reference the major tag (`@v1`), which is moved to every
compatible release; full version tags (`v1.0.0`) never move.

## 1. Prepare the release commit on `main`

1. Update `version` in `package.json` and `package-lock.json`, and `VERSION` in
   `src/shared/version.ts`.
2. Add the version and date to `CHANGELOG.md`.
3. Rebuild and check:

   ```bash
   npm ci
   npm run check
   npm run build:action
   git status --short dist/action   # must be empty once committed
   ```

4. Commit and push to `main`, then wait for `ci` and `action-selftest` to pass on that commit.

## 2. Tag

```bash
git switch main && git pull --ff-only
git tag -a v1.0.0 -m "v1.0.0"
git push origin v1.0.0

# Move the major tag to the same commit
git tag -fa v1 -m "v1" v1.0.0^{}
git push origin v1 --force
```

Only `v1` is ever force-pushed. A breaking change to inputs, outputs or behaviour starts `v2`.

## 3. Create the GitHub release and publish to the Marketplace

1. On GitHub, open **Releases > Draft a new release** and choose the tag `v1.0.0`.
2. Tick **Publish this Action to the GitHub Marketplace**. The first time, accept the Marketplace
   agreement (two-factor authentication is required) and pick the primary and secondary
   categories (for example Security and Continuous integration). GitHub validates `action.yml`
   here: it must be the only action metadata file at the repository root, and its `name` must be
   unique in the Marketplace.
3. Use the `CHANGELOG.md` section as the release notes and publish.

With the GitHub CLI, steps 1 and 3 can be done with
`gh release create v1.0.0 --title v1.0.0 --notes-file <notes>`, but the Marketplace checkbox is
only available in the web form for the first publication.

## 4. Verify

- The Marketplace listing shows the name, description and branding from `action.yml`.
- A workflow in another repository with `uses: diegoperezg7/mcp-guard@v1` runs and produces the
  job summary, the outputs and the SARIF upload.
