# GitHub releases and GHCR images

Two workflows are provided: `ci.yml` validates commits and builds a test image, while `publish-ghcr.yml` publishes multiarch (AMD64/ARM64) images only when a version tag matching `v*` is pushed.

The first publicly published image is **`v0.2.0-beta.1`**. Beta.2 is also published. The next source candidate is **`v0.2.0-beta.3`**. Compose defaults intentionally retain the original `beta.1` fallback; existing installations should explicitly select their approved image with `SMTP_PROBE_IMAGE`.

## Validate before requesting release approval

- Keep the README, `.env` overrides and production Compose examples pinned to `v0.2.0-beta.1` during review. Source version `0.2.0-beta.3` does not mean that image exists yet.
- Run `npm run check` and `npm test`, and require the Tests workflow (including the container build) to pass for the exact commit being released.
- Build that commit in CI and smoke-test it in an isolated container with a dedicated password and sending disabled. Confirm `/healthz`, login/logout, both page version labels, authenticated `/api/info`, and the startup log. All version surfaces must report `0.2.0-beta.3`.
- Review the beta.3 changelog against the final diff; leave it marked **pending release** until release approval. Record the release date in the approved release commit.
- Obtain explicit approval before pushing the version tag, publishing a GitHub release, or upgrading a deployment.

## Publish only after approval

After the approved release commit's Tests workflow succeeds, update your local checkout, verify that commit, and publish a **new** release tag:

```bash
git pull --ff-only origin main
node scripts/check-release-version.mjs v0.2.0-beta.3
git tag v0.2.0-beta.3
git push origin v0.2.0-beta.3
```

Check **Actions → Publish GHCR image**. The workflow publishes `ghcr.io/texomans/smtp-probe:v0.2.0-beta.3` and the moving `:beta` tag, using `GITHUB_TOKEN`. A public container package can be pulled without authentication. Optionally create a GitHub pre-release for the same tag.

The publishing workflow checks the tag against `package.json` and runs syntax checks and automated tests before logging in to GHCR. A mismatched tag fails before publication. Automatic `latest` tagging is disabled; only a stable version tag may explicitly receive `:latest`.

**Do not move or force-update an existing tag**. Production installations should use version-specific tags or digests; `:beta` is intended for staging. The `:latest` image is reserved for stable releases.

After publication, inspect the versioned image manifest and confirm both `linux/amd64` and `linux/arm64` are present. Pull the versioned image into isolated staging, confirm health/login/version behavior, and record the image digest. Override `SMTP_PROBE_IMAGE` explicitly when validating an exact image; staging otherwise follows the moving `:beta` alias.

Keep the existing deployment on `v0.2.0-beta.1` until the new image passes validation and the upgrade is approved. If already upgraded to beta.2, retain that approved image while reviewing beta.3. Then update the deployment and public image examples in a separate change, retaining beta.1 as the rollback target. Never include environment secrets or customer data in source control or build artifacts.
