# GitHub releases and GHCR images

Two workflows are provided: `ci.yml` validates commits and builds a test image, while `publish-ghcr.yml` publishes multiarch (AMD64/ARM64) images only when a version tag matching `v*` is pushed.

The first publicly published image is **`v0.2.0-beta.1`**. Updates to `main` are intended for **`v0.2.0-beta.2`**. Until that tag is published, Compose defaults intentionally reference the existing `beta.1` image.

After the `main` Tests workflow succeeds, update your local checkout and publish a **new** release tag:

```bash
git pull --ff-only origin main
git tag v0.2.0-beta.2
git push origin v0.2.0-beta.2
```

Check **Actions → Publish GHCR image**. The workflow publishes `ghcr.io/texomans/smtp-probe:v0.2.0-beta.2` and the moving `:beta` tag, using `GITHUB_TOKEN`. A public container package can be pulled without authentication. Optionally create a GitHub pre-release for the same tag.

**Do not move or force-update an existing tag**. Production installations should use version-specific tags or digests; `:beta` is intended for staging. The `:latest` image is reserved for stable releases.

After the new image is available, update the default image reference in the Compose examples. Never include environment secrets or customer data in source control or build artifacts.
