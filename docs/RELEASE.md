# Publishing SMTP Probe to GitHub and GHCR

This repository contains two GitHub Actions workflows: `ci.yml` for checking incoming changes and `publish-ghcr.yml` for release tags.

## First GitHub repository

1. Sign in to the intended GitHub account, create an empty **public** repository named `smtp-probe` (do **not** initialize it with a README, license, or .gitignore; those already exist).
2. Work from a clean copy of the **source ZIP**, not from the running VPS or its `.env`. Inspect source before publishing.
3. From the extracted source folder, push the initial contents:

```bash
git init -b main
git add .
git status --short
git commit -m "Initial public SMTP Probe beta source"
git remote add origin https://github.com/texomans/smtp-probe.git
git push -u origin main
```

4. Open **Actions** on GitHub and verify that the Tests workflow succeeds (including the Docker build). This CI build does not publish an image.
5. Create the first version tag, then push it:

```bash
git tag v0.2.0-beta.1
git push origin v0.2.0-beta.1
```

6. GitHub Actions builds a multiarch (`linux/amd64` + `linux/arm64`) image and pushes **two GHCR tags**: `ghcr.io/texomans/smtp-probe:v0.2.0-beta.1` and `ghcr.io/texomans/smtp-probe:beta`. The moving `beta` tag is intended for staging; VPS deployments should use the immutable version-named tag (or digest).
7. If necessary, visit your GitHub profile → **Packages** → `smtp-probe` → **Package settings** → **Change visibility** → **Public**. A newly created GHCR package may be private even when the repository is public. Once public, anyone can pull without logging in.
8. Optionally draft a GitHub Release attached to tag `v0.2.0-beta.1`, mark it **Pre-release**, and paste the CHANGELOG entry and security limitations. The GitHub Release is a convenience; the tag is what triggers image publishing.

No Docker Hub token, personal access token, or registry password is required in Actions for GHCR publication: the workflow uses the repository's short-lived `GITHUB_TOKEN` with `packages: write`.

## Inspect image before deploying

```bash
docker pull ghcr.io/texomans/smtp-probe:v0.2.0-beta.1
docker image inspect ghcr.io/texomans/smtp-probe:v0.2.0-beta.1 --format '{{json .RepoDigests}}'
```

Check your GitHub Actions build/test results, then use Komodo with `compose.komodo.yaml`. If you want absolute immutability, pin the image digest instead of the tag.

## Future releases

- Add fixes to `main` through PRs. CI must pass before release.
- For a tested beta: bump `package.json` (single source of version), update changelog, then tag `v0.2.0-beta.2`. The `beta` image moves; pinned versions remain available.
- Later use stable tags like `v1.0.0` (workflow publishes `:latest` only for tags without prerelease suffix).
- Keep the VPS pinned to a tested tag/digest. Allow your home staging installation to poll the moving `:beta` digest, or update it manually.
- Docker Hub is optional; if added later, use a dedicated token stored in GitHub Actions Secrets. Keep the same version tags across registries.

## Important security warning

Do not push existing VPS or home `.env` files, saved email messages, SMTP credentials, session cookies, logs or test-generated certificate private keys. The source ZIP is curated to exclude them, but **review `git status` before every push**. Use `.gitignore` and `.dockerignore` as additional defenses, not as a replacement for checking.
