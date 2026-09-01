# Releasing Gatehouse

Gatehouse releases are driven by a version tag. Do not create or publish the
GitHub Release manually; the release workflow creates it only after crates.io
publication succeeds.

## One-time setup

Configure `gatehouse` on crates.io with a GitHub Trusted Publisher using:

- repository owner: `thepartly`
- repository: `gatehouse`
- workflow: `release.yml`
- environment: leave blank

The workflow uses GitHub OIDC to obtain a short-lived crates.io token. It does
not use a long-lived repository secret.

## Release procedure

1. Prepare and merge a release PR that updates `Cargo.toml`, `Cargo.lock`, and
   `CHANGELOG.md`.
2. Wait for the `CI` workflow on the exact `main` merge commit to pass.
3. Fast-forward local `main` and verify the commit and version:

   ```bash
   git switch main
   git pull --ff-only origin main
   git status --short --branch
   cargo audit
   cargo publish --dry-run --locked
   ```

4. Tag that exact commit and push the tag:

   ```bash
   git tag -a vX.Y.Z -m "Release vX.Y.Z"
   git push origin vX.Y.Z
   ```

The release workflow refuses to publish unless the tag matches the crate
version and a successful `main` push CI run exists for the exact tagged commit.
It then audits and packages the crate, publishes through crates.io Trusted
Publishing, and creates the GitHub Release as the final step. The release body
comes exclusively from the matching `CHANGELOG.md` section; GitHub-generated
release notes are intentionally disabled.

If a release fails, inspect the workflow before retrying. Do not move or reuse a
published version tag, and do not manually create the GitHub Release to bypass a
failed gate.
