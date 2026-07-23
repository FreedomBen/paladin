---
name: bump-version
description: Bump the paladin workspace version everywhere it is recorded (workspace Cargo.toml, internal path-dependency requirements, man page headers, Cargo.lock), verify nothing was missed, run the CI gate, and commit. Use when asked to bump, change, or set the project version, or to prepare a release. Argument: the new X.Y.Z version.
argument-hint: <new-version X.Y.Z>
---

# Bump the paladin version

Change the project version to `$ARGUMENTS` in every place it is recorded,
verify nothing was missed, run the CI gate, and commit. If no version argument
was given, ask for one before changing anything.

## Preconditions

- Read the current version from `[workspace.package]` → `version` in the root
  `Cargo.toml`.
- The new version must be plain semver `X.Y.Z` — digits and dots, no leading
  `v`. The `v` prefix belongs only to the git tag.
- If the new version is not greater than the current one, say so and confirm
  with the user before continuing.

## Checklist

Work through these in order, checking each off:

- [ ] **Root `Cargo.toml`** — `[workspace.package]` → `version = "X.Y.Z"`.
      This is the canonical copy: all five crates inherit it, the binaries'
      `--version` output compiles from it, the Makefile's `VERSION` and the
      nfpm package versions read it, and the release workflow's tag guard
      checks against it.
- [ ] **Internal path-dependency requirements** — five occurrences, all must
      be set to the new version exactly:
  - `crates/paladin-cli/Cargo.toml` — `paladin-common`, `paladin-core`
  - `crates/paladin-tui/Cargo.toml` — `paladin-common`, `paladin-core`
  - `crates/paladin-gtk/Cargo.toml` — `paladin-core`

  These are caret semver requirements, so a stale value still resolves on a
  patch bump but breaks the build on a minor/major bump — update them on every
  bump regardless.
- [ ] **Man page `.TH` headers** — first line of
      `crates/paladin-cli/paladin.1` and `docs/paladin-tui.1`. Update the
      source field `"paladin X.Y.Z"` (both intentionally say `paladin`, not
      the binary name) and set the date field to today's date (YYYY-MM-DD).
- [ ] **README install examples** — the `VERSION=X.Y.Z` lines in the
      "Installing a Release" section of `README.md` (one per package-manager
      block) illustrate downloading the newest release; set them to the new
      version.
- [ ] **`Cargo.lock`** — refresh the workspace members' recorded versions with
      `cargo update --workspace` (touches only the workspace crates, not
      third-party dependencies). Commit the refreshed lockfile with the bump.
- [ ] **AppStream metainfo (conditional)** — `data/org.paladin.Gtk.metainfo.xml`
      currently has no `<releases>` section; if one has been added since, add
      an entry for the new version.

## Verify

- [ ] Grep the repo for the **old** version string, excluding `target/`,
      `dist/`, `.git/`, `TODO.md`, and `Cargo.lock` (third-party crates may
      coincidentally use the old number). Expected, fine-to-leave matches:
  - `packaging/nfpm-*.yaml` — a `VERSION=…` usage example in a comment
  - `README.md` — the illustrative tag example ("e.g. `v0.1.0`")

  Any other match is a version-bearing location this checklist does not know
  about: update it, then add it to this skill so the next bump gets it.
- [ ] `make ci` passes (fmt-check, clippy `-D warnings`, full test suite).

## Commit

Commit all changed files together — root `Cargo.toml`, the three crate
manifests, both man pages, `README.md`, `Cargo.lock` — with a message like
`Bump version to X.Y.Z`, following the repository's commit-lock protocol
(see CLAUDE.md). Do not tag and do not push.

## Hand-off

Finish by giving the user the release steps, which are theirs to run (agents
never tag or push):

```sh
git push                  # the bump commit must be on the remote
git tag vX.Y.Z            # tag the bump commit
git push origin vX.Y.Z    # triggers .github/workflows/release.yml
```

The release workflow re-checks that the tag equals `v` + the `Cargo.toml`
version, re-runs the full test gate, builds the `.deb`/`.rpm` packages, and
publishes them with a `SHA256SUMS` file to a GitHub release for the tag.
