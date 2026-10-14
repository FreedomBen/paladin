---
name: bump-version
description: Bump the Paladin workspace version to a target like v0.0.2. Updates every hardcoded version pin (workspace manifest, path-dependency requirements, xtask constant, Makefile and CI sentinels), refreshes Cargo.lock, runs the fmt/clippy/test gates, and commits. Use when the user asks to bump, set, or bump up the project/workspace version.
argument-hint: v<major>.<minor>.<patch>
---

# Bump the workspace version

Target version: $ARGUMENTS

## 1. Validate the argument

- Accept `vX.Y.Z` or `X.Y.Z` (an optional semver pre-release suffix such as
  `-rc.1` is fine). Strip any leading `v` — Cargo versions never carry it.
  Call the result `NEW` below. If the argument is missing or not a valid
  semver version, stop and ask the user for one.
- Read the current version (`OLD` below) from `version = "..."` under
  `[workspace.package]` in the root `Cargo.toml`.
- If `NEW` is not greater than `OLD`, confirm with the user before
  proceeding — a downgrade or re-release is unusual and may be a typo.

## 2. Update every version pin

The grep in step 4 is authoritative; this table is the expected baseline.
Member crates inherit `version.workspace = true`, but these literals do not:

| File                          | Pin to update                                            |
|-------------------------------|----------------------------------------------------------|
| `Cargo.toml`                  | `version = "OLD"` under `[workspace.package]`            |
| `xtask/Cargo.toml`            | Its own `version = "OLD"` (does not inherit) and the `version = "OLD"` requirements on the `paladin-cli` / `paladin-tui` path dependencies |
| `crates/paladin-cli/Cargo.toml` | `version = "OLD"` on both `paladin-core` path dependencies (deps and dev-deps) |
| `crates/paladin-tui/Cargo.toml` | `version = "OLD"` on the `paladin-core` path dependency  |
| `crates/paladin-gtk/Cargo.toml` | `version = "OLD"` on the `paladin-core` path dependency  |
| `xtask/src/package.rs`        | `const WORKSPACE_VERSION: &str = "OLD";`                 |

The path-dependency requirements must move in lockstep: a `0.0.x`
requirement matches only that exact patch version, so leaving one behind
breaks the build.

Sentinels keep their suffixes — update the version prefix only:

| File                           | Sentinel                                                |
|--------------------------------|---------------------------------------------------------|
| `Makefile`                     | `PALADIN_VERSION ?= OLD-dev` → `NEW-dev`                |
| `.github/workflows/ci.yml`     | `PALADIN_VERSION: "OLD-ci-dry-run"` → `NEW-ci-dry-run`  |
| `docs/IMPLEMENTATION_PLAN_04_GTK.md` | References the `OLD-ci-dry-run` sentinel string — keep it in sync with `ci.yml` |

## 3. Refresh the lockfile

```bash
cargo update --workspace
```

This rewrites the four `paladin-*` entries in `Cargo.lock` without
touching external dependency versions.

## 4. Audit for stragglers

```bash
grep -rn "OLD" --exclude-dir=target --exclude-dir=.git .
```

Update any genuine version pin this finds that the table above missed.
Known hits to **leave alone** — they are not pins of the real version:

- `crates/paladin-gtk/tests/cargo_manifest_workspace_inheritance_logic.rs` —
  arbitrary fixture manifest inside a parser unit test.
- `crates/paladin-gtk/tests/packaging_appimage_build_script_logic.rs` —
  `suspicious_tokens` list used to detect hardcoded versions; it is
  intentionally a list of example version strings.
- Prose mentions of historical versions in comments, assertion messages,
  or docs (e.g. "the v0.0.1 / pre-v0.2 workspace").

Never run a blind global search-and-replace; classify each hit.

## 5. Verify

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

The test suite is the backstop: several tests pin packaging and manifest
contracts and will fail if a required location was missed. Fix failures
before committing.

## 6. Commit

Commit per the repository conventions in `CLAUDE.md` (serialize with the
`commit.lock` protocol — acquire, commit, release as three separate
commands). Subject line: `Bump version to NEW`. Do **not** git tag and
never git push — the release pipeline derives packaging versions from
tags the user creates.
