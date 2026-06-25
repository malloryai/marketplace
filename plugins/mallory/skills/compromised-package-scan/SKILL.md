---
name: compromised-package-scan
description: Cross-reference a codebase's dependencies against Mallory's latest compromised packages. Pulls the most recently compromised packages (and their compromised versions) from the Mallory API, pre-processes GitHub SBOMs into a normalized package/version list, and reports which dependencies are confirmed-compromised or need review. Use when checking exposure to supply-chain attacks, npm/PyPI account takeovers, or malicious package versions.
allowed-tools: Bash(python *), Bash(python3 *), Bash(uv *), Bash(pip *), Bash(gh api *)
---

# Compromised Package Scan

Detect supply-chain exposure by joining **Mallory's latest compromised packages** against the
**dependencies declared in GitHub repositories** (via their Dependency Graph SBOMs).

## Prerequisites

- The `malloryapi` SDK and `MALLORY_API_KEY` — see the **mallory-api** skill.
  ```bash
  uv pip install --system malloryapi   # MALLORY_API_KEY read from env
  ```
- The GitHub CLI (`gh`), authenticated, to pull SBOMs. The skill shells out to
  `gh api repos/<owner>/<repo>/dependency-graph/sbom`, so it uses your existing `gh auth`.
  (You can also pass pre-downloaded SPDX JSON files instead.)

All work runs through one script:

```bash
SCAN=${CLAUDE_PLUGIN_ROOT}/skills/compromised-package-scan/scripts/scan.py
```

## How it works (3 stages)

1. **Compromised feed** — pull the latest *N* compromised packages from Mallory, sorted by most
   recent compromise. For each, fetch its `compromised_versions`, `compromise_type`, and sources.
2. **SBOM pre-processing** — pull each repo's SBOM and normalize every component to a clean
   `{ecosystem, name, version, pinned}` record by parsing its PURL. **This step is what makes the
   report accurate** (see *Accuracy* below) — always pre-process before cross-referencing.
3. **Cross-reference** — join on `(ecosystem, name)` and classify each hit.

## Quick start (end-to-end)

Default behavior: the **latest 100 compromised packages** from Mallory.

```bash
# Scan one or more repos in one shot (table output)
python3 $SCAN run owner/repo another/repo --output table

# Restrict to an ecosystem, change the feed size
python3 $SCAN run owner/repo --ecosystem npm --limit 200 --output table

# Scan a locally downloaded SBOM instead of pulling from GitHub
python3 $SCAN run --sbom-file ./sbom.spdx.json --output table
```

## Running the stages separately

Prefer this when scanning many repos against one feed (fetch the feed once, reuse it):

```bash
# 1. Pull the compromised feed once  (default --limit 100)
python3 $SCAN compromised --limit 100 -o feed.json

# 2. Pre-process each repo's SBOM into a normalized package list
python3 $SCAN sbom owner/repo-a -o sbom_a.json
python3 $SCAN sbom owner/repo-b -o sbom_b.json

# 3. Cross-reference (repeat --sbom for multiple repos)
python3 $SCAN crossref --feed feed.json --sbom sbom_a.json --sbom sbom_b.json --output table
```

`compromised` and `sbom` emit JSON. `crossref` / `run` default to JSON; pass `--output table`
for a human-readable summary.

## Reading the results

Each finding is classified:

| Status      | Meaning                                                                        | Action |
| ----------- | ------------------------------------------------------------------------------ | ------ |
| `CONFIRMED` | A **pinned** SBOM version exactly matches a known compromised version.         | Treat as an active incident — the compromised version is declared. Remove/upgrade now. |
| `REVIEW`    | The package (name + ecosystem) is known-compromised, but the SBOM version is a **range** or doesn't exactly match. | Check the **resolved/installed** version (lockfile) against `compromised_versions`. |

## Accuracy — why pre-processing matters

GitHub SBOMs frequently report **declared version ranges** (e.g. `^2.0.0`) taken from manifests
(`package.json`, `requirements.txt`), not pinned, resolved versions. A range like `^2.0.0` *may*
resolve to a compromised `2.0.2`, but the SBOM alone can't prove it. So the scan never reports a
range as `CONFIRMED`:

- Pre-processing parses PURLs to get a reliable `(ecosystem, name)` and marks each version
  `pinned` or not.
- `CONFIRMED` requires a **pinned** version that exactly matches a known compromised version.
- Everything else that matches by name lands in `REVIEW` — surfaced, but flagged as needing a
  resolved-version check. To resolve a `REVIEW`, scan a repo that commits a lockfile (GitHub's
  dependency graph reads lockfiles and emits pinned versions), or check the installed version
  directly.

Ecosystem names are normalized (`go`↔`golang`, `rubygems`↔`gem`) to match Mallory's values.

## Notes

- The feed is **the latest** compromised packages, not an exhaustive list. Raise `--limit` (or
  filter with `--ecosystem`) to widen coverage of recent activity.
- Never print or log `MALLORY_API_KEY`.
- For deeper detail on any flagged package (full evidence, sources, mentions), use the
  **mallory-api** skill: `client.packages.compromises(uuid)` and `client.packages.mentions(uuid)`.

See `reference.md` for the data model, command reference, and field details.
