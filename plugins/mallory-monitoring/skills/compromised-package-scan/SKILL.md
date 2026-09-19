---
name: compromised-package-scan
description: Use when checking supplied GitHub repository SBOMs or SPDX/CycloneDX exports (including GitLab) against known malicious package releases. For recurring multi-repository and build-component investigations, use supply-chain-compromise-monitor.
---

# Compromised package scan

Read [runtime](../../references/runtime.md) and [output contract](../../references/output-contract.md).
Use **malloryapi 0.4.0** for Mallory intelligence. GitHub retrieval uses the user's
authenticated `gh` CLI; supplied exports require neither provider CLI nor credentials.

Resolve `PLUGIN_ROOT` to this installed plugin's root. The script works when the
plugin is copied/installed independently, with no sibling checkout required.

```bash
SCAN="$PLUGIN_ROOT/skills/compromised-package-scan/scripts/scan.py"
# Exhaust the known compromised-package index, not merely the latest 100.
python "$SCAN" run example/repository --all --output json > supply-chain-scan.json
# SPDX or CycloneDX exports, including caller-supplied GitLab exports.
python "$SCAN" run --sbom-file gitlab-project.cdx.json --all --output json
# Backward-compatible bounded recent-feed scan:
python "$SCAN" run example/repository --limit 100 --output table
```

The existing `compromised`, `sbom`, `crossref` and `run` commands remain available.
`--all` is supported on `compromised` and `run`; `--limit` selects a recent feed.
The script reads Mallory and provider APIs, creates no findings, sends no messages,
and never modifies a repository. It returns data for agent assessment.

## Interpretation

- `CONFIRMED`: an exact pinned version matches recorded affected-version evidence
  with no evidence-read gap or unresolved PURL qualifier. This is a component
  exposure candidate, not proof of execution or tenant compromise. Read the cited
  source before escalating or filing; a stored allegation is not independent proof.
- `REVIEW`: version/range, source provenance or compromise evidence needs review.
  Unknown versions and a package name match are insufficient for confirmation.
- No match: only no affected package found in the successfully inspected inventory
  and intelligence scope. The scanner does not establish that every component,
  registry, historical build or deployed artifact is covered.

The JSON includes sources, exact versions, component PURLs, full compromise
records, snapshot timestamps when present, source inventory counts, and
`coverage.gaps`. The package list and per-package compromise evidence both page
through the SDK. A failed package/source does not become a clean empty result;
partial rows and gaps remain visible. The latest-N cap is explicitly partial
relative to the entire compromised index. Unknown snapshot age stays unknown.

CycloneDX nested components and SPDX PURL references are supported. PyPI names
use the ecosystem's normalized spelling; case-sensitive ecosystems retain case.
PURL qualifiers are retained as evidence and require provenance review before
confirmation. SBOMs do not prove all transitive, development, workflow or container
components are represented. Map each exported file to a canonical repository,
branch/ref and observed time before claiming repository coverage or filing.
GitLab live discovery is not implemented by this standalone script; request an
export or use an existing authorized provider tool and report unavailable scope.

Read source reports behind matches, validate exact upstream/registry and affected
release, inspect available dependency paths and execution evidence, then produce
`supply-chain-review.json` and `.md` using the shared envelope. Keep raw scan JSON
as supporting evidence. For no-write requests, report findings not requested.
When finding writes were explicitly requested, follow the shared lifecycle and
the supply-chain monitor's canonical component/repository identity rules.
The base plugin's standalone scanner is intentionally report-only; the monitoring
bundle provides that orchestration playbook.
