---
name: supply-chain-compromise-monitor
description: Use when monitoring GitHub or GitLab repositories for malicious packages, compromised releases, or compromised build components, including repeated scans of a saved repository scope. Ordinary dependency hygiene and CVE-only exposure use their own workflows.
---

# Supply-chain compromise monitor

Read [runtime](../../references/runtime.md), [outputs](../../references/output-contract.md)
and [findings](../../references/finding-lifecycle.md). Use `malloryapi==0.4.0` for
all Mallory intelligence. The bundled [scanner playbook](../compromised-package-scan/SKILL.md)
and script work independently of another plugin install.

## Confirm inventory and permissions

Save an explicit roster of repository host/owner/name or GitLab project IDs,
branch/ref, source artifact paths, snapshot times, freshness requirement and
Create findings yes/no (default no). Include inaccessible requested repositories
in coverage. Do not infer that one exported SBOM covers all provider repositories.

Read tenant inventory with `client.assets.inventory_repositories` and integrations
with `client.integrations.list` when available, exhausting pages. Inventory rows
establish repository presence, not dependency completeness. malloryapi 0.4.0 has
no general cache/live SQL endpoint: do not recreate the internal credential proxy,
call private transport, or invent SDK methods. For dependency proof use authorized
GitHub CLI SBOM retrieval or caller-supplied SPDX/CycloneDX exports, including
GitLab exports. A missing GitLab export/provider capability is an explicit gap,
not an empty repository. Use an already-connected host provider tool for targeted
reads when available and authorized; otherwise retain unknown freshness/coverage.

## Assess a fresh snapshot

For an exhaustive package assessment, use the scanner's `--all` feed mode,
which pages every package with compromise evidence and all evidence rows.
The legacy latest-N mode is a bounded recent-feed scan and must be labeled so.
Each execution re-reads current authorized inventory/SBOMs and considers all
applicable known compromise evidence. The last 24 hours highlights new/revised
evidence only; older intelligence can match a newly introduced dependency.

```bash
python "$PLUGIN_ROOT/skills/compromised-package-scan/scripts/scan.py" run \
  example/repository --sbom-file gitlab-project.cdx.json --all --output json
```

Read the source reports behind candidate matches, preferably maintainer/vendor
or incident responder evidence. Stored allegations, empty affected-version lists,
account takeover alone or package-name resemblance cannot establish a malicious
release. Match ecosystem, namespace, actual registry/upstream provenance, then
resolved version, full commit or algorithm-prefixed digest. Preserve exact
case/qualifiers where required. Ranges/mutable tags remain potential until resolved.

The standalone scanner handles package/version matching and supplied SBOMs;
the agent assesses workflow actions, remote includes and images with available
file/ref evidence. Verify resolved SHA/digest and historical execution interval.
A current tag target does not prove what an older build fetched. No provider
capability means unchecked build-component coverage, not a fabricated verdict.

Report confirmed component exposure, potential matches, no affected version in
inspected scope, and unchecked separately. Presence does not establish execution
or compromise. Development/transitive dependencies count; lack of a CVE or an
application call site does not suppress malicious install-time tooling.

## Findings and output

With explicit writes, use `intel.supply_chain.compromised_component_present`.
Canonical repository identifiers use `github.repo` or `gitlab.project` (including
actual host), never a path to a downloaded SBOM. If mapping is not established,
retain the assessment without filing. Qualifier is `component:` plus SHA-256 of
UTF-8 compact JSON `[identity, release_kind, release]`: versionless canonical PURL
including source qualifiers (or canonical upstream URL), and kind `version`,
`commit` or `digest` with its exact resolved value. Preserve these inputs in
evidence. Normalize PyPI names by collapsing runs of `[-_.]` to `-` and lowercasing;
retain case for case-sensitive ecosystems, sort PURL qualifiers without changing
values. Paths, evidence IDs and run times do not belong in identity.

Link open findings and preserve dismissed ones. A fixed finding can recur only
with fresh post-resolution evidence that the same affected component was
reintroduced; unknown/cached older observations cannot prove recurrence. Follow
the shared lifecycle; do not silently reopen or change old findings. Use supported
severity from credible evidence/default definition and state execution unknown.

Write `supply-chain-review.json` and `.md` with the roster denominator, branches,
artifact/snapshot times, inspected dependency/workflow paths, exact matches,
potential cases, evidence links, execution evidence/unknowns, finding actions,
and remaining provider/build coverage. A confirmed match and partial coverage can
coexist. No scan changes dependencies or starts scheduling/delivery by itself.
