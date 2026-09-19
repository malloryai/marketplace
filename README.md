# Mallory Security Plugin Marketplace

Agent skills for threat intelligence, security monitoring and evidence-based
investigations, powered by the official [malloryapi Python client](https://github.com/malloryai/malloryapi).

## Install

```text
/plugin marketplace add malloryai/marketplace
/plugin install mallory@mallory
/plugin install mallory-monitoring@mallory
/plugin install mallory-investigations@mallory
```

Install only the bundles you need. Each includes its own runtime references and
helpers; monitoring and investigations do not require a sibling plugin installation.
The repository also includes `.codex-plugin/plugin.json` manifests and a Codex
catalog at `.agents/plugins/marketplace.json` for adding this repository as a
Codex marketplace.

Use Python 3.10+ in your chosen environment:

```bash
python -m pip install 'malloryapi==0.4.0'
export MALLORY_API_KEY='your-api-key'
```

If your package index has not published 0.4.0 yet, use the exact v0.4.0 release
source (the revision used for this change's offline verification):

```bash
python -m pip install 'malloryapi @ git+https://github.com/malloryai/malloryapi.git@f23ae7f0ecd8dab4400a56b2ad8f3fc17a558bb2'
```

Get a key from [Mallory API keys](https://app.mallory.ai/api/keys). Credentials
stay in the environment. SDK 0.4.0 supplies findings, definitions, sightings,
advisories, organizations, stories and inventory methods. Availability of data
and writes still depends on the key's tenant permissions and populated inventory.

## Bundles and outputs

| Plugin | Skill | Output |
| --- | --- | --- |
| `mallory` | `mallory-api` | SDK access/reference guide |
| | `adversary-emulation-planning` | ATT&CK-grounded exercise planning |
| | `actor-tactic-timeline` | Self-contained TTP heatmap |
| | `hunt-pack` | Cited actors, hunting hypotheses and shareable hunt pack |
| | `compromised-package-scan` | Package/version evidence and coverage JSON/table; agent assessment report |
| | `daily-briefing` | HTML digest; workspace mode adds JSON, Markdown and saved comparison state |
| | `story-based-tabletop-exercise` | Complete exercise Markdown plus source/coverage JSON |
| `mallory-monitoring` | `third-party-breach-monitor` | Vendor-by-vendor breach verdicts and optional findings |
| | `technology-advisory-monitor` | Advisory/profile applicability and optional findings |
| | `supply-chain-compromise-monitor` | Repository/component assessment and optional findings |
| | `compromised-package-scan` | Bundled copy of the standalone scanner |
| `mallory-investigations` | `exposure-validation` | Exploited CVE/asset presence, reachability and optional escalation |
| | `observable-investigation` | Exact sighting/opinion matches and optional findings |

The new assessments are **agent-executed playbooks**: the agent reads evidence,
uses SDK recipes and writes reports. They are not unattended Python verdict
engines. Deterministic helpers handle pagination, report artifacts, SBOM parsing
and workspace-briefing collection. No proprietary mounted paths or internal
agent tools are prerequisites.

## Try a workflow

- “Create a 30-minute tabletop from the last seven days of stories for our engineering team.”
- “Check this vendor roster for breaches newly added since yesterday; report only.”
- “Does this advisory apply to our gateway's exact version and enabled modules?”
- “Check newly exploited CVEs against our inventory and create or escalate findings.”
- “Review the last 24 hours of observable sightings against stored malicious opinions.”
- “Check these GitHub repositories and GitLab SBOM exports for compromised releases.”
- “Give me our workspace briefing, including newly matched stories and new findings.”

New workflows default to reports. Explicit requests enable documented finding
writes. Evidence, exact scope/window, actions and coverage gaps accompany every
assessment. Reports distinguish complete/partial/blocked; incomplete reads never
become an all-clear. Existing dismissals and workflow-specific resolution rules
are preserved. Component presence or a malicious sighting does not establish
execution or tenant compromise.

Scheduling and email/Slack delivery are host capabilities, invoked only when
requested. Save roster/profile/state files in caller-owned storage. A generated
file is not a delivered message. No automatic response/remediation is performed.

## Standalone helpers

Resolve `PLUGIN_ROOT` to the **installed plugin's** absolute directory.

```bash
# Complete known compromised-package feed + caller-supplied GitLab CycloneDX export.
python "$PLUGIN_ROOT/skills/compromised-package-scan/scripts/scan.py" run \
  --sbom-file project.cdx.json --all --output json

# In the mallory plugin: workspace briefing, with state isolated per tenant/workspace.
python "$PLUGIN_ROOT/skills/daily-briefing/scripts/workspace_briefing.py" \
  --workspace "$WORKSPACE_UUID" --state output/briefing-state.json \
  --output-prefix output/daily-briefing

# Render a completed assessment JSON using the common report contract.
python "$PLUGIN_ROOT/scripts/workflow_support.py" result.json \
  --output-prefix output/review --html
```

The scanner preserves the original `run`, `compromised`, `sbom`, and `crossref`
commands. It accepts SPDX and CycloneDX (including GitLab exports); GitHub live
SBOM retrieval uses `gh`. GitLab live inventory/dependency discovery is not
implemented by this standalone helper. Report missing exports/authorization as
coverage gaps. The monitor can use existing host provider tools when available.

SDK 0.4.0 has no general cached/live SQL query methods. Reachability and broader
provider inspection use already-authorized host tools or remain not assessable;
the plugins do not bypass the SDK through private HTTP calls.

Workspace briefing stories follow the workspace; findings and vulnerability
matches are labeled tenant-wide. First run establishes the matched-story baseline.
Partial reads preserve failed-section checkpoints. State tracks collection, not
external delivery; retry a saved artifact after a delivery failure.

## Development

Python 3.12+ is required for repository development. Use an isolated environment
with the pinned client before running offline tests:

```bash
python -m unittest discover -s tests -v
python scripts/sync_bundles.py --check
python scripts/validate_plugins.py --verbose
python -m compileall -q plugins shared scripts tests
```

`shared/` is the canonical runtime/output/finding guidance and pagination/artifact
helper. The scanner under `plugins/mallory/` is canonical. After editing either,
run `python scripts/sync_bundles.py`; commit the generated copies too. Do not edit
bundled copies independently. Plugin installs must work without this repo's
`shared/` directory or another plugin's files.

The offline suite uses actual malloryapi 0.4.0 with mocked HTTP responses, checks
pagination/partial coverage, source formats, report escaping and briefing state.
It does not establish live API entitlements, current data availability or actual
finding/delivery success. See [validation notes](docs/validation.md).
