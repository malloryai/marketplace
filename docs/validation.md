# Validation and release notes

## Baseline and environment

Base marketplace commit: `3f5dfbcd7d73b769aa62811c0dc38f3305334568`.
Client tested: exact `malloryapi` **v0.4.0** source tag,
`f23ae7f0ecd8dab4400a56b2ad8f3fc17a558bb2`. The tagged source was archived into an
isolated directory and installed in a local virtual environment; unrelated
uncommitted SDK files were excluded. The SDK reports package version 0.4.0.
PyPI's version endpoint and resolver did not serve 0.4.0 during verification;
the README documents installation from the exact release commit as a fallback.

The original six-skill/one-plugin structural validator passed. Baseline checks
then failed on missing report helpers/workspace collector, unsupported CycloneDX,
private-registry false confirmation, and absent full compromise pagination.
The implementation addressed those failures. Later review added regressions for
initial failed-section checkpoints, source-qualified component deduplication and
nameless SBOM components. A pre-existing unquoted colon in hunt-pack's description
failed real YAML validation; the description was quoted and angle-bracket
placeholders were replaced with plain words to satisfy skill-frontmatter validation.

## Offline checks

- 26 unittest tests: actual SDK + httpx.MockTransport request/response recipes,
  duplicate-write exception contract, pagination reconciliation/truncation,
  scanner provenance/formats/partial evidence, report escaping and saved state.
- Isolated plugin copies render JSON/Markdown/HTML without repo-level shared files.
  Both bundled scanners expose their standalone commands from isolated installs.
- Claude marketplace validation and the repository validator cover three bundles.
- Codex plugin and skill-frontmatter validators cover each shipped manifest/skill.
- Bundled copies match canonical sources; Python compilation and lint are clean.

These checks never use a real key or perform live finding, delivery, scheduler
or remediation operations. They do not prove API entitlements or current
production data availability. The independent agent evaluator was unavailable
because its runtime usage limit was reached; **no successful agent-behavior
trial is claimed**. Local scenario review follows below.

## Scenario review of the playbooks

| Scenario | Required behavior recorded in the skill |
| --- | --- |
| No relevant recent story, or only an unreadable headline | Skip/mark incomplete; never invent a recent incident or broaden the window. |
| Company merged; another roster entry appears only as responder | Follow the survivor; don't confuse a relationship with victimhood; report every roster entry. |
| Advisory matches a product but module/hotfix is unknown | Unresolved; no confirmed-applicability finding. |
| Newly exploited older CVE with unavailable reachability evidence | Exploitation event drives selection; unknown reachability stays explicit and conservative. |
| Fixed observable finding plus an old occurrence newly ingested | Recent receipt alone does not justify recurrence; compare occurrence to resolution boundary. |
| Declared package range or private registry with same public package name | Review rather than confirmed exposure; preserve provenance. |
| Old story newly matched to assets; prior baseline read failed | Compare complete ID sets independently of story freshness; retain the last successful baseline. |

These are document/contract reviews, not a substitute for a live agent evaluation.
The five new primary workflows are agent-executed skills, not autonomous verdict
programs. Host agents still need to read source evidence and apply the playbooks.

## Deliberate capability boundaries

- General cache/live SQL endpoints are absent from malloryapi 0.4.0. Skills use
  existing authorized host/provider tools for missing inspection or report the gap.
- Standalone GitLab scanning accepts exported SPDX/CycloneDX; it does not discover
  every GitLab project or retrieve dependency exports automatically.
- Workspace briefing scopes stories to the workspace; findings/vulnerability
  matches are explicitly tenant-wide. Checkpoints track collection, not delivery.
- Agent-level finding preflights, exact identity/history and recurrence rules must
  be applied before using the SDK's create/update methods. No live writes tested.
- An assessment report and an HTML file are not an external delivery receipt.
- Neither the SDK nor local checkpoint files provide atomic cross-agent locks.
  Use one collector per state file and reconcile uncertain writes before retrying.
