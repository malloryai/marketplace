# Workflow output contract (version 1)

Produce a concise readable answer and save a JSON artifact with these fields:

```json
{
  "schema_version": 1,
  "skill": "third-party-breach-monitor",
  "scope": {"roster": ["Example vendor"]},
  "window": {"start": "2026-01-01T00:00:00Z", "end": "2026-01-02T00:00:00Z"},
  "status": "partial",
  "summary": "One company could not be checked.",
  "results": [{"subject": "Example vendor", "verdict": "unchecked", "assessed_at": "2026-01-02T00:00:00Z", "evidence": [], "recommended_actions": ["Retry the failed lookup"]}],
  "coverage": {"examined": 0, "requested": 1, "gaps": ["Organization lookup unavailable"]},
  "finding_actions": []
}
```

This is a synthetic shape example, not real intelligence. `scope` carries the
confirmed workspace/roster/profiles/repositories and authenticated tenant UUID
when relevant. `window` is null for specified-advisory or supplied-SBOM requests
without a time window. Each result requires `assessed_at`, the UTC assessment
time in `YYYY-MM-DDTHH:MM:SS[.ffffff]Z` form (or the equivalent `+00:00` suffix).
Dates without a time, timezone-free values, invalid dates and non-UTC offsets
are rejected. Keep event, ingestion and assessment times separate.

Each result requires a nonempty string `subject`, a `verdict` from the table
below, `assessed_at`, an `evidence` list and a `recommended_actions` list of
nonempty strings. Evidence entries are objects or strings containing actual SDK
methods/parameters, record IDs, source links, relevant returned values and dates;
recommendations describe the next useful action. Include every
requested subject, including unchecked ones; a negative means only the stated
scope and evidence were checked. Do not invent links, IDs or receipts.

| Skill | Result verdicts |
| --- | --- |
| third-party-breach-monitor | `matched`, `no_matching_breaches`, `linked_not_breached_party`, `linked_role_unclear`, `unchecked` |
| technology-advisory-monitor | `affected`, `not_affected`, `unresolved`, `unchecked` |
| exposure-validation | `exposed`, `not_exposed`, `unverifiable`, `unchecked` |
| observable-investigation | `malicious_opinion`, `no_malicious_opinion`, `unchecked` |
| supply-chain-compromise-monitor / compromised-package-scan | `confirmed_component_exposure`, `potential_match`, `no_affected_version`, `unchecked` |
| story-based-tabletop-exercise | `selected`, `not_selected`, `unchecked` |
| daily-briefing | `reported`, `incomplete` |

This vocabulary applies to assessment artifacts; the scanner's raw data keeps
its existing `CONFIRMED`/`REVIEW` statuses. Custom skill names may use the listed
verdicts; new vocabulary requires a contract/validator update. Unknown metadata
fields remain allowed at every level.

`coverage.examined` and `coverage.requested` are required nonnegative integer
counts in the same unit: completed subject assessments versus the declared
scope. State the unit in `coverage.unit` when ambiguous (for workspace briefings,
the unit is the four briefing sections, not evidence rows). Include unchecked
subjects in requested, not examined. Examined cannot exceed requested; complete
requires equality. `coverage.gaps` is always a list, including when empty.

Every `finding_actions` entry requires an `identity` object and `status`.
Identity requires nonempty strings `tenant_uuid`, `definition_tenant_uuid`,
`definition_slug`, `asset_type`, `asset_identifier`, plus `qualifier` (an exact
string, or null for no qualifier). Use `not_requested`, `created`, `already_open`,
`escalated`, `suppressed_by_prior_resolution`, or `qualifies_but_not_filed` as the
status. Report-only matching results use `not_requested`; no actions uses `[]`.
`created`, `already_open` and `escalated` require a verified `finding_uuid`;
add a verified `url` only when available. `escalated` additionally requires
nonempty `before`/`after` objects. It is reserved for a future verified guarded
update; malloryapi 0.4.0 must instead report requested escalation as
`qualifies_but_not_filed`, as described in [finding lifecycle](finding-lifecycle.md).

- **complete:** all promised checks completed for the declared scope.
- **partial:** useful work completed but unresolved evidence, failed reads,
  unreviewed records, required missing fields or requested write/delivery gaps remain.
- **blocked:** no useful assessment could run due to missing prerequisites.

Never emit complete with coverage gaps. Limits are visible: a deliberately
bounded tabletop's 20-story selection is its scope; a capped exhaustive
inventory assessment is partial. An empty complete result is distinct from a
failed query. Keep evidence concise enough to read; large raw input stays in
separate files with verified paths.

Render the JSON artifact with the bundled helper, using the installed plugin's
absolute root and a caller-selected output directory:

```bash
python "$PLUGIN_ROOT/scripts/workflow_support.py" result.json --output-prefix output/review
# Add --html for a dependency-free, escaped HTML copy.
```

The helper makes Markdown and preserves the exact JSON. Tabletop additionally
writes the complete exercise Markdown (not just a report summary). Briefings
also emit HTML. Never claim files exist before writing and checking them.
