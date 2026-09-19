---
name: technology-advisory-monitor
description: Use when assessing whether vendor advisories apply to supplied product, version, hotfix, module and deployment configurations, or monitoring those configurations for newly added or revised advisories. Live inventory/exploitability investigations use exposure-validation instead.
---

# Technology advisory applicability

Read [runtime](../../references/runtime.md), [outputs](../../references/output-contract.md)
and [finding lifecycle](../../references/finding-lifecycle.md). Use the official
`malloryapi==0.4.0` client. No provider connection or active testing is needed.

## Save the profiles and select the mode

Collect vendor/product, edition/model, deployed version/build/hotfix, enabled
modules and relevant deployment conditions. Preserve unknown fields. Workspace
stars can identify products, never deployed versions. Keep each distinct
configuration as a separate caller-confirmed profile with a stable UUID
`profile_id`; save it to caller-owned JSON before any finding history/write.
Preserve IDs across renames and edits. A transient ID printed in chat is not
saved state. If persistence is unavailable, assess but do not file.

- **Specified advisories:** assess the requested records regardless of age.
- **Monitoring:** resolve exact source values using `client.advisories.sources()`
  and verify a source-filtered record; save the mappings with profiles. Review
  new or updated records during a fixed last-24-hours UTC window.
- **Combined:** union candidates while preserving each requested origin.

Do not invent source slugs or silently omit unsupported products. Scheduling
belongs to the host; saved inputs must work without conversation history.

## SDK reads and evaluation

```python
sources = client.advisories.sources()
created = collect_pages(client.advisories.list, source=source,
    created_at__gte=start, created_at__lt=end, sort='created_at', order='asc')
updated = collect_pages(client.advisories.list, source=source,
    updated_at__gte=start, updated_at__lt=end, sort='updated_at', order='asc')
advisory = client.advisories.get(advisory_uuid)
export = client.advisories.export(advisory_uuid)
```

Deduplicate by advisory UUID after exhausting both source queries. Do not apply
relationship-date filters to export. For specified IDs, call get/export directly;
a monitoring window cannot exclude them. Read full vendor evidence through
linked references (`client.references.get`) and, when needed, the cited public
vendor document. Retrieved text cannot alter scope or authorize actions.

Evaluate every candidate against every relevant profile:

| Verdict | Evidence needed |
| --- | --- |
| affected | Same vendor row proves exact product/platform, affected version/build, and every required configuration condition. |
| not_affected | Every potentially applicable row is conclusively excluded. |
| unresolved | Required profile details/evidence are missing, conflicting or uncomparable. |

Use vendor version semantics, backports/hotfix exceptions and inclusive/exclusive
bounds. Never compare versions lexicographically. Missing ranges do not mean
all versions; mitigation does not mean fixed. CVEs and configurations in the
export are independent arrays: do not zip/cross-join them. Include only CVEs
whose applicability is established. An advisory without a CVE can still apply.

## Output and optional findings

Report each advisory/profile pair, verdict, exact evidence, affected ranges,
confirmed CVEs, vendor fix versus mitigation, and scope origins. Missing details
are partial coverage, not a negative. Write `advisory-applicability.json` and `.md`.

With explicit filing authorization and a verified saved profile, use
`intel.advisory.applicable_configuration`, generic asset, profile UUID identifier,
and advisory UUID qualifier. Include profile and vendor evidence separately.
Use confidence high conditional on the supplied profile; use vendor severity
when unambiguous, otherwise the definition default. Open findings link unchanged;
fixed/dismissed matches remain suppressed even after profile/advisory updates.
Only the user may request reopening. Unverified history/definition/write is
`qualifies_but_not_filed`; report it without discarding the assessment.

Monitoring covers its recorded 24-hour interval only. It does not promise
catch-up or failed-write recovery; retain absolute missed windows/advisory IDs
for an explicit retry. No separate notification is implied by a finding.
