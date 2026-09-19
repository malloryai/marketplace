---
name: exposure-validation
description: Use when checking newly exploited vulnerabilities or KEV entries against the caller's assets, assessing their reachability, or creating and escalating evidence-backed exposure findings. Malicious package releases use supply-chain-compromise-monitor instead.
---

# Exploited-CVE exposure validation

Read [runtime](../../references/runtime.md), [outputs](../../references/output-contract.md)
and [findings](../../references/finding-lifecycle.md). Use `malloryapi==0.4.0`.
This assesses exposure, not whether the tenant has been compromised.

## Select the queue

Capture fixed UTC start/end from explicit scope or the last completed checkpoint,
else the last 24 hours. Fetch exploitation events, not CVEs created recently:

```python
events = collect_pages(client.exploitations.list,
    filter=f'begins_at>={start}', sort='begins_at', order='asc')
known_exploited = client.vulnerabilities.exploited(limit=100, offset=0)
```

Bound event rows locally to `begins_at < end`. Exhaust relevant pages, then
deduplicate by vulnerability UUID/CVE, ordering by exploitation time with CVE as
a stable tie-breaker. Review at most 20 distinct CVEs per execution; report any
remaining set and retain its earliest timestamp as the next checkpoint. Failed
CVEs also hold their timestamp for retry. A Mallory story is not an entry gate.

## Assess each CVE and asset

```python
vulnerability = client.vulnerabilities.get(cve)
presence = client.assets.exposure_check({
    'entities': [{'type':'vulnerability', 'identifier':cve}]
})
references = client.vulnerabilities.mentions(cve, limit=100, offset=0)
```

1. **Presence:** inspect affected asset families in the exposure response and
   inventory details. A version inside the affected range yields high confidence;
   established software presence with unknown version is medium. Confirmed
   outside-range assets do not qualify. A name resemblance alone does not pass.
   A failed/unpopulated inventory is unverifiable, not absent. Record the exact
   SDK query and returned asset/version evidence.
2. **Materiality:** retain the actual exploitation record/source and time.
3. **Reachability:** use available authorized code/cloud evidence to determine
   `reachable_exposed`, `reachable`, `not_reachable`, or `not_assessable`.
   Record queried evidence or the precise missing capability. Public 0.4.0 lacks
   general cached/live SQL query methods; do not use private transport or invent
   a cache-query client. Use existing host-connected provider tools if authorized,
   or return not_assessable. Presence checks remain useful without these tools.

Look for corroboration through `client.stories.list(topic_group='active-exploitation',
filter='search:'+cve)` and read full matches. Ambiguous stories require matching
reference evidence; no story is not a reason to skip exposure.

| Reachability | Without corroborating story | With story |
| --- | --- | --- |
| reachable_exposed | CRITICAL | CRITICAL |
| reachable | HIGH | CRITICAL |
| not_reachable | MEDIUM | HIGH |
| not_assessable | CRITICAL | CRITICAL |

Unknown reachability stays conservative. Confidence follows presence only;
story coverage does not increase it. Clearly disclose these prioritization rules.

## Findings, continuation and output

Default to report-only. With writes authorized, use definition
`intel.vuln.exploited_cve_validated`, canonical asset type/identifier and CVE
qualifier, one finding per asset/CVE. Link verified vulnerability/story UUIDs and
include evidence for each gate. Preserve closed decisions. For an exact open
finding, raise severity and/or confidence only if new evidence improves it;
never reduce either, overwrite identity/status, or discard the existing body.
Read back the update and report old/new values for every dimension changed.

Save `exploitation-review.json` and `.md` with reviewed CVEs, assets, gates,
severity/confidence, finding actions, skip reasons and incomplete work. Save
caller-owned checkpoint JSON only after artifacts/writes are accounted for.
A cap, query failure, unresolved presence or requested filing failure prevents
advancing beyond that work. Report-only does not require Findings access.
No active exploitation, remediation, schedule or delivery is part of assessment.
