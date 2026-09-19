# Optional finding writes via malloryapi

Report-only is the default. A request to create findings, including a saved
monitor setting, authorizes the documented writes; do not ask again. Assessment
without writes must work without Findings access. Never infer authorization
from a match. No remediation, ticket creation, status changes or notifications
are implicit.

With writes requested, verify the exact managed definition:

```python
definition = client.finding_definitions.get(slug, scope='global')
history = collect_pages(client.findings.list, limit=25,
    definition_slug=slug, asset_type=asset_type, asset_identifier=asset_identifier)
```

Check its returned `slug`, global owner (`tenant_uuid` equal to
`ffffffff-ffff-ffff-ffff-ffffffffffff`), `is_managed: true`, non-deprecated state,
and usable metadata.
Match that owner against history's `definition_tenant_uuid`. A tenant-owned
same-slug definition is not interchangeable. Preserve exact identity. Compare
`qualifier` locally; it is not a supported list filter. Read all statuses and
all pages. Failed/incomplete history means `qualifies_but_not_filed`, never
permission to create. A missing definition blocks filing but retain assessment
results; do not register a replacement definition.

The key is `(authenticated tenant, global definition owner/slug, asset_type,
asset_identifier, qualifier)`. Use actual canonical asset IDs. `generic` is the
fallback for roster/profile/observable identities; do not invent asset-type
enum members. The individual playbook specifies qualifier and recurrence.

Preserve exact open findings. Preserve dismissals; do not recreate or reopen
without an explicit user instruction. Fixed recurrence is workflow-specific.
Unless that skill establishes fresh evidence meeting its recurrence rule,
suppress fixed history as well. Only exposure validation performs monotonic
severity/confidence escalation; it never lowers either dimension.

Construct an evidence-backed payload from observed data:

```python
payload = {
    'definition_slug': slug, 'definition_scope': 'global',
    'asset_type': asset_type, 'asset_identifier': asset_identifier,
    'qualifier': qualifier, 'title': title, 'summary': summary,
    'body': explanation, 'remediation': remediation,
    'severity': severity, 'confidence': confidence,
    'asset_details': assessed_snapshot,
    'evidence': [{'kind':'text', 'title':'Assessment evidence', 'description': evidence_text}],
}
# Optional: thread_uuid only from a real trusted runtime thread; never invent one.
result = client.findings.create(payload)
```

The SDK create call returns the created finding detail dictionary (HTTP 201),
not the internal agent tool's batch envelope. Require its UUID and verify its
identity. A duplicate raises `malloryapi.exceptions.APIError` with status 409;
inspect `exc.response_body["detail"]` for `existing_finding_uuid` and verify by readback.
A missing definition or invalid payload raises an error (typically 422), not
a successful result. Retain independent failures and ambiguous acknowledgments
as filing gaps. Reconcile ambiguous writes using complete
history reads before retrying; never change identity to evade deduplication.
Link only supported verified vulnerability/threat_actor/story UUIDs in
`entities`; other records belong in evidence/asset_details.

For exposure escalation only, read the current finding and send just the
increased fields plus a body preserving existing details and explaining new
evidence:

```python
result = client.findings.update(finding_uuid, {
    'severity': new_severity, 'confidence': new_confidence, 'body': combined_body,
})
```

Omit fields that did not increase. Do not change identity/status. Read back the
finding before reporting success, and record old/new values. Concurrent writers
are not transactionally locked by the SDK; if state changed, reread and reassess
rather than overwriting newer evidence. No claimed automatic exactly-once writes.
