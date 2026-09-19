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
suppress fixed history as well. Exposure validation may recommend increased
severity/confidence for an open finding, but this SDK/API contract cannot apply
such an escalation safely against concurrent writers; use the procedure below.

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

For an open exposure finding, read its current detail and compare each dimension
with the new assessment. If either should increase, report the finding UUID,
observed severity/confidence and body, proposed increases, and supporting new
evidence. Preserve the existing finding; **do not call `findings.update`**.

The 0.4.0 SDK sends an unconditional PATCH and the API accepts no expected
version, ETag/If-Match, or compare-and-set precondition. The server locks its own
PATCH transaction, but cannot tell that a client's earlier GET is stale. A
read/compare/PATCH/readback loop can still lower another writer's newer severity
or confidence and replace its body before that loss is detected. A local lock
also cannot coordinate other clients. Do not claim a monotonic update or rely
on readback to repair such a race.

If finding writes/escalation were requested, record `qualifies_but_not_filed`
with reason `atomic_escalation_unavailable`, retain the recommendation and
coverage gap, and keep the affected work pending. Report-only recommendations
use `not_requested` and need no Findings access. If complete history shows an
exact open finding already at or above the assessment in both dimensions, link
it as `already_open`. This limitation does not block authorized creates when
complete history establishes no matching finding. Never create a second finding
to work around an escalation gap. Automatic escalation requires a future,
verified server-side conditional or monotonic update operation before this
playbook can enable it.
