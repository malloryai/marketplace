# Public security workflows

Implement the user-approved seven workflow interactions using the official
malloryapi 0.4.0 client. The existing mallory plugin gains a story-based tabletop
skill and richer daily briefing and compromised-package workflows. Add
mallory-monitoring (third-party breaches, advisory applicability, supply-chain
monitoring) and mallory-investigations (exploited-CVE exposure and observable
investigation). Each install is self-contained; common support is generated
from shared/ rather than maintained independently.

Reports carry scope, a fixed UTC window where applicable, evidence, actions,
coverage gaps, and finding outcomes. Report-only is the default. Explicit
finding requests authorize only the documented creates. Review established that
0.4.0 cannot safely escalate concurrent findings; requested escalations remain
evidence-backed recommendations with an explicit filing gap. Preserve
existing dismissals and workflow-specific fixed-finding recurrence semantics.
Scheduling and external delivery belong to the host and are opt-in.

Use real SDK resource methods and no replacement HTTP client. New playbooks
are agent-executed evidence assessments, with deterministic helpers only for
pagination, artifacts, and existing report/scanner extensions. No autonomous
scheduler, LLM wrapper, live production writes, or publication in this change.
Keep existing standalone commands compatible. Validate offline with the exact
v0.4.0 release source and mocked SDK HTTP responses; live integration outcomes
are outside these offline checks.
