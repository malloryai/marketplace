# Security Workflows Implementation Plan

> For agentic workers: execute the approved scope task-by-task with tests and review.

**Goal:** Ship usable public security skills backed by malloryapi 0.4.0.
**Architecture:** Three independent plugin installs, declarative SDK playbooks,
shared artifact/pagination utilities, and backward-compatible scanner/briefing
extensions. Bundle common files with a reproducible sync script.
**Tech Stack:** Markdown, Python standard library, malloryapi 0.4.0, unittest.
**Spec:** ../specs/2026-09-19-security-workflows.md

## Global constraints

- malloryapi 0.4.0 owns all Mallory HTTP/auth access; no raw transport wrapper.
- Assessment-only by default; explicit finding authorization is preserved.
- Reports distinguish complete, partial, blocked, negative and unresolved.
- Never claim component presence proves execution or tenant compromise.
- No live mutations or external deliveries during verification.
- No private mounted paths, Mastra tool names, or sibling-plugin file dependencies.

## Tasks

- [x] Shared support: write failing tests for paginated SDK/raw relationship responses,
  changing totals, partial errors, report validation and HTML escaping; implement
  shared/workflow_support.py and shared runtime/output/finding references.
- [x] Author five new assessment/exercise skills and the recurring supply-chain
  orchestration skill, grounded in internal merged playbooks and exact SDK source.
  Include SDK recipes, inputs, output contracts and workflow-specific identities.
- [x] Extend daily briefing with a separate SDK-backed workspace collector and
  durable per-section state, preserving the existing command. Test first-run
  baselines, newly matched older stories, failed reads, and workspace isolation.
- [x] Extend compromised-package scanning with CycloneDX/GitLab inputs, complete
  compromise pagination and explicit evidence/coverage. Preserve SPDX commands.
- [x] Add manifests/catalog entries, bundle common files, update README/version,
  and remove the stale missing vulnerability-escalation listing.
- [x] Verify SDK request contracts with httpx.MockTransport, run focused unittest
  coverage, plugin validators, compileall and diff checks. Review simulated
  evidence scenarios and record material limits.

## Progress

Baseline: six skills, one plugin, validator passes. Missing all five new workflows;
existing briefing lacks workspace/delta state and scanner assumes SPDX + GitHub.
Independent baseline evaluator could not run because its usage budget was unavailable.
Use deterministic fixtures and a local scenario review; do not claim agent-eval success.
PyPI 0.4.0 returned 404; exact v0.4.0 tag f23ae7f installed from an archived source
checkout into .venv without including uncommitted SDK files.

Initial implementation completed with 26 offline tests; PR review added
regressions and tightened output, pagination, queue and finding-write contracts. Shared references/helpers and the
scanner are bundled reproducibly. The canonical directory is shared/ plus the
scanner in plugins/mallory. Codex compatibility additionally required quoting
the pre-existing hunt-pack frontmatter description; its workflow is unchanged.
Local scenario review and exact-client HTTP fixtures substitute for the unavailable
independent agent evaluation; no live finding or notification writes were made.
