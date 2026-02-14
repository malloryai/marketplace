---
name: adversary-emulation-planning
version: 1.0.0
description: Research and simulate threat actor TTPs using MITRE ATT&CK framework. Use when planning adversary simulations or TTP research.
runtime: knowledge
---

# Adversary Emulation

Research and document adversary tactics, techniques, and procedures (TTPs) for security testing and threat simulation.

## When to Use

- Research threat actor TTPs for a specific group
- Plan adversary simulation or red team exercises
- Map behaviors to MITRE ATT&CK framework
- Document attack chains for purple team exercises
- Develop detection rules based on known techniques

## Data Access

When you need threat actor data, attack patterns, or TTPs from the Mallory platform, use the **mallory-api** skill. Key endpoints for adversary emulation:

- `GET /v1/actors/{identifier}` — Threat actor details
- `GET /v1/actors/{identifier}/attack_patterns` — MITRE ATT&CK techniques
- `GET /v1/actors/{identifier}/export` — Full profile with relationships
- `GET /v1/search?q=...&types=threat_actor` — Search for actors by name

## Emulation Workflow

1. **Select Threat Actor**: Choose based on industry targeting or recent activity
2. **Research TTPs**: Get attack patterns and techniques from Mallory API
3. **Map to ATT&CK**: Align techniques to MITRE ATT&CK matrix
4. **Plan Execution**: Design test scenarios for each technique
5. **Document Detections**: Record expected detection opportunities

## Resources

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [MITRE Caldera](https://caldera.mitre.org/)
