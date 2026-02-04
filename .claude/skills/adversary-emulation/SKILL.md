---
name: adversary-emulation
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

## MITRE ATT&CK Integration

Use the Mallory API to get threat actor TTPs:

```bash
# Get attack patterns for a threat actor
curl -s "https://api.mallory.ai/v1/actors/APT29/attack_patterns" \
  -H "Authorization: Bearer $MALLORY_API_KEY" | jq
```

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
