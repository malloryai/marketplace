## Mallory Security Plugin Marketplace

A [Claude Code plugin marketplace](https://code.claude.com/docs/en/plugin-marketplaces) providing security operations skills for threat intelligence, adversary emulation, and vulnerability research.

## Quick Start

```bash
# Add the marketplace
/plugin marketplace add malloryai/marketplace

# Install the plugin
/plugin install mallory@mallory
```

## Setup

The **mallory-api** skill is the hub for all Mallory API access. It uses the official [`malloryapi`](https://pypi.org/project/malloryapi/) Python SDK. The **adversary-emulation-planning** and **vulnerability-escalation** skills use mallory-api when they need threat actor or vulnerability data.

```bash
# Install the SDK (always grab the latest)
uv pip install --system --upgrade malloryapi
# or, on an externally-managed Python without uv: pip install --user --upgrade malloryapi

# Set your API key (the SDK reads this automatically)
export MALLORY_API_KEY="your-api-key"
```

Get a key at `https://app.mallory.ai/api/keys`.

## Available Skills

The `mallory` plugin includes the following skills:

| Skill                            | Runtime   | Description                                                                                                                                               |
| -------------------------------- | --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **mallory-api**                  | python    | Query Mallory threat intelligence API for actors, vulnerabilities, exploits, malware (hub for API access)                                                 |
| **adversary-emulation-planning** | knowledge | Adversary emulation and TTP research using MITRE ATT&CK; uses mallory-api for data                                                                        |
| **vulnerability-escalation**     | python    | Privilege escalation and vulnerability chain analysis; uses mallory-api + [assetquery](https://pypi.org/project/assetquery/) for deployed asset discovery |
| **actor-tactic-timeline**        | python    | Chart how a threat actor's MITRE ATT&CK TTPs evolve over time; uses mallory-api for observation data                                                       |

## Example Use Cases

### Threat Intelligence

- Query trending vulnerabilities and threat actors
- Get detailed exploit and exploitation activity data

### Detection Engineering

- Monitor news for new TTPs and IoC information
- Generate detection candidates in KQL / SQL / Sigma

### Adversary Simulation

- Research threat actor TTPs via MITRE ATT&CK
- Track how an actor's tactics evolve over time and spot emerging techniques
- Plan red team and purple team exercises

### Exploit & Vulnerability Analysis

- Analyze exploit efficacy and capability
- Map privilege escalation chains
- Find where vulnerable software is deployed across AWS, Azure, GCP, GitHub, CrowdStrike

## Repository Structure

```
marketplace/
├── .claude-plugin/
│   └── marketplace.json              # Marketplace catalog
├── plugins/
│   └── mallory/                      # The mallory plugin
│       ├── .claude-plugin/
│       │   └── plugin.json
│       ├── skills/
│       │   ├── mallory-api/
│       │   │   ├── SKILL.md
│       │   │   ├── reference.md
│       │   │   └── scripts/client.py
│       │   ├── adversary-emulation-planning/
│       │   │   └── SKILL.md
│       │   ├── vulnerability-escalation/
│       │   │   ├── SKILL.md
│       │   │   ├── reference.md
│       │   │   └── scripts/escalation.py
│       │   └── actor-tactic-timeline/
│       │       ├── SKILL.md
│       │       └── scripts/tactic_timeline.py
├── scripts/
│   └── validate_plugins.py
├── pyproject.toml
└── README.md
```

## Development

### Validate

```bash
# Custom validator (CI-friendly)
python3 scripts/validate_plugins.py --verbose

# Built-in Claude Code validation
claude plugin validate .
```

### Adding a New Skill

1. Create directory: `plugins/mallory/skills/<skill-name>/`
2. Create `SKILL.md` with frontmatter (`name`, `description`, optionally `allowed-tools`)
3. Add scripts in `scripts/` subdirectory if needed
4. Run `python3 scripts/validate_plugins.py` to verify

### Skill Format

Each skill has a `SKILL.md` with YAML frontmatter:

```yaml
---
name: my-skill
description: Brief description (max 1024 chars)
allowed-tools: Bash(python *)
---
```

### Naming Rules

- 1-64 characters, lowercase alphanumeric with single hyphen separators
- Regex: `^[a-z0-9]+(-[a-z0-9]+)*$`
