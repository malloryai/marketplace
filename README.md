## Mallory Skills Agent

A collection of Claude Code/OpenCode-compatible skills for security operations practitioners. Provides threat intelligence, feed discovery, image generation, and security research capabilities.

## Quick Start

```bash
# Clone the repo
git clone https://github.com/malloryai/mallory-agent.git
cd mallory-agent

# Install dependencies (requires Python 3.12+)
pdm install

# For skills with additional dependencies, install their group:
pdm install -G intel-feed-finder   # For intel-feed-finder skill
pdm install -G image-gen           # For image-gen skill
```

## API Key Setup

An API key is required for the Mallory API skill. Visit `https://app.mallory.ai/api/keys` to obtain a key:

```bash
# Set via environment variable (recommended)
export MALLORY_API_KEY="your-api-key"

# Or store in a file
echo "your-api-key" > .claude/skills/mallory-api/.api_key
```

## Repository Structure

```
mallory-agent/
├── .claude/
│   ├── Claude.md              # Pack-level agent instructions
│   └── skills/                # Canonical skill location
│       ├── mallory-api/       # Threat intelligence API
│       ├── intel-feed-finder/ # RSS/Atom feed discovery
│       ├── image-gen/         # AI image generation
│       ├── adversary-emulation/
│       └── vulnerability-escalation/
├── skills/                    # Symlink to .claude/skills/ (backward compat)
├── docs/                      # Shared documents (OpenAPI specs)
├── scripts/                   # Repo-level utilities
├── pyproject.toml             # Root dependencies + optional groups
└── README.md
```

**Canonical skill path:** `.claude/skills/<skill-name>/SKILL.md`

The `skills/` directory is a symlink to `.claude/skills/` for backward compatibility.

## Available Skills

| Skill                        | Directory                                  | Description                                                                          |
| ---------------------------- | ------------------------------------------ | ------------------------------------------------------------------------------------ |
| **mallory-api**              | `.claude/skills/mallory-api/`              | Query Mallory threat intelligence API for actors, vulnerabilities, exploits, malware |
| **intel-feed-finder**        | `.claude/skills/intel-feed-finder/`        | Discover RSS/Atom/JSON feeds from URLs for threat intel sources                      |
| **image-gen**                | `.claude/skills/image-gen/`                | Generate images using Google Imagen or OpenAI models                                 |
| **adversary-emulation**      | `.claude/skills/adversary-emulation/`      | Adversary emulation and TTP research                                                 |
| **vulnerability-escalation** | `.claude/skills/vulnerability-escalation/` | Privilege escalation and vulnerability chain analysis                                |

## Example Use Cases

### Attack Surface Management

- Correlate an organization to its top level domains
- Search for subdomains
- Resolve subdomains to hosts, scope an analysis
- Analyze an application for exposures or vulnerabilities

### Exposure Management

- Monitor a technology for recent component or library vulnerabilities
- Monitor the news for recent component or library vulnerabilities
- Search GitHub/GitLab repositories for affected instances of a given vulnerability

### Threat Intelligence

- Discover RSS feeds for security blogs and vendor advisories
- Query trending vulnerabilities and threat actors
- Get detailed exploit and exploitation activity data

### Exploit Analysis

- Obtain new samples from Mallory
- Analyze exploit for efficacy and capability

### Malware Analysis

- Obtain new samples from VirusTotal
- Analyze samples for maliciousness

### Detection Engineering

- Monitor the news for new TTPs and IoC information
- Generate detection candidates in KQL / SQL / Sigma
- Search SIEMs for identification of the behavior

## Compatibility

This skillpack is compatible with:

- **Claude Code** (via `.claude/skills/` directory)
- **OpenCode** (via `.claude/skills/` or symlinked `skills/`)

Skills follow the [Claude Code skill authoring best practices](https://docs.claude.com/en/docs/agents-and-tools/agent-skills/best-practices) and use OpenCode-compatible naming conventions.

## Development

```bash
# Validate all skills
pdm run python scripts/validate_skills.py

# Run a skill script directly
pdm run python .claude/skills/intel-feed-finder/scripts/rss_finder.py --help
```

## Skill Format

Each skill has a `SKILL.md` file with YAML frontmatter:

```yaml
---
name: my-skill # Must match directory name (OpenCode convention)
version: 1.0.0 # Semantic version
description: Brief description of what the skill does (max 1024 chars)
runtime: python # Runtime: python, knowledge, docker (future)
deps-group: my-skill # Optional: PDM dependency group name
entrypoints: # Optional: executable scripts
  - scripts/main.py
---
# Skill Title

Markdown content with usage instructions...
```

### Required Fields

- `name`: Lowercase alphanumeric with hyphens (e.g., `my-skill-name`)
- `description`: What the skill does and when to use it (1-1024 chars)

### Optional Fields

- `version`: Semantic version (e.g., `1.0.0`)
- `runtime`: Execution environment (`python`, `knowledge`, `docker`)
- `deps-group`: PDM optional dependency group for this skill
- `entrypoints`: List of executable scripts relative to skill directory

### Naming Rules (OpenCode-compatible)

- 1-64 characters
- Lowercase alphanumeric
- Single hyphen separators (no consecutive hyphens)
- Cannot start or end with hyphen
- Regex: `^[a-z0-9]+(-[a-z0-9]+)*$`

## Adding a New Skill

1. Create directory: `.claude/skills/<skill-name>/`
2. Create `SKILL.md` with frontmatter and instructions
3. Add scripts in `scripts/` subdirectory (if needed)
4. Add dependencies to root `pyproject.toml` as optional group (if needed)
5. Run `python scripts/validate_skills.py` to verify
