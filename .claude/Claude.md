# Mallory Agent

A collection of Claude Code/OpenCode-compatible skills for threat intelligence analysis and security research.

## Running Python with PDM

This project uses [PDM](https://pdm-project.org/) for Python dependency management.

### Install dependencies

```bash
# Install base dependencies
pdm install

# Install skill-specific dependencies via optional groups
pdm install -G intel-feed-finder   # For intel-feed-finder skill
pdm install -G image-gen           # For image-gen skill

# Install all optional dependencies
pdm install -G :all
```

### Running Python scripts

Always use `pdm run` to execute Python scripts:

```bash
# Run a skill script from repo root
pdm run python .claude/skills/intel-feed-finder/scripts/rss_finder.py --help
pdm run python .claude/skills/image-gen/scripts/image-gen.py --help
```

## Available Skills

Skills are located in `.claude/skills/`. Each skill has a `SKILL.md` file with detailed usage instructions.

| Skill                        | Directory                                  | Description                               | When to Use                                                                         |
| ---------------------------- | ------------------------------------------ | ----------------------------------------- | ----------------------------------------------------------------------------------- |
| **mallory-api**              | `.claude/skills/mallory-api/`              | Query the Mallory threat intelligence API | When you need current threat intel about actors, vulnerabilities, exploits, malware |
| **intel-feed-finder**        | `.claude/skills/intel-feed-finder/`        | Discover RSS/Atom/JSON feeds from URLs    | When setting up new threat intel sources or finding syndication feeds               |
| **image-gen**                | `.claude/skills/image-gen/`                | Generate images using AI models           | When you need to create diagrams, flowcharts, or visualizations                     |
| **adversary-emulation**      | `.claude/skills/adversary-emulation/`      | Adversary emulation techniques            | When researching or simulating threat actor TTPs                                    |
| **vulnerability-escalation** | `.claude/skills/vulnerability-escalation/` | Vulnerability escalation research         | When analyzing privilege escalation or vulnerability chains                         |

### Skill: mallory-api

**Use when:** You need up-to-date threat intelligence information about:

- Threat actors (APT groups, cybercriminals)
- Vulnerabilities (CVEs, trending vulns)
- Exploits and exploitation activity
- Malware families

**Quick start:**

```bash
# Set API key (get one at https://app.mallory.ai/api/keys)
export MALLORY_API_KEY="your-api-key"

# Query vulnerabilities
curl -s "https://api.mallory.ai/v1/vulnerabilities/CVE-2024-1234" \
  -H "Authorization: Bearer $MALLORY_API_KEY" | jq

# Get trending vulnerabilities
curl -s "https://api.mallory.ai/v1/vulnerabilities/trending/diff" \
  -H "Authorization: Bearer $MALLORY_API_KEY" | jq
```

See `.claude/skills/mallory-api/SKILL.md` for full API documentation.

### Skill: intel-feed-finder

**Use when:** You need to discover RSS/Atom/JSON feeds from a URL.

**Quick start:**

```bash
# Install intel-feed-finder dependencies
pdm install -G intel-feed-finder

# Find feeds from a URL
pdm run python .claude/skills/intel-feed-finder/scripts/rss_finder.py -a https://krebsonsecurity.com
```

See `.claude/skills/intel-feed-finder/SKILL.md` for all options.

### Skill: image-gen

**Use when:** You need to generate:

- Network diagrams or flowcharts
- Architecture visualizations
- Tables rendered as images

**Quick start:**

```bash
# Install image-gen dependencies
pdm install -G image-gen

# Generate an image
pdm run python .claude/skills/image-gen/scripts/image-gen.py \
  --prompt "A minimal flowchart showing: Input -> Process -> Output" \
  --output diagram.png
```

See `.claude/skills/image-gen/SKILL.md` for prompt templates and best practices.

## Project Structure

```
mallory-agent/
├── .claude/
│   ├── Claude.md              # This file (pack-level instructions)
│   └── skills/                # Canonical skill location
│       ├── mallory-api/
│       ├── intel-feed-finder/
│       ├── image-gen/
│       ├── adversary-emulation/
│       └── vulnerability-escalation/
├── skills/                    # Symlink to .claude/skills/ (backward compat)
├── docs/
│   └── openapi-public.json    # Mallory API OpenAPI spec
├── scripts/
│   └── validate_skills.py     # Skill validation utility
├── src/
│   └── mallory_agent/         # Python package (future use)
├── tests/
├── pyproject.toml             # Root dependencies + optional groups
└── pdm.lock
```

## Best Practices

1. **Always read the SKILL.md** before using a skill - it contains the most current instructions
2. **Install dependencies** before running any Python scripts: `pdm install`
3. **Use optional groups** for skill-specific deps: `pdm install -G <group>`
4. **Use pdm run** to execute Python to ensure correct environment
5. **Keep API keys secure** - use environment variables, never commit to git
