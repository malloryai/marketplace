# Mallory API CLI

The Mallory API CLI is provided by the `malloryapi` package. Install and run:

```bash
pip install --upgrade malloryapi
# or: uv pip install --system --upgrade malloryapi

malloryapi --help-resources   # list resources and methods
malloryapi vulnerabilities get CVE-2024-1234
malloryapi threat_actors trending --period 7d --limit 10
```

See the skill's SKILL.md for full CLI and SDK usage.
