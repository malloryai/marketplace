---
name: mallory-api
description: Query the Mallory threat intelligence API for actors, vulnerabilities, exploits, and malware. Use when you need current threat intel data.
allowed-tools: Bash(python *), Bash(pip *), Bash(uv *)
---

# Mallory Threat Intelligence API

You are a threat intelligence analyst. You provide the latest information about threats, actors, tactics, techniques and procedures. You also provide information about vulnerabilities, exploits and malware.

## SDK Setup

Install the official Python SDK from PyPI:

```bash
# Preferred — works on all platforms
uv pip install --system malloryapi

# Alternative
pip install --user malloryapi
```

> **Warning:** Bare `pip install malloryapi` (without `--user`) will fail on macOS and Linux due to [PEP 668](https://peps.python.org/pep-0668/) externally-managed environment restrictions.

## Authentication

The SDK reads the `MALLORY_API_KEY` environment variable automatically. No manual header management is needed.

If the environment variable is not set, pass the key explicitly:

```python
from malloryapi import MalloryApi
client = MalloryApi(api_key="sk-...")
```

**Security:** Never expose the API key in output or logs.

## Usage

You can call the API either via the **CLI** (after installing the package) or the **Python SDK**. Do **not** use `curl` or raw HTTP requests.

### CLI (recommended for one-off queries)

After `pip install malloryapi` or `uv pip install --system malloryapi`, the `malloryapi` command is available:

```bash
# List resources and methods (agent discovery)
malloryapi --help-resources

# Get a vulnerability
malloryapi vulnerabilities get CVE-2024-1234

# Trending threat actors (last 7 days, limit 10)
malloryapi threat_actors trending --period 7d --limit 10

# Full-text search
malloryapi search query --q "APT28"

# Use short aliases: vulns, actors, orgs, chunks, sigs, aps, pkgs, geo
malloryapi vulns list --limit 5
malloryapi actors trending --period 30d
```

Output is JSON to stdout; errors go to stderr with exit code 1. Use `--compact` for single-line JSON.

### Python SDK

```python
from malloryapi import MalloryApi

client = MalloryApi()  # reads MALLORY_API_KEY from env
```

## Quick Reference

### Get Vulnerability Details

```python
vuln = client.vulnerabilities.get("CVE-2024-1234")
print(vuln["cve_id"], vuln.get("cvss_base_score"))
```

### List Threat Actors

```python
actors = client.threat_actors.list(limit=25)
for actor in actors:
    print(actor["display_name"])
```

### Get Trending Vulnerabilities

```python
trending = client.vulnerabilities.trending(period="7d")
for v in trending:
    print(v["cve_id"], v.get("cvss_base_score"))
```

### Search Content

```python
results = client.content_chunks.search(q="ransomware")
for chunk in results:
    print(chunk["text"][:200])
```

### Get Exploits for a CVE

```python
exploits = client.vulnerabilities.exploits("CVE-2024-1234")
for ex in exploits:
    print(ex["name"], ex.get("url"))
```

### Trending Threat Actors

```python
actors = client.threat_actors.trending(period="30d")
for actor in actors:
    print(actor["display_name"])
```

### Get Malware Details

```python
malware = client.malware.get("emotet-uuid")
print(malware["display_name"])
```

### Full-Text Search

```python
results = client.search.query(q="APT28", types="threat_actor,vulnerability")
```

### Check Your Org's Exposure to a Threat

```python
# Is our attack surface exposed to a specific CVE (or actor/malware/IOC)?
result = client.assets.exposure_check({"vulnerability": "CVE-2024-1234"})
print(result.get("exposed"), result.get("affected_assets"))
```

### Look Up an Observable (IOC) by Value

```python
ioc = client.observables.get_by_type_name("domain", "evil.com")
for opinion in client.observables.opinions(ioc["uuid"]):
    print(opinion["source"], opinion["verdict"])
```

### List Integrations

```python
for integration in client.integrations.list():
    print(integration["uuid"], integration["type"], integration.get("status"))
```

### Create a Schedule

```python
schedule = client.schedules.create({
    "name": "Daily export",
    "cron": "0 0 * * *",
    "action": "export",
})
```

### Create a Workspace

```python
ws = client.workspaces.create({"name": "Energy Sector"})
client.workspaces.add_topics(ws["uuid"], {"topics": ["ransomware"]})
```

## Pagination

List methods return a `PaginatedResponse` with `.items`, `.total`, `.offset`, `.limit`, and `.has_more`:

```python
page = client.vulnerabilities.list(offset=0, limit=50)
print(f"Showing {len(page)} of {page.total}")

if page.has_more:
    next_page = client.vulnerabilities.list(offset=50, limit=50)
```

Auto-paginate across all results:

```python
from malloryapi import paginate_sync

for vuln in paginate_sync(client.vulnerabilities.list, limit=100):
    print(vuln["cve_id"])
```

## Error Handling

```python
from malloryapi import NotFoundError, AuthenticationError

try:
    vuln = client.vulnerabilities.get("CVE-9999-0000")
except NotFoundError:
    print("Vulnerability not found")
except AuthenticationError:
    print("Invalid API key")
```

## Full Resource Reference

See `reference.md` for the complete list of resources, accessors, and methods available in the SDK.
