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
uv pip install --system --upgrade malloryapi

# Alternative
pip install --user --upgrade malloryapi
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

## API Endpoints

Every call goes through an SDK accessor (`client.<resource>.<method>(...)`); the
REST path is shown for orientation only — call the SDK, not raw HTTP. See
`reference.md` for the full per-method signatures.

### Threat intelligence entities

| Accessor | REST path | Purpose | Key methods |
| --- | --- | --- | --- |
| `client.vulnerabilities` | `/vulnerabilities` | CVEs with scores, exploits, affected products | `list`, `get`, `trending`, `exploited`, `exploits`, `exploitations`, `products`, `advisories`, `malware`, `threat_actors`, `detection_signatures`, `configurations`, `observables`, `export`, `enrich` |
| `client.threat_actors` | `/actors` | Adversary groups, their TTPs and targeting | `list`, `get`, `trending`, `attack_patterns`, `malware`, `exploitations`, `observables`, `source_geographies`, `target_geographies`, `target_industries`, `mentions`, `export`, `enrich` |
| `client.malware` | `/malware` | Malware families and their relationships | `list`, `get`, `trending`, `vulnerabilities`, `attack_patterns`, `threat_actors`, `observables`, `mentions`, `export`, `enrich` |
| `client.exploits` | `/exploits` | Exploit code/PoCs | `list`, `get`, `vulnerabilities`, `export`, `enrich` |
| `client.exploitations` | `/exploitations` | Observed exploitation-in-the-wild events | `list`, `get` |
| `client.attack_patterns` | `/attack_patterns` | MITRE ATT&CK techniques | `list`, `get`, `trending`, `threat_actors`, `malware`, `mentions` |
| `client.organizations` | `/organizations` | Vendors/orgs, their products and breaches | `list`, `get`, `trending`, `products`, `breaches`, `mentions`, `export`, `enrich` |
| `client.products` | `/products` | Technology products | `list`, `get`, `trending`, `search`, `advisories`, `mentions`, `export`, `enrich` |
| `client.advisories` | `/technology_product_advisories` | Vendor security advisories | `list`, `get`, `products`, `vulnerabilities`, `sources`, `export` |
| `client.breaches` | `/breaches` | Breach events and attribution | `list`, `get`, `organizations`, `threat_actors`, `malware`, `attack_patterns`, `mentions`, `export` |
| `client.detection_signatures` | `/detection_signatures` | Detection rules (e.g. YARA/Sigma) | `list`, `get` |
| `client.weaknesses` | `/weaknesses` | CWE weakness taxonomy | `list`, `get` |
| `client.packages` | `/packages` | Software packages tracked for compromise | `list`, `get`, `compromises`, `configurations`, `mentions` |
| `client.vulnerable_configurations` | `/vulnerable_technology_product_configuration_sets` | CPE-style affected-version sets | `list`, `get`, `by_vulnerability`, `by_configuration`, `search` |
| `client.extensions` | `/extensions` | Tracked extensions, with configs and mentions | `list`, `get`, `configurations`, `mentions` |
| `client.industries` | `/industries` | Industry-sector taxonomy | `list`, `get` |
| `client.geographies` | `/geographies` | Country/region taxonomy | `list`, `get` |

### Observables & opinions

| Accessor | REST path | Purpose | Key methods |
| --- | --- | --- | --- |
| `client.observables` | `/observables` | IOCs (IPs, domains, hashes, URLs) | `list`, `get`, `get_by_type_name`, `create`, `update`, `delete`, `opinions`, `opinions_by_type_name` |
| `client.opinions` | `/opinions` | Verdicts/assessments about observables | `list`, `get`, `create`, `update`, `delete`, `grouped` |

### Content & search

| Accessor | REST path | Purpose | Key methods |
| --- | --- | --- | --- |
| `client.stories` | `/stories` | Curated intelligence stories | `list`, `get`, `references`, `events`, `timeline`, `entities`, `observables`, `citations`, `similar`, `topics`, `exposure`, `export` |
| `client.references` | `/references` | Source articles/reports | `list`, `get`, `create`, `entities`, `threat_actors`, `vulnerabilities`, `observables`, `citations`, `labels` |
| `client.sources` | `/sources` | Intel source registry | `list`, `statistics`, `create` |
| `client.content_chunks` | `/content_chunks` | Indexed content for semantic search | `list`, `get`, `search` |
| `client.mentions` | `/mentions` | Mention/volume trends | `list`, `actors`, `vulnerabilities` |
| `client.search` | `/search` | Cross-entity full-text search | `query` |

### Asset exposure & inventory

| Accessor | REST path | Purpose | Key methods |
| --- | --- | --- | --- |
| `client.assets` | `/assets` | Your attack surface vs. threats | `exposure_check`, `presence_check`, `vulnerabilities`, `profile`, `profile_for`, `inventory_hosts`, `inventory_software`, `inventory_users`, `inventory_repositories`, `inventory_cloud_resources`, `inventory_vulnerability_instances`, `upload`, `uploads`, `upload_status`, `upload_retry` |

### Account, workspaces & automation

| Accessor | REST path | Purpose | Key methods |
| --- | --- | --- | --- |
| `client.user` | `/user` | Current authenticated user | `me` |
| `client.tenants` | `/tenants` | Tenants and their users | `list`, `users` |
| `client.workspaces` | `/workspaces` | Team collections of entities/topics/sources | `list`, `get`, `create`, `update`, `delete`, `entities`, `add_entities`, `remove_entity`, `add_topics`, `remove_topic`, `sources`, `add_sources`, `members`, `add_member`, `update_member`, `remove_member` |
| `client.profiles` | `/profiles` | Saved entity + topic collections | `list`, `get`, `create`, `update`, `delete`, `entities`, `add_entities`, `add_topics` |
| `client.integrations` | `/integrations` | Third-party connectors and their actions | `list`, `get`, `create`, `update`, `delete`, `capabilities`, `schemas`, `run_action` |
| `client.schedules` | `/schedules` | Recurring jobs (e.g. exports) | `list`, `get`, `create`, `update`, `delete`, `executions` |
| `client.exports` | `/exports` | Bulk export jobs and download URLs | `list`, `history`, `latest`, `get` |

### Common parameters

These recur across methods (passed as keyword args):

| Parameter | Type / values | Default | Applies to | Meaning |
| --- | --- | --- | --- | --- |
| `identifier` | str — UUID or natural key (`CVE-2024-1234`, `T1566`, actor name) | — | `get` and sub-resource accessors | Which record to fetch |
| `limit` | int | `100` | `list`, sub-resources | Page size |
| `offset` | int | `0` | `list`, sub-resources | Pagination offset |
| `sort` | str (field name) | `None` | `list` | Field to sort by |
| `order` | `"asc"` \| `"desc"` | `None` | `list` | Sort direction |
| `filter` | str (filter expression) | `None` | most `list` | Server-side filter |
| `scope` | str | `None` | `observables`/`opinions` `list` | Result scope |
| `period` | `"1d"` \| `"7d"` \| `"30d"` | `"7d"` | `trending` | Trailing window |
| `q` | str | — | `search.query`, `*.search`, `content_chunks.search` | Query text |
| `types` | comma-separated str (`threat_actor,vulnerability`) | `None` | `search.query` | Restrict to entity types |
| `data` / `urls` | dict / list | — | `create`, `update`, `upload`, `run_action` | Request body payload |

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
