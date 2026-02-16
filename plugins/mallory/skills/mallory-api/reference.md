# Mallory API SDK Reference

Complete reference for the `malloryapi` Python SDK.

```bash
pip install malloryapi
```

```python
from malloryapi import MalloryApi
client = MalloryApi()  # reads MALLORY_API_KEY from env
```

## Entities

### Vulnerabilities — `client.vulnerabilities`

| Method                                       | Description              | Example                                                        |
| -------------------------------------------- | ------------------------ | -------------------------------------------------------------- |
| `list(limit, offset, sort, order, **kwargs)` | List vulnerabilities     | `client.vulnerabilities.list(limit=10)`                        |
| `get(identifier)`                            | Get by CVE ID or UUID    | `client.vulnerabilities.get("CVE-2024-1234")`                  |
| `trending(period="7d")`                      | Trending vulnerabilities | `client.vulnerabilities.trending(period="30d")`                |
| `exploited(limit, offset)`                   | Actively exploited       | `client.vulnerabilities.exploited()`                           |
| `export(identifier)`                         | Full profile export      | `client.vulnerabilities.export("CVE-2024-1234")`               |
| `exploits(identifier)`                       | Known exploits           | `client.vulnerabilities.exploits("CVE-2024-1234")`             |
| `exploitations(identifier)`                  | Exploitation activity    | `client.vulnerabilities.exploitations("CVE-2024-1234")`        |
| `mentions(identifier)`                       | Source mentions          | `client.vulnerabilities.mentions("CVE-2024-1234")`             |
| `products(identifier)`                       | Affected products        | `client.vulnerabilities.products("CVE-2024-1234")`             |
| `advisories(identifier)`                     | Related advisories       | `client.vulnerabilities.advisories("CVE-2024-1234")`           |
| `observables(identifier)`                    | Related IOCs             | `client.vulnerabilities.observables("CVE-2024-1234")`          |
| `detection_signatures(identifier)`           | Detection rules          | `client.vulnerabilities.detection_signatures("CVE-2024-1234")` |
| `configurations(identifier)`                 | Affected configurations  | `client.vulnerabilities.configurations("CVE-2024-1234")`       |
| `used_by_malware(identifier)`                | Malware using this vuln  | `client.vulnerabilities.used_by_malware("CVE-2024-1234")`      |
| `enrich(identifier)`                         | AI enrichment            | `client.vulnerabilities.enrich("CVE-2024-1234")`               |

### Threat Actors — `client.threat_actors`

| Method                                       | Description             | Example                                              |
| -------------------------------------------- | ----------------------- | ---------------------------------------------------- |
| `list(limit, offset, sort, order, **kwargs)` | List actors             | `client.threat_actors.list(limit=25)`                |
| `get(identifier)`                            | Get by name or UUID     | `client.threat_actors.get("apt28-uuid")`             |
| `trending(period="7d")`                      | Trending actors         | `client.threat_actors.trending(period="7d")`         |
| `export(identifier)`                         | Full profile export     | `client.threat_actors.export("apt28-uuid")`          |
| `mentions(identifier)`                       | Source mentions         | `client.threat_actors.mentions("apt28-uuid")`        |
| `observables(identifier)`                    | Related IOCs            | `client.threat_actors.observables("apt28-uuid")`     |
| `attack_patterns(identifier)`                | MITRE ATT&CK techniques | `client.threat_actors.attack_patterns("apt28-uuid")` |
| `enrich(identifier)`                         | AI enrichment           | `client.threat_actors.enrich("apt28-uuid")`          |

### Malware — `client.malware`

| Method                                       | Description               | Example                                         |
| -------------------------------------------- | ------------------------- | ----------------------------------------------- |
| `list(limit, offset, sort, order, **kwargs)` | List malware              | `client.malware.list(limit=10)`                 |
| `get(identifier)`                            | Get by name or UUID       | `client.malware.get("emotet-uuid")`             |
| `trending(period="7d")`                      | Trending malware          | `client.malware.trending()`                     |
| `export(identifier)`                         | Full profile export       | `client.malware.export("emotet-uuid")`          |
| `mentions(identifier)`                       | Source mentions           | `client.malware.mentions("emotet-uuid")`        |
| `observables(identifier)`                    | Related IOCs              | `client.malware.observables("emotet-uuid")`     |
| `vulnerabilities(identifier)`                | Exploited vulnerabilities | `client.malware.vulnerabilities("emotet-uuid")` |
| `attack_patterns(identifier)`                | MITRE ATT&CK techniques   | `client.malware.attack_patterns("emotet-uuid")` |
| `enrich(identifier)`                         | AI enrichment             | `client.malware.enrich("emotet-uuid")`          |

### Exploits — `client.exploits`

| Method                                       | Description             | Example                                           |
| -------------------------------------------- | ----------------------- | ------------------------------------------------- |
| `list(limit, offset, sort, order, **kwargs)` | List exploits           | `client.exploits.list(limit=10)`                  |
| `get(identifier)`                            | Get exploit details     | `client.exploits.get("exploit-uuid")`             |
| `export(identifier)`                         | Full profile export     | `client.exploits.export("exploit-uuid")`          |
| `vulnerabilities(identifier)`                | Related vulnerabilities | `client.exploits.vulnerabilities("exploit-uuid")` |
| `enrich(identifier)`                         | AI enrichment           | `client.exploits.enrich("exploit-uuid")`          |

### Exploitations — `client.exploitations`

| Method                                       | Description              | Example                                         |
| -------------------------------------------- | ------------------------ | ----------------------------------------------- |
| `list(limit, offset, sort, order, **kwargs)` | List exploitation events | `client.exploitations.list(limit=10)`           |
| `get(identifier)`                            | Get exploitation details | `client.exploitations.get("exploitation-uuid")` |

### Organizations — `client.organizations`

| Method                                       | Description            | Example                                     |
| -------------------------------------------- | ---------------------- | ------------------------------------------- |
| `list(limit, offset, sort, order, **kwargs)` | List organizations     | `client.organizations.list(limit=10)`       |
| `get(identifier)`                            | Get org details        | `client.organizations.get("org-uuid")`      |
| `trending(period="7d")`                      | Trending organizations | `client.organizations.trending()`           |
| `export(identifier)`                         | Full profile export    | `client.organizations.export("org-uuid")`   |
| `mentions(identifier)`                       | Source mentions        | `client.organizations.mentions("org-uuid")` |
| `products(identifier)`                       | Associated products    | `client.organizations.products("org-uuid")` |
| `breaches(identifier)`                       | Associated breaches    | `client.organizations.breaches("org-uuid")` |
| `enrich(identifier)`                         | AI enrichment          | `client.organizations.enrich("org-uuid")`   |

### Products — `client.products`

| Method                                       | Description         | Example                                      |
| -------------------------------------------- | ------------------- | -------------------------------------------- |
| `list(limit, offset, sort, order, **kwargs)` | List products       | `client.products.list(limit=10)`             |
| `get(identifier)`                            | Get product details | `client.products.get("product-uuid")`        |
| `trending(period="7d")`                      | Trending products   | `client.products.trending()`                 |
| `search(query)`                              | Search products     | `client.products.search({"q": "apache"})`    |
| `export(identifier)`                         | Full profile export | `client.products.export("product-uuid")`     |
| `advisories(identifier)`                     | Vendor advisories   | `client.products.advisories("product-uuid")` |
| `mentions(identifier)`                       | Source mentions     | `client.products.mentions("product-uuid")`   |
| `enrich(identifier)`                         | AI enrichment       | `client.products.enrich("product-uuid")`     |

### Attack Patterns — `client.attack_patterns`

| Method                                       | Description          | Example                                         |
| -------------------------------------------- | -------------------- | ----------------------------------------------- |
| `list(limit, offset, sort, order, **kwargs)` | List ATT&CK patterns | `client.attack_patterns.list(limit=10)`         |
| `get(identifier)`                            | Get pattern details  | `client.attack_patterns.get("T1566")`           |
| `trending(period="7d")`                      | Trending patterns    | `client.attack_patterns.trending()`             |
| `mentions(identifier)`                       | Source mentions      | `client.attack_patterns.mentions("T1566")`      |
| `threat_actors(identifier)`                  | Actors using this    | `client.attack_patterns.threat_actors("T1566")` |
| `malware(identifier)`                        | Malware using this   | `client.attack_patterns.malware("T1566")`       |

### Breaches — `client.breaches`

| Method                                       | Description        | Example                                        |
| -------------------------------------------- | ------------------ | ---------------------------------------------- |
| `list(limit, offset, sort, order, **kwargs)` | List breaches      | `client.breaches.list(limit=10)`               |
| `get(identifier)`                            | Get breach details | `client.breaches.get("breach-uuid")`           |
| `organizations(identifier)`                  | Affected orgs      | `client.breaches.organizations("breach-uuid")` |

### Detection Signatures — `client.detection_signatures`

| Method                                       | Description           | Example                                       |
| -------------------------------------------- | --------------------- | --------------------------------------------- |
| `list(limit, offset, sort, order, **kwargs)` | List detection rules  | `client.detection_signatures.list(limit=10)`  |
| `get(identifier)`                            | Get signature details | `client.detection_signatures.get("sig-uuid")` |

### Advisories — `client.advisories`

| Method                                       | Description          | Example                                              |
| -------------------------------------------- | -------------------- | ---------------------------------------------------- |
| `list(limit, offset, sort, order, **kwargs)` | List advisories      | `client.advisories.list(limit=10)`                   |
| `get(identifier)`                            | Get advisory details | `client.advisories.get("advisory-uuid")`             |
| `export(identifier)`                         | Full profile export  | `client.advisories.export("advisory-uuid")`          |
| `products(identifier)`                       | Affected products    | `client.advisories.products("advisory-uuid")`        |
| `vulnerabilities(identifier)`                | Related vulns        | `client.advisories.vulnerabilities("advisory-uuid")` |

### Weaknesses — `client.weaknesses`

| Method                                       | Description            | Example                            |
| -------------------------------------------- | ---------------------- | ---------------------------------- |
| `list(limit, offset, sort, order, **kwargs)` | List weaknesses (CWEs) | `client.weaknesses.list(limit=10)` |
| `get(identifier)`                            | Get weakness details   | `client.weaknesses.get("CWE-79")`  |

## Content

### Stories — `client.stories`

| Method                                       | Description               | Example                                   |
| -------------------------------------------- | ------------------------- | ----------------------------------------- |
| `list(limit, offset, sort, order, **kwargs)` | List intelligence stories | `client.stories.list(limit=10)`           |
| `get(identifier)`                            | Get story details         | `client.stories.get("story-uuid")`        |
| `topics()`                                   | List story topics         | `client.stories.topics()`                 |
| `references(identifier)`                     | Source references         | `client.stories.references("story-uuid")` |
| `events(identifier)`                         | Timeline events           | `client.stories.events("story-uuid")`     |
| `similar(identifier)`                        | Similar stories           | `client.stories.similar("story-uuid")`    |
| `entities(identifier)`                       | Extracted entities        | `client.stories.entities("story-uuid")`   |
| `export(identifier)`                         | Full story export         | `client.stories.export("story-uuid")`     |

### References — `client.references`

| Method                                       | Description           | Example                                                      |
| -------------------------------------------- | --------------------- | ------------------------------------------------------------ |
| `list(limit, offset, sort, order, **kwargs)` | List references       | `client.references.list(limit=10)`                           |
| `get(identifier)`                            | Get reference details | `client.references.get("ref-uuid")`                          |
| `create(urls)`                               | Ingest new URLs       | `client.references.create(["https://example.com/advisory"])` |
| `labels()`                                   | List reference labels | `client.references.labels()`                                 |
| `entities(identifier)`                       | Extracted entities    | `client.references.entities("ref-uuid")`                     |
| `threat_actors(identifier)`                  | Mentioned actors      | `client.references.threat_actors("ref-uuid")`                |
| `vulnerabilities(identifier)`                | Mentioned vulns       | `client.references.vulnerabilities("ref-uuid")`              |

### Sources — `client.sources`

| Method                | Description        | Example                                          |
| --------------------- | ------------------ | ------------------------------------------------ |
| `list(limit, offset)` | List intel sources | `client.sources.list(limit=10)`                  |
| `statistics(source)`  | Source stats       | `client.sources.statistics("bleeping_computer")` |

### Content Chunks — `client.content_chunks`

| Method                   | Description         | Example                                        |
| ------------------------ | ------------------- | ---------------------------------------------- |
| `list(limit, offset)`    | List content chunks | `client.content_chunks.list(limit=10)`         |
| `get(identifier)`        | Get chunk details   | `client.content_chunks.get("chunk-uuid")`      |
| `search(q="ransomware")` | Semantic search     | `client.content_chunks.search(q="ransomware")` |

## Analytics

### Mentions — `client.mentions`

| Method                           | Description          | Example                             |
| -------------------------------- | -------------------- | ----------------------------------- |
| `list(limit, offset)`            | List all mentions    | `client.mentions.list(limit=10)`    |
| `actors(limit, offset)`          | Actor mention trends | `client.mentions.actors()`          |
| `vulnerabilities(limit, offset)` | Vuln mention trends  | `client.mentions.vulnerabilities()` |

### Search — `client.search`

| Method                      | Description      | Example                                                |
| --------------------------- | ---------------- | ------------------------------------------------------ |
| `query(q, types, **kwargs)` | Full-text search | `client.search.query(q="APT28", types="threat_actor")` |

## Pagination

All `list` methods return a `PaginatedResponse`:

```python
page = client.vulnerabilities.list(offset=0, limit=50)
print(f"Showing {len(page)} of {page.total}")
print(f"Has more: {page.has_more}")

# Access items
for item in page:
    print(item["cve_id"])
```

Auto-paginate:

```python
from malloryapi import paginate_sync

for vuln in paginate_sync(client.vulnerabilities.list, limit=100):
    print(vuln["cve_id"])
```

## Async Usage

```python
from malloryapi import AsyncMalloryApi

async with AsyncMalloryApi() as client:
    vulns = await client.vulnerabilities.list(limit=10)
    actor = await client.threat_actors.get("apt28-uuid")
```

Auto-paginate (async):

```python
from malloryapi import paginate_async

async for vuln in paginate_async(client.vulnerabilities.list):
    print(vuln["cve_id"])
```

## Error Handling

```python
from malloryapi import (
    APIError,            # Base exception
    AuthenticationError, # 401/403
    NotFoundError,       # 404
    ValidationError,     # 422
    RateLimitError,      # 429
)

try:
    vuln = client.vulnerabilities.get("CVE-9999-0000")
except NotFoundError:
    print("Not found")
except AuthenticationError:
    print("Bad API key")
except APIError as e:
    print(f"API error {e.status_code}: {e.response_body}")
```

## Trending Periods

Entities with trending support accept `period`:

- `"1d"` — last 24 hours
- `"7d"` — last 7 days (default)
- `"30d"` — last 30 days

```python
client.vulnerabilities.trending(period="30d")
client.threat_actors.trending(period="1d")
client.malware.trending(period="7d")
```
