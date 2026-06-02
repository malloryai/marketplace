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
| `malware(identifier)`                        | Associated malware       | `client.vulnerabilities.malware("CVE-2024-1234")`              |
| `threat_actors(identifier)`                  | Actors exploiting this   | `client.vulnerabilities.threat_actors("CVE-2024-1234")`        |
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
| `exploitations(identifier)`                  | Exploitation activity   | `client.threat_actors.exploitations("apt28-uuid")`   |
| `malware(identifier)`                        | Associated malware      | `client.threat_actors.malware("apt28-uuid")`         |
| `source_geographies(identifier)`             | Attributed origin geos  | `client.threat_actors.source_geographies("apt28-uuid")` |
| `target_geographies(identifier)`             | Targeted geographies    | `client.threat_actors.target_geographies("apt28-uuid")` |
| `target_industries(identifier)`              | Targeted industries     | `client.threat_actors.target_industries("apt28-uuid")` |
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
| `threat_actors(identifier)`                  | Attributed actors  | `client.breaches.threat_actors("breach-uuid")` |
| `malware(identifier)`                        | Malware involved   | `client.breaches.malware("breach-uuid")`       |
| `attack_patterns(identifier)`                | ATT&CK techniques  | `client.breaches.attack_patterns("breach-uuid")` |
| `mentions(identifier)`                       | Source mentions    | `client.breaches.mentions("breach-uuid")`      |
| `export(identifier)`                         | Full breach export | `client.breaches.export("breach-uuid")`        |

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

### Observables (IOCs) — `client.observables`

Indicators of compromise (IPs, domains, hashes, URLs). The `type/name` accessors let you look up an IOC without knowing its UUID.

| Method                                       | Description                       | Example                                                            |
| -------------------------------------------- | --------------------------------- | ------------------------------------------------------------------ |
| `list(offset, limit, sort, order, filter, scope, **kwargs)` | List observables   | `client.observables.list(limit=50)`                                |
| `create(data)`                               | Create an observable              | `client.observables.create({"type": "ipv4", "name": "1.2.3.4"})`   |
| `get(uuid)`                                  | Get observable by UUID            | `client.observables.get("obs-uuid")`                               |
| `get_by_type_name(observable_type, name)`    | Look up IOC by type and value     | `client.observables.get_by_type_name("domain", "evil.com")`        |
| `update(uuid, data)`                         | Update an observable              | `client.observables.update("obs-uuid", {"description": "C2"})`     |
| `delete(uuid)`                               | Delete an observable              | `client.observables.delete("obs-uuid")`                            |
| `opinions(uuid)`                             | Opinions/verdicts for an IOC      | `client.observables.opinions("obs-uuid")`                          |
| `opinions_by_type_name(observable_type, name)` | Opinions by IOC type and value  | `client.observables.opinions_by_type_name("ipv4", "1.2.3.4")`      |

### Opinions — `client.opinions`

Verdicts/assessments (e.g. malicious, benign) about observables, from sources or analysts.

| Method                                       | Description                  | Example                                                       |
| -------------------------------------------- | ---------------------------- | ------------------------------------------------------------- |
| `list(offset, limit, sort, order, filter, scope, **kwargs)` | List opinions | `client.opinions.list(limit=50)`                              |
| `create(data)`                               | Create an opinion            | `client.opinions.create({"observable_uuid": "...", "verdict": "malicious"})` |
| `get(uuid)`                                  | Get opinion by UUID          | `client.opinions.get("opinion-uuid")`                         |
| `update(uuid, data)`                         | Update an opinion            | `client.opinions.update("opinion-uuid", {"verdict": "benign"})` |
| `delete(uuid)`                               | Delete an opinion            | `client.opinions.delete("opinion-uuid")`                      |
| `grouped(type, verdict, source, observable_name, ...)` | Opinions grouped by observable | `client.opinions.grouped(verdict="malicious")`         |

### Vulnerable Configurations — `client.vulnerable_configurations`

CPE-style configuration sets describing which technology product versions are affected by a vulnerability.

| Method                                       | Description                          | Example                                                             |
| -------------------------------------------- | ------------------------------------ | ------------------------------------------------------------------- |
| `list(offset, limit, sort, order, filter, **kwargs)` | List configuration sets      | `client.vulnerable_configurations.list(limit=20)`                   |
| `get(identifier)`                            | Get a configuration set              | `client.vulnerable_configurations.get("config-uuid")`               |
| `by_configuration(configuration_uuid)`       | Sets for a product configuration     | `client.vulnerable_configurations.by_configuration("cfg-uuid")`     |
| `by_vulnerability(vulnerability_uuid)`       | Sets affected by a vulnerability     | `client.vulnerable_configurations.by_vulnerability("vuln-uuid")`    |
| `search(query)`                              | Search configuration sets            | `client.vulnerable_configurations.search({"product": "apache"})`    |

### Packages — `client.packages`

Software packages (e.g. from package registries) tracked for compromises and malicious versions.

| Method                                       | Description                       | Example                                       |
| -------------------------------------------- | --------------------------------- | --------------------------------------------- |
| `list(filter, offset, limit, sort, order, include_merged, **kwargs)` | List packages | `client.packages.list(limit=20)`              |
| `get(identifier)`                            | Get package details               | `client.packages.get("package-uuid")`         |
| `compromises(identifier)`                    | Known compromised versions        | `client.packages.compromises("package-uuid")` |
| `configurations(identifier)`                 | Affected configurations           | `client.packages.configurations("package-uuid")` |
| `mentions(identifier)`                       | Source mentions                   | `client.packages.mentions("package-uuid")`    |

### Industries — `client.industries`

Industry sector taxonomy (e.g. for actor targeting analysis).

| Method        | Description           | Example                              |
| ------------- | --------------------- | ------------------------------------ |
| `list()`      | List all industries   | `client.industries.list()`           |
| `get(code)`   | Get industry by code  | `client.industries.get("finance")`   |

### Geographies — `client.geographies`

Geographic region/country taxonomy.

| Method        | Description            | Example                          |
| ------------- | ---------------------- | -------------------------------- |
| `list()`      | List all geographies   | `client.geographies.list()`      |
| `get(code)`   | Get geography by code  | `client.geographies.get("US")`   |

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
| `citations(identifier)`                      | Story citations           | `client.stories.citations("story-uuid")`  |
| `observables(identifier)`                    | Related IOCs              | `client.stories.observables("story-uuid")` |
| `timeline(identifier)`                       | Story timeline            | `client.stories.timeline("story-uuid")`   |
| `exposure(identifier)`                       | Your org's exposure       | `client.stories.exposure("story-uuid")`   |
| `topics_taxonomy()`                          | Story topic taxonomy      | `client.stories.topics_taxonomy()`        |
| `update(identifier, title, description)`     | Update a story            | `client.stories.update("story-uuid", title="New title")` |
| `delete(identifier)`                         | Delete a story            | `client.stories.delete("story-uuid")`     |
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

## Asset Exposure & Inventory

### Assets — `client.assets`

Your organization's attack surface. Exposure/presence checks tell you whether your inventory is impacted by a specific threat (CVE, actor, malware, IOC). Inventory accessors enumerate uploaded asset data.

| Method                                       | Description                                   | Example                                                              |
| -------------------------------------------- | --------------------------------------------- | -------------------------------------------------------------------- |
| `exposure_check(data)`                       | Check if your org is exposed to a threat      | `client.assets.exposure_check({"vulnerability": "CVE-2024-1234"})`   |
| `presence_check(data)`                       | Check if assets/IOCs are present in inventory | `client.assets.presence_check({"observables": ["1.2.3.4"]})`         |
| `inventory_hosts(offset, limit, **kwargs)`   | Host inventory                                | `client.assets.inventory_hosts(limit=50)`                            |
| `inventory_software(offset, limit, **kwargs)`| Software/package inventory                    | `client.assets.inventory_software()`                                 |
| `inventory_users(offset, limit, **kwargs)`   | User inventory                                | `client.assets.inventory_users()`                                    |
| `inventory_repositories(offset, limit, **kwargs)` | Code repository inventory                | `client.assets.inventory_repositories()`                             |
| `inventory_cloud_resources(offset, limit, **kwargs)` | Cloud resource inventory             | `client.assets.inventory_cloud_resources()`                          |
| `inventory_vulnerability_instances(offset, limit, **kwargs)` | Vulnerability instances on assets | `client.assets.inventory_vulnerability_instances()`            |
| `profile()`                                  | Tenant asset-exposure profile                 | `client.assets.profile()`                                            |
| `profile_for(entity_type)`                   | Profile for an entity type                    | `client.assets.profile_for("host")`                                  |
| `vulnerabilities(vulnerability_uuid, status, asset_type, asset_uuid, ...)` | Vulnerabilities across your assets | `client.assets.vulnerabilities(status="open")`         |
| `upload(data)`                               | Upload tenant asset data                      | `client.assets.upload({"data_type": "hosts", "rows": [...]})`        |
| `uploads(status, data_type, offset, limit, ...)` | List prior uploads                        | `client.assets.uploads(status="completed")`                         |
| `upload_status(upload_uuid)`                 | Get an upload's processing status             | `client.assets.upload_status("upload-uuid")`                         |
| `upload_retry(upload_uuid)`                  | Retry a held/failed upload                    | `client.assets.upload_retry("upload-uuid")`                          |

## Account & Workspaces

### User — `client.user`

| Method   | Description                          | Example              |
| -------- | ------------------------------------ | -------------------- |
| `me()`   | Current authenticated user info      | `client.user.me()`   |

### Tenants — `client.tenants`

| Method                                | Description           | Example                                  |
| ------------------------------------- | --------------------- | ---------------------------------------- |
| `list(offset, limit)`                 | List tenants          | `client.tenants.list()`                  |
| `users(tenant_uuid, offset, limit)`   | List users in tenant  | `client.tenants.users("tenant-uuid")`    |

### Workspaces — `client.workspaces`

Collections that scope entities, topics, and sources to a team, with member management.

| Method                                       | Description                       | Example                                                            |
| -------------------------------------------- | --------------------------------- | ------------------------------------------------------------------ |
| `list(offset, limit, sort, order, filter, **kwargs)` | List workspaces           | `client.workspaces.list(limit=20)`                                 |
| `create(data)`                               | Create a workspace                | `client.workspaces.create({"name": "Energy Sector"})`             |
| `get(uuid)`                                  | Get workspace details             | `client.workspaces.get("ws-uuid")`                                 |
| `update(uuid, data)`                         | Update a workspace                | `client.workspaces.update("ws-uuid", {"name": "Renamed"})`        |
| `delete(uuid)`                               | Delete a workspace                | `client.workspaces.delete("ws-uuid")`                              |
| `entities(uuid, entity_type, ...)`           | List workspace entities           | `client.workspaces.entities("ws-uuid")`                            |
| `add_entities(uuid, data)`                   | Add entities to a workspace       | `client.workspaces.add_entities("ws-uuid", {"entities": [...]})`  |
| `remove_entity(uuid, entity_type, entity_uuid)` | Remove an entity               | `client.workspaces.remove_entity("ws-uuid", "actor", "a-uuid")`   |
| `add_topics(uuid, data)`                     | Add topics to a workspace         | `client.workspaces.add_topics("ws-uuid", {"topics": ["ransomware"]})` |
| `remove_topic(uuid, topic)`                  | Remove a topic                    | `client.workspaces.remove_topic("ws-uuid", "ransomware")`         |
| `sources(uuid)`                              | List workspace sources            | `client.workspaces.sources("ws-uuid")`                             |
| `add_sources(uuid, data)`                    | Add sources to a workspace        | `client.workspaces.add_sources("ws-uuid", {"sources": [...]})`    |
| `remove_source(uuid, source_uuid)`           | Remove a source                   | `client.workspaces.remove_source("ws-uuid", "src-uuid")`          |
| `members(uuid)`                              | List workspace members            | `client.workspaces.members("ws-uuid")`                             |
| `add_member(uuid, data)`                     | Add a member                      | `client.workspaces.add_member("ws-uuid", {"user_uuid": "..."})`   |
| `update_member(uuid, user_uuid, data)`       | Update a member's role            | `client.workspaces.update_member("ws-uuid", "u-uuid", {"role": "admin"})` |
| `remove_member(uuid, user_uuid)`             | Remove a member                   | `client.workspaces.remove_member("ws-uuid", "u-uuid")`            |

## Automation

### Integrations — `client.integrations`

Configured third-party integrations (e.g. SIEM, ticketing, enrichment connectors) and their actions.

| Method                                       | Description                          | Example                                                            |
| -------------------------------------------- | ------------------------------------ | ------------------------------------------------------------------ |
| `list(offset, limit, filter, **kwargs)`      | List integrations                    | `client.integrations.list()`                                       |
| `create(data)`                               | Create an integration                | `client.integrations.create({"type": "slack", "config": {...}})`  |
| `get(integration_uuid)`                      | Get integration details              | `client.integrations.get("int-uuid")`                              |
| `update(integration_uuid, data)`            | Update an integration                | `client.integrations.update("int-uuid", {"config": {...}})`       |
| `delete(integration_uuid, force=False)`     | Delete an integration                | `client.integrations.delete("int-uuid")`                           |
| `capabilities()`                             | Available integration capabilities   | `client.integrations.capabilities()`                               |
| `schemas()`                                  | Integration config schemas           | `client.integrations.schemas()`                                    |
| `run_action(integration_uuid, action, data)`| Execute an integration action        | `client.integrations.run_action("int-uuid", "notify", {"text": "Alert"})` |

### Schedules — `client.schedules`

Scheduled/recurring jobs (e.g. periodic exports or integration runs) and their execution history.

| Method                                       | Description                  | Example                                                       |
| -------------------------------------------- | ---------------------------- | ------------------------------------------------------------- |
| `list(offset, limit, filter, uuid, status, **kwargs)` | List schedules      | `client.schedules.list()`                                     |
| `create(data)`                               | Create a schedule            | `client.schedules.create({"name": "Daily export", "cron": "0 0 * * *", "action": "export"})` |
| `get(schedule_uuid)`                         | Get schedule details         | `client.schedules.get("sched-uuid")`                          |
| `update(schedule_uuid, data)`                | Update a schedule            | `client.schedules.update("sched-uuid", {"status": "paused"})` |
| `delete(schedule_uuid)`                      | Delete a schedule            | `client.schedules.delete("sched-uuid")`                       |
| `executions(schedule_uuid, offset, limit)`   | Execution history            | `client.schedules.executions("sched-uuid")`                   |

### Exports — `client.exports`

Bulk data export jobs and download URLs.

| Method               | Description                     | Example                            |
| -------------------- | ------------------------------- | ---------------------------------- |
| `list(**kwargs)`     | List exports                    | `client.exports.list()`            |
| `history(**kwargs)`  | Export run history              | `client.exports.history()`         |
| `latest(**kwargs)`   | Latest export download URL      | `client.exports.latest()`          |
| `get(uuid, **kwargs)`| Export download URL by UUID     | `client.exports.get("export-uuid")` |

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
