# Mallory API Endpoint Reference

Quick reference for key endpoints. Full spec: `curl -s "https://api.mallory.ai/openapi.json" | jq`

Base URL: `https://api.mallory.ai`  
Auth: `Authorization: Bearer $MALLORY_API_KEY`

## User

| Method | Path       | Description       |
| ------ | ---------- | ----------------- |
| GET    | `/v1/user` | Current user info |

## Threat Actors

| Method | Path                                      | Description                     |
| ------ | ----------------------------------------- | ------------------------------- |
| GET    | `/v1/actors`                              | List actors (supports filters)  |
| GET    | `/v1/actors/{identifier}`                 | Actor details                   |
| GET    | `/v1/actors/{identifier}/attack_patterns` | MITRE ATT&CK techniques         |
| GET    | `/v1/actors/{identifier}/export`          | Full profile with relationships |
| GET    | `/v1/actors/trending/diff`                | Trending actors                 |

## Vulnerabilities

| Method | Path                                             | Description                                |
| ------ | ------------------------------------------------ | ------------------------------------------ |
| GET    | `/v1/vulnerabilities`                            | List vulnerabilities                       |
| GET    | `/v1/vulnerabilities/{identifier}`               | Vulnerability details (e.g. CVE-2024-1234) |
| GET    | `/v1/vulnerabilities/{identifier}/exploits`      | Known exploits                             |
| GET    | `/v1/vulnerabilities/{identifier}/exploitations` | Exploitation activity                      |
| GET    | `/v1/vulnerabilities/{identifier}/export`        | Full profile with relationships            |
| GET    | `/v1/vulnerabilities/trending/diff`              | Trending vulnerabilities                   |

## Exploits & Exploitations

| Method | Path                        | Description              |
| ------ | --------------------------- | ------------------------ |
| GET    | `/v1/exploits`              | List exploits            |
| GET    | `/v1/exploits/{identifier}` | Exploit details          |
| GET    | `/v1/exploitations`         | List exploitation events |

## Malware

| Method | Path                              | Description      |
| ------ | --------------------------------- | ---------------- |
| GET    | `/v1/malware`                     | List malware     |
| GET    | `/v1/malware/{identifier}`        | Malware details  |
| GET    | `/v1/malware/{identifier}/export` | Full profile     |
| GET    | `/v1/malware/trending/diff`       | Trending malware |

## Search

| Method | Path                        | Description                                                                        |
| ------ | --------------------------- | ---------------------------------------------------------------------------------- |
| GET    | `/v1/search`                | Full-text search. Params: `q`, `types` (e.g. threat_actor, vulnerability, malware) |
| GET    | `/v1/content_chunks/search` | Search content. Param: `q`                                                         |

## Products & Advisories

| Method | Path                                | Description              |
| ------ | ----------------------------------- | ------------------------ |
| GET    | `/v1/products`                      | List technology products |
| GET    | `/v1/products/search`               | Search products          |
| GET    | `/v1/technology_product_advisories` | List vendor advisories   |

## Observables & Detection

| Method | Path                       | Description               |
| ------ | -------------------------- | ------------------------- |
| GET    | `/v1/observables`          | List observables (IOCs)   |
| GET    | `/v1/detection_signatures` | List detection signatures |
| GET    | `/v1/opinions`             | List threat opinions      |

## Dashboards

| Method | Path                             | Description             |
| ------ | -------------------------------- | ----------------------- |
| GET    | `/v1/dashboards/current-events`  | Current threat events   |
| GET    | `/v1/dashboards/vulnerabilities` | Vulnerability dashboard |

## Example curl (all endpoints)

```bash
curl -s "https://api.mallory.ai/v1/actors" \
  -H "Authorization: Bearer $MALLORY_API_KEY" | jq
```

## Python client

```bash
python ${CLAUDE_PLUGIN_ROOT}/skills/mallory-api/scripts/client.py GET /v1/user
python ${CLAUDE_PLUGIN_ROOT}/skills/mallory-api/scripts/client.py GET /v1/vulnerabilities/CVE-2024-1234
```
