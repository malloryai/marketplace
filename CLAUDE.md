# AGENTS.md - Mallory Cybersecurity Intel Platform

## Overview

Mallory is a cybersecurity threat intelligence platform. This repository contains the OpenAPI specification and tooling for interacting with the Mallory API.

## API Reference

The full API specification is available in `openapi-public.json` (OpenAPI 3.1.0).

### Base URL

```
https://api.mallory.ai
```

### Authentication

Check if MALLORY_API_KEY is already set in the environment. If not, prompt the user for the key and set it in the .env (see envioronment setup below)

All API requests require Bearer token authentication. Include your API key in the `Authorization` header:

```
Authorization: Bearer <MALLORY_API_KEY>
```

### Environment Setup

1. Copy `.env.local.example` to `.env.local` (if starting fresh)
2. Set your `MALLORY_API_KEY` in `.env.local`

```bash
# .env.local
MALLORY_API_URL=https://api.mallory.ai
MALLORY_API_KEY=your_api_key_here
```

> **Note:** `.env.local` contains sensitive credentials and is git-ignored. Never commit API keys.

## API Endpoints

### Threat Intelligence

| Endpoint | Description |
|----------|-------------|
| `GET /v1/actors` | List threat actors |
| `GET /v1/actors/{identifier}` | Get threat actor details |
| `GET /v1/actors/trending/diff` | Get trending threat actors |
| `GET /v1/malware` | List malware |
| `GET /v1/malware/{identifier}` | Get malware details |
| `GET /v1/malware/trending/diff` | Get trending malware |

### Vulnerabilities

| Endpoint | Description |
|----------|-------------|
| `GET /v1/vulnerabilities` | List vulnerabilities |
| `GET /v1/vulnerabilities/{identifier}` | Get vulnerability details (e.g., CVE-2024-1234) |
| `GET /v1/vulnerabilities/trending/diff` | Get trending vulnerabilities |
| `GET /v1/vulnerabilities/{identifier}/exploits` | Get exploits for a vulnerability |
| `GET /v1/vulnerabilities/{identifier}/exploitations` | Get exploitation activity |
| `GET /v1/vulnerabilities/{identifier}/export` | Export complete vulnerability intel with all related entities (exploits, exploitations, mentions, detection signatures, vulnerable configurations, advisories) |

### Exploits & Exploitations

| Endpoint | Description |
|----------|-------------|
| `GET /v1/exploits` | List exploits |
| `GET /v1/exploits/{identifier}` | Get exploit details |
| `GET /v1/exploitations` | List exploitation events |

### Products & Advisories

| Endpoint | Description |
|----------|-------------|
| `GET /v1/products` | List technology products |
| `GET /v1/products/search` | Search products |
| `GET /v1/technology_product_advisories` | List vendor advisories |

### Intelligence Content

| Endpoint | Description |
|----------|-------------|
| `GET /v1/bulletins` | List intelligence bulletins |
| `GET /v1/stories` | List threat stories |
| `GET /v1/references` | List intelligence references |
| `GET /v1/content_chunks/search` | Search content |

### Observables & Detection

| Endpoint | Description |[]
|----------|-------------|
| `GET /v1/observables` | List observables (IOCs) |
| `GET /v1/detection_signatures` | List detection signatures |
| `GET /v1/opinions` | List threat opinions/assessments |

### Dashboards

| Endpoint | Description |
|----------|-------------|
| `GET /v1/dashboards/current-events` | Current threat events |
| `GET /v1/dashboards/vulnerabilities` | Vulnerability dashboard |

### Organizations & Workspaces

| Endpoint | Description |
|----------|-------------|
| `GET /v1/organizations` | List organizations |
| `GET /workspaces` | List workspaces |
| `GET /v1/user` | Get current user info |

## Example API Calls

### Quick Start (Shell)

The easiest way to make API calls is to load your environment and use curl:

```bash
# Load environment variables (do this once per shell session)
export MALLORY_API_KEY=$(grep "^MALLORY_API_KEY=" .env.local | cut -d'=' -f2 | tr -d '"')

# Verify it's set
echo "Key loaded: ${MALLORY_API_KEY:0:8}..."

# Now make API calls
curl -s "https://api.mallory.ai/v1/user" \
  -H "Authorization: Bearer $MALLORY_API_KEY" | python3 -m json.tool
```

### Using curl

```bash
# Get current user
curl -s "https://api.mallory.ai/v1/user" \
  -H "Authorization: Bearer $MALLORY_API_KEY"

# Get vulnerability details (e.g., CVE-2026-20805)
curl -s "https://api.mallory.ai/v1/vulnerabilities/CVE-2026-20805" \
  -H "Authorization: Bearer $MALLORY_API_KEY" | python3 -m json.tool

# List threat actors
curl -s "https://api.mallory.ai/v1/actors" \
  -H "Authorization: Bearer $MALLORY_API_KEY"

# Get trending vulnerabilities
curl -s "https://api.mallory.ai/v1/vulnerabilities/trending/diff" \
  -H "Authorization: Bearer $MALLORY_API_KEY"

# Search content for ransomware intel
curl -s "https://api.mallory.ai/v1/content_chunks/search?q=ransomware" \
  -H "Authorization: Bearer $MALLORY_API_KEY"

# Get exploits for a specific CVE
curl -s "https://api.mallory.ai/v1/vulnerabilities/CVE-2026-20805/exploits" \
  -H "Authorization: Bearer $MALLORY_API_KEY"
```

### Using Python

```python
import os
import requests

API_URL = os.getenv("MALLORY_API_URL", "https://api.mallory.ai")
API_KEY = os.getenv("MALLORY_API_KEY")

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# Get vulnerabilities
response = requests.get(f"{API_URL}/v1/vulnerabilities", headers=headers)
vulnerabilities = response.json()

# Get specific threat actor
response = requests.get(f"{API_URL}/v1/actors/APT29", headers=headers)
actor = response.json()
```

### Using JavaScript/TypeScript

```typescript
const API_URL = process.env.MALLORY_API_URL || "https://api.mallory.ai";
const API_KEY = process.env.MALLORY_API_KEY;

const headers = {
  "Authorization": `Bearer ${API_KEY}`,
  "Content-Type": "application/json"
};

// Fetch vulnerabilities
const response = await fetch(`${API_URL}/v1/vulnerabilities`, { headers });
const vulnerabilities = await response.json();
```

## Export Functionality

Many entities support export for integration with other security tools:

- `GET /v1/actors/{identifier}/export`
- `GET /v1/malware/{identifier}/export`
- `GET /v1/vulnerabilities/{identifier}/export`
- `GET /v1/exploits/{identifier}/export`
- `GET /v1/products/{identifier}/export`

## Integrations

The API supports configurable integrations:

| Endpoint | Description |
|----------|-------------|
| `GET /v1/integrations` | List configured integrations |
| `GET /v1/integrations/meta/capabilities` | Get integration capabilities |
| `GET /v1/integrations/meta/schemas` | Get integration schemas |
| `POST /v1/integrations/{uuid}/actions/{action}` | Execute integration action |

## Scheduled Tasks

| Endpoint | Description |
|----------|-------------|
| `GET /v1/schedules` | List scheduled tasks |
| `GET /v1/schedules/{uuid}/executions` | Get schedule execution history |

## Error Handling

The API returns standard HTTP status codes:

- `200` - Success
- `401` - Unauthorized (invalid or missing API key)
- `404` - Resource not found
- `422` - Validation error (check request parameters)
- `429` - Rate limited
- `500` - Server error

Validation errors return detailed information:

```json
{
  "detail": [
    {
      "loc": ["query", "param_name"],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```
