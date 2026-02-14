---
name: mallory-api
version: 1.0.0
description: Query the Mallory threat intelligence API for actors, vulnerabilities, exploits, and malware. Use when you need current threat intel data.
runtime: python
entrypoints:
  - scripts/client.py
---

# Mallory Threat Intelligence API

You are a threat intelligence analyst. You provide the latest information about threats, actors, tactics, techniques and procedures. You also provide information about vulnerabilities, exploits and malware.

## Base URL

```
https://api.mallory.ai
```

## Authentication

Check for an API key in the environment variable `MALLORY_API_KEY` or in the `.api_key` file in this skill directory.

For every request, load the api key first:

```bash
MALLORY_API_KEY="${MALLORY_API_KEY:-$(cat .api_key 2>/dev/null)}"
```

Then include the API key in the `Authorization` header:

```
Authorization: Bearer <MALLORY_API_KEY>
```

**Security:** Never expose the API key in output or logs.

## Tools

Use `curl` to make requests and `jq` to parse responses.

## API Discovery

Fetch the full OpenAPI spec on demand to discover all available endpoints, parameters, and response schemas:

```bash
curl -s "https://api.mallory.ai/openapi.json" | jq
```

Use this to look up exact query parameters, filter options, and response shapes before making API calls.

## Quick Reference

### Get Current User

```bash
curl -s "https://api.mallory.ai/v1/user" \
  -H "Authorization: Bearer $MALLORY_API_KEY"
```

### Get Vulnerability Details

```bash
curl -s "https://api.mallory.ai/v1/vulnerabilities/CVE-2024-1234" \
  -H "Authorization: Bearer $MALLORY_API_KEY" | jq
```

### List Threat Actors

```bash
curl -s "https://api.mallory.ai/v1/actors" \
  -H "Authorization: Bearer $MALLORY_API_KEY" | jq
```

### Get Trending Vulnerabilities

```bash
curl -s "https://api.mallory.ai/v1/vulnerabilities/trending/diff" \
  -H "Authorization: Bearer $MALLORY_API_KEY" | jq
```

### Search Content

```bash
curl -s "https://api.mallory.ai/v1/content_chunks/search?q=ransomware" \
  -H "Authorization: Bearer $MALLORY_API_KEY" | jq
```

### Get Exploits for a CVE

```bash
curl -s "https://api.mallory.ai/v1/vulnerabilities/CVE-2024-1234/exploits" \
  -H "Authorization: Bearer $MALLORY_API_KEY" | jq
```

## Python Client

A Python client is available in `scripts/client.py`:

```bash
# Install dependencies
pip install requests

# Run the client
python ${CLAUDE_PLUGIN_ROOT}/skills/mallory-api/scripts/client.py GET /v1/user
python ${CLAUDE_PLUGIN_ROOT}/skills/mallory-api/scripts/client.py GET /v1/vulnerabilities/CVE-2024-1234
```
