# compromised-package-scan — Reference

## Command reference

`scan.py` (`scripts/scan.py`) has four subcommands.

### `compromised`
Pull the latest compromised packages from Mallory and enrich each with its compromised versions.

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--limit` | `100` | Number of most-recently-compromised packages to fetch. |
| `--ecosystem` | — | Restrict to one ecosystem (`npm`, `pypi`, `gem`, `golang`, ...). |
| `--workers` | `8` | Concurrency for per-package `compromises` lookups. |
| `-o, --output-file` | stdout | Write JSON feed to a file. |

Implementation: lists packages with `sort=last_compromised_at&order=desc`, paging until `--limit`
packages with a non-null `last_compromised_at` are collected (packages with no compromise sort
last, so paging stops there). Then calls `packages.compromises(uuid)` per package in a thread pool.

### `sbom`
Pull and pre-process GitHub SBOM(s) into a normalized package list.

| Argument / flag | Description |
| --------------- | ----------- |
| `repos...` | One or more `owner/repo`; each pulled via `gh api repos/<repo>/dependency-graph/sbom`. |
| `--sbom-file` | Local SPDX JSON file(s) (repeatable). Accepts raw GitHub SBOM (`{"sbom": {...}}`) or bare SPDX. |
| `-o, --output-file` | Write JSON to a file. |

### `crossref`
Join a compromised feed against pre-processed SBOM(s).

| Flag | Description |
| ---- | ----------- |
| `--feed` | Feed JSON from `compromised` (required). |
| `--sbom` | Pre-processed SBOM JSON from `sbom` (required, repeatable). |
| `--output` | `json` (default) or `table`. |

### `run`
End-to-end `compromised` → `sbom` → `crossref`. Same flags as `compromised` plus `repos...` /
`--sbom-file`, and `--output json|table` (defaults to `table`).

## Data model

### Compromised feed (`compromised` output)
```jsonc
{
  "count": 100,
  "limit": 100,
  "packages": [
    {
      "uuid": "019e8f87-...",
      "name": "rstreams-metrics",
      "ecosystem": "npm",
      "last_compromised_at": "2026-06-25T13:10:15Z",
      "compromise_evidence_count": 3,
      "compromised_versions": ["2.0.2"],
      "compromise_types": ["account_takeover"],
      "sources": ["cyber_security_news", "ox_security_blog"]
    }
  ]
}
```

### Pre-processed SBOM (`sbom` output)
```jsonc
{
  "source": "owner/repo",
  "count": 54,
  "packages": [
    { "ecosystem": "npm", "name": "axios", "version": "^1.6.0", "pinned": false,
      "purl": "pkg:npm/axios@%5E1.6.0" }
  ]
}
```
- `pinned` is `false` for ranges (`^`, `~`, `>=`, `*`, `||`, ` - `, `x`) — these can't produce a
  `CONFIRMED` match.
- `version` falls back to SPDX `versionInfo` when the PURL has no `@version`.

### Cross-reference report (`crossref` / `run` output)
```jsonc
{
  "feed_packages": 100,
  "sbom_sources": ["owner/repo"],
  "summary": { "confirmed": 1, "review": 2 },
  "findings": [
    {
      "status": "CONFIRMED",            // or "REVIEW"
      "sbom_source": "owner/repo",
      "ecosystem": "npm",
      "name": "rstreams-metrics",
      "sbom_version": "2.0.2",
      "pinned": true,
      "compromised_versions": ["2.0.2"],
      "compromise_types": ["account_takeover"],
      "last_compromised_at": "2026-06-25T13:10:15Z",
      "sources": ["cyber_security_news"],
      "package_uuid": "019e8f87-..."
    }
  ]
}
```

## Matching rules

- Join key: `(normalized ecosystem, lowercased name)`.
- `CONFIRMED`: SBOM version is `pinned` **and** (after stripping a leading `v`/`=`) equals one of
  the package's `compromised_versions`.
- `REVIEW`: name + ecosystem match but the above isn't satisfied (range version, version mismatch,
  or the package has no specific compromised version recorded).

## Ecosystem normalization

PURL type → Mallory ecosystem: `go`→`golang`, `rubygems`→`gem`; `npm`, `pypi`, `gem`, `golang`,
`cargo`, `maven`, `composer`, `nuget` pass through. Unknown types pass through unchanged.

## Underlying Mallory API

- `GET /v1/packages?sort=last_compromised_at&order=desc` — packages by most recent compromise.
- `GET /v1/packages/{uuid}/compromises` — `compromised_versions`, `compromise_type`, `source`,
  `reported_at` per evidence record.

See the **mallory-api** skill for SDK setup, auth, and the full resource reference.
