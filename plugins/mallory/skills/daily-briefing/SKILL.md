---
name: daily-briefing
description: Generate a self-contained HTML threat-intelligence daily briefing filtered by topics, industry, and geography. Use when you need a shareable or emailable intel digest. Uses mallory-api for data.
allowed-tools: Bash(python *), Bash(uv *), Bash(pip *)
---

# Daily Threat Intelligence Briefing

Produce a single, dependency-free HTML briefing from the Mallory threat
intelligence API — intelligence stories plus trending vulnerabilities, actively
exploited CVEs, threat actors, and malware — scoped to the topics, industries,
and geographies you care about. The output is one self-contained `.html` file
you can open in a browser, attach to an email, or hand to a mail transport.

## Prerequisites

This skill uses the **mallory-api** skill's SDK. Install it and set your key:

```bash
uv pip install --system malloryapi
export MALLORY_API_KEY="your-api-key"   # get one at https://app.mallory.ai/api/keys
```

## Generate a briefing

```bash
python scripts/briefing.py \
  --topics ransomware,actively-exploited-vulnerability \
  --technologies cisco,fortinet,winrar \
  --industry financials \
  --geo US,UA \
  --days 1 \
  --period 7d \
  --output daily-briefing.html
```

The script writes the file and prints its path to stdout. Open it, or pass it to
an email step.

## Filters

| Flag             | Meaning                                                                                     |
| ---------------- | ------------------------------------------------------------------------------------------- |
| `--topics`       | Story topic slugs (comma-separated). Server-side filter on stories. **Primary filter.**     |
| `--technologies` | Vendor/product names (e.g. `cisco,fortinet,winrar`). Keyword-matched across **every** section's text (CVE titles/descriptions, story text, actor/malware names). Hard filter. Alias: `--tech`. |
| `--industry`     | GICS sector/industry names or codes. Structured filter on trending actors; keyword refine on stories. |
| `--geo`          | ISO country codes (e.g. `US,UA`). Structured filter on trending actors; keyword refine on stories. |
| `--days`         | Story freshness window in days (default `1`).                                                |
| `--period`   | Trending window: `1d` / `7d` / `30d` (default `7d`).                                         |
| `--limit`    | Max items per section (default `8`).                                                         |
| `--title`    | Briefing headline.                                                                           |
| `--output`   | Output HTML path (default `daily-briefing.html`).                                            |

Section toggles: `--no-stories`, `--no-vulns`, `--no-exploited`, `--no-actors`, `--no-malware`.

### Technology spotlight

When `--technologies` is set, the briefing opens with a **Spotlight** block that
pins the highest-priority matches to the top of the page. It is diversity-first
— the top item from each category (exploited → vulnerability → story → actor →
malware), then remaining slots filled by urgency — so it summarizes rather than
duplicates the sections below. Exploited / CISA KEV items are flagged in red.
Control its size with `--spotlight N` (default `6`; `--spotlight 0` disables it).

### Discovering filter values

```bash
# Topic slugs (use these with --topics)
malloryapi stories topics

# GICS industry taxonomy (codes + names for --industry)
malloryapi industries list
```

Geographies are matched as **ISO country codes** (the Mallory geography taxonomy
endpoint is currently empty, so use codes like `US`, `UA`, `DE`).

## How filtering works

- **Topics** are the strongest filter: applied server-side on `stories.list`
  (one request per slug, merged and de-duplicated).
- **Technologies** are keyword-matched (case-insensitive) against each item's
  text — CVE id / description / generated name for vulnerabilities, title +
  description for stories, and name + description for actors and malware. Vendor
  and product names appear reliably in CVE descriptions, so this narrows vulns
  well (e.g. `fortinet` cuts ~100 trending vulns to the handful that are
  Fortinet). It is a hard filter: a section can legitimately come back empty.
  Matching is **word-boundary aware**, so short tokens don't match inside
  unrelated words (`aws` won't hit "flaws", `rds` won't hit Oracle "ords"),
  while distinctive short / dotted / spaced names still work (`s3`, `ec2`,
  `next.js`, `delta lake`). Boundaries can't disambiguate *whole-word* product
  collisions, though — `sentry` will still match "Ivanti Sentry", and common
  English words (`slack`, `resend`, `temporal`) match unrelated prose — so
  curate ambiguous terms out of the list rather than relying on the matcher.
- **Industry / geo** are applied as *structured* filters on trending threat
  actors via their `target_industries` (GICS) and `target_geographies` (country
  code) associations. Stories carry no structured industry/geo field, so for
  stories these terms act as a **best-effort keyword refine** over the title and
  description — and the refine is skipped if it would empty the result set.

## Emailing the briefing

The briefing is intentionally self-contained (inline CSS, no external assets),
so it embeds cleanly as an HTML email body or attachment. This skill only
**generates** the file. To send it, hand the output to whatever mail tool you
have available (an MCP email tool in-session, a local `sendmail`, or an SMTP
script) — for example, attach `daily-briefing.html` or inline its contents.
