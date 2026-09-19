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

## Workspace-aware briefing (malloryapi 0.4.0)

For "what changed for us?", read [runtime](../../references/runtime.md) and
[output contract](../../references/output-contract.md). Use the SDK-backed
collector below; the older `briefing.py` remains available for topic/industry/
geography intelligence reports.

Confirm the workspace UUID and a durable state-file location, then run:

```bash
python "$PLUGIN_ROOT/skills/daily-briefing/scripts/workspace_briefing.py" \
  --workspace "$WORKSPACE_UUID" --state output/workspace-briefing-state.json \
  --output-prefix output/daily-briefing
```

`PLUGIN_ROOT` is the resolved installed plugin path, not a guessed cwd. The
collector writes HTML, Markdown and JSON; it makes no finding writes, schedules,
or deliveries. Return its verified file paths and concise highlights. Exit 2
means useful partial output; inspect coverage rather than treating it as empty.

Sections are always present: new findings, newly asset-matched stories, newly
exploited asset-matched vulnerabilities, and up to five recent workspace stories.
Stories use workspace followed entities/topics/sources; findings and vulnerability
matches are explicitly **tenant-wide** because those APIs have no workspace
filter. Do not represent them as workspace-only. Rank stories by asset-match
count then freshness; further editorial analysis may explain their relevance
without changing evidence or pretending the selection was exhaustive.

The collector uses `first_exploitation_at` and positive matched-asset count for
vulnerabilities. Newly matched stories compare the complete current matched-ID
set to the previous successful baseline, including older stories; freshness is
not match recency. First run records a baseline with no newly-matched callout.
Each time-filtered section keeps its own checkpoint; failed sections retain
previous state. An unsuccessful first matching read does not create a baseline.
State is validated against authenticated tenant/workspace and written atomically
after artifacts. Never share state files across tenants, workspaces or API
environments. Do not run two collectors concurrently against one state file.

An old fixed-window failure remains a gap until a successful later read covers
it. The report records each section's absolute window. This collector's state
tracks successful **reads**, not delivery: if later delivery fails, retain and
retry the saved artifact with the host, not a fresh collection that would lose
the prior digest. Email/Slack/other delivery requires the user's explicit request
and an available host tool. Verify the receipt; don't auto-resend uncertain sends.
