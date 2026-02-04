---
name: intel-feed-finder
version: 1.0.0
description: Discover RSS, Atom, and JSON feeds from any URL. Use when setting up threat intel sources or finding syndication feeds.
runtime: python
deps-group: intel-feed-finder
entrypoints:
  - scripts/rss_finder.py
---

# Intel Feed Finder

Discover RSS, Atom, and JSON feeds from any URL. This skill helps identify syndication feeds for threat intelligence sources, security blogs, vendor advisories, and other cybersecurity content.

## When to Use This Skill

Use this skill when:

- Given a URL and need to find its RSS/Atom feed
- Setting up a new threat intelligence source
- Looking for syndication feeds on security vendor sites
- Discovering all available feeds from a website

## Feed Discovery Methods

The script uses multiple techniques to find feeds:

1. **Direct URL check** - Tests if the URL itself is a feed
2. **HTML meta headers** - Parses `<link rel="alternate">` tags
3. **HTML link tags** - Finds links with feed MIME types
4. **HTML content links** - Scans `<a>` tags for feed-related URLs
5. **robots.txt analysis** - Looks for feed references
6. **sitemap.xml checking** - Extracts feed URLs from sitemaps
7. **Common path probing** - Tries well-known feed paths like `/feed`, `/rss`, `/atom.xml`

## Usage

### Install Dependencies

```bash
# From repo root
pdm install -G intel-feed-finder
```

### Find a Single Feed

```bash
# From repo root
pdm run python .claude/skills/intel-feed-finder/scripts/rss_finder.py https://example.com
```

Output:

```
https://example.com → https://example.com/feed.xml
```

### Find All Feeds

Use `-a` or `--all` to discover all feeds, not just the first one:

```bash
pdm run python .claude/skills/intel-feed-finder/scripts/rss_finder.py -a https://krebsonsecurity.com
```

Output:

```
https://krebsonsecurity.com:
  1. https://krebsonsecurity.com/feed/
     Type: rss, Method: html_link_alternate
     Title: Krebs on Security RSS Feed
```

### JSON Output

Use `--json` for machine-readable output:

```bash
pdm run python .claude/skills/intel-feed-finder/scripts/rss_finder.py --json -a https://example.com
```

Output:

```json
[
  {
    "url": "https://example.com",
    "feeds": [
      {
        "url": "https://example.com/feed/",
        "type": "rss",
        "title": "Example Feed",
        "method": "html_link_alternate"
      }
    ]
  }
]
```

### Check Multiple URLs

```bash
pdm run python .claude/skills/intel-feed-finder/scripts/rss_finder.py https://site1.com https://site2.com
```

### Check URLs from File

```bash
pdm run python .claude/skills/intel-feed-finder/scripts/rss_finder.py -f urls.txt
```

### Verbose Mode

Use `-v` or `--verbose` for debug output:

```bash
pdm run python .claude/skills/intel-feed-finder/scripts/rss_finder.py -v https://example.com
```

## CLI Options

| Option            | Description                               |
| ----------------- | ----------------------------------------- |
| `urls`            | One or more URLs to check                 |
| `-f`, `--file`    | Path to file with URLs (one per line)     |
| `-a`, `--all`     | Show all discovered feeds, not just first |
| `-v`, `--verbose` | Enable debug logging                      |
| `--json`          | Output results in JSON format             |

## Feed Types Detected

- **RSS 2.0** - Most common syndication format
- **Atom** - Alternative to RSS with better specification
- **JSON Feed** - Modern JSON-based feed format
- **RDF/XML** - Older RSS 1.0 format

## Common Feed Paths Checked

The script probes these common paths:

- `/feed`, `/rss`, `/atom`
- `/feed.xml`, `/rss.xml`, `/atom.xml`
- `/blog/feed`, `/blog/rss`
- `/news/feed`, `/news/rss`
- `/feed.json` (JSON Feed)
- And many more...

## Example: Finding Feeds for Security Sites

```bash
# Single site
pdm run python .claude/skills/intel-feed-finder/scripts/rss_finder.py -a https://www.bleepingcomputer.com

# Multiple security blogs
pdm run python .claude/skills/intel-feed-finder/scripts/rss_finder.py -a \
  https://krebsonsecurity.com \
  https://www.bleepingcomputer.com \
  https://thehackernews.com \
  https://www.darkreading.com
```

## Programmatic Usage

The script can be imported as a module:

```python
from scripts.rss_finder import find_all_feeds, find_rss_feed

# Find all feeds
feeds = find_all_feeds("https://example.com")
for feed in feeds:
    print(f"{feed['url']} ({feed['type']}) - {feed['method']}")

# Find best single feed
feed_url = find_rss_feed("https://example.com")
print(f"Best feed: {feed_url}")
```

## Output Format

Each discovered feed includes:

- `url` - The feed URL
- `type` - Feed format (rss, atom, json, xml, unknown)
- `title` - Feed title if available
- `method` - How the feed was discovered (e.g., `html_link_alternate`, `common_path_root`)
