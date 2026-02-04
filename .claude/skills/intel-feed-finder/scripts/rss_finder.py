#!/usr/bin/env python3
"""
RSS Feed Finder - Advanced Web Content Discovery Edition

This script takes a URL and uses multiple modern techniques to discover RSS/Atom/JSON feeds:
1. HTML meta header parsing (<link rel="alternate">)
2. Common path checking
3. Robots.txt analysis
4. Sitemap.xml checking
5. JSON feed detection
6. HTML content link analysis
"""

import argparse
import logging
import sys
import urllib.parse
from typing import Optional, List, Dict, Tuple, Iterable
import concurrent.futures
import time
import random
import re
import json

try:
    import requests  # type: ignore
    from requests.exceptions import RequestException  # type: ignore
except Exception as e:  # pragma: no cover
    raise SystemExit(
        "Missing dependency 'requests'. Install with:\n"
        "  pip install requests beautifulsoup4 feedparser\n"
        f"Import error: {e}"
    )
try:
    import feedparser  # type: ignore

    _FEEDPARSER_AVAILABLE = True
except Exception:  # pragma: no cover
    feedparser = None
    _FEEDPARSER_AVAILABLE = False

try:
    from bs4 import BeautifulSoup, Comment  # type: ignore

    _BS4_AVAILABLE = True
except Exception:  # pragma: no cover
    BeautifulSoup = None
    Comment = None
    _BS4_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Network/request safety defaults (avoid hanging on slow sites)
# requests timeout supports either a float or (connect_timeout, read_timeout)
REQUEST_TIMEOUT: Tuple[float, float] = (3.05, 10.0)
ROBOTS_TIMEOUT: Tuple[float, float] = (2.0, 5.0)
SITEMAP_TIMEOUT: Tuple[float, float] = (2.0, 7.0)
MAX_REDIRECTS = 5

# Common paths where RSS feeds might be located (absolute paths from root)
COMMON_RSS_PATHS = [
    "",
    "/",
    "/feed",
    "/rss",
    "/atom",
    "/atom.xml",
    "/rss.xml",
    "/feed.xml",
    "/feeds/posts/default",
    "/feeds/all.atom.xml",
    "/index.xml",
    "/feed/",
    "/rss/",
    "/atom/",
    "/blog",
    "/blog/",
    "/blog/feed",
    "/blog/rss",
    "/blog/atom",
    "/blog/feed/",
    "/blog/rss/",
    "/blog/atom.xml",
    "/blog/index.xml",
    "/en/feed",
    "/en/rss",
    "/en-us/rss",
    "/en-us/feed",
    "/news/feed",
    "/news/rss",
    "/posts.xml",
    "/feed.json",  # JSON Feed support
    "/feeds.json",
    "/blog/feed.json",
]

# Common relative paths to try from any given base URL
RELATIVE_RSS_PATHS = [
    "",
    "feed",
    "rss",
    "atom",
    "atom.xml",
    "rss.xml",
    "feed.xml",
    "index.xml",
    "feed/",
    "rss/",
    "atom/",
    "feed.json",
    "feeds.json",
]

# Feed MIME types to look for in HTML link tags
FEED_MIME_TYPES = [
    "application/rss+xml",
    "application/atom+xml",
    "application/rdf+xml",
    "application/xml",
    "text/xml",
    "application/feed+json",  # JSON Feed
    "application/json",
]

# Common feed link patterns in HTML
FEED_LINK_PATTERNS = [
    r"(?i)rss",
    r"(?i)atom",
    r"(?i)feed",
    r"(?i)syndication",
    r"(?i)xml",
]

# Common section roots often used for blogs/research/news.
# Used to generate smarter candidate bases from deep article URLs.
COMMON_SECTION_PATHS = [
    "/blog/",
    "/news/",
    "/research/",
    "/insights/",
    "/articles/",
    "/threat-research/",
    "/threat-intelligence/",
    "/resources/",
]

# Cache results per domain (scheme+netloc) to speed up batches.
_DOMAIN_FEED_CACHE: dict[str, List[Dict[str, str]]] = {}


def get_session() -> requests.Session:
    """Create a configured requests session with appropriate headers."""
    session = requests.Session()
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        + "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": (
            "text/html,application/xhtml+xml,application/xml,"
            "application/json;q=0.9,image/webp,*/*;q=0.8"
        ),
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }
    session.headers.update(headers)
    session.max_redirects = MAX_REDIRECTS
    return session


def normalize_url(url: str) -> str:
    """Ensure URL has scheme."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _root_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _split_path(url: str) -> List[str]:
    parsed = urllib.parse.urlparse(url)
    # Keep path segments only; ignore empty segments
    return [seg for seg in parsed.path.split("/") if seg]


def _iter_parent_paths(url: str) -> Iterable[str]:
    """
    Yield URL candidates by walking up the path.
    Example: https://a/b/c -> https://a/b/c, https://a/b/, https://a/
    """
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    segments = _split_path(url)

    # Full path first
    if segments:
        yield base + "/" + "/".join(segments)
        # Parent dirs
        for i in range(len(segments) - 1, 0, -1):
            yield base + "/" + "/".join(segments[:i]) + "/"
    yield base + "/"


def _is_probable_feed_url(url: str) -> bool:
    lowered = url.lower()
    return any(k in lowered for k in ["rss", "atom", "feed", "index.xml", ".xml", ".json"])


def _parse_rel_tokens(rel_value: object) -> set[str]:
    """
    BeautifulSoup can return rel as list[str], str, or None.
    """
    if rel_value is None:
        return set()
    if isinstance(rel_value, list):
        return {str(x).strip().lower() for x in rel_value if str(x).strip()}
    return {tok.strip().lower() for tok in str(rel_value).split() if tok.strip()}


def _parse_http_link_header(link_header: str, base_url: str) -> List[Dict[str, str]]:
    """
    Parse RFC 5988 Link header entries for feed discovery.
    Very small, pragmatic parser (good enough for typical feed Link headers).
    """
    feeds: List[Dict[str, str]] = []
    if not link_header:
        return feeds

    # Split on commas that delimit links. This is not a perfect parser,
    # but works for typical <...>; param=... , <...>; param=... headers.
    parts = [p.strip() for p in link_header.split(",") if p.strip()]
    for part in parts:
        m = re.match(r'\s*<([^>]+)>\s*(;.*)?$', part)
        if not m:
            continue
        href = m.group(1).strip()
        params_str = m.group(2) or ""

        params: dict[str, str] = {}
        for pm in re.finditer(r';\s*([a-zA-Z0-9_-]+)\s*=\s*(".*?"|[^;]+)', params_str):
            key = pm.group(1).strip().lower()
            val = pm.group(2).strip().strip('"')
            params[key] = val

        rel_tokens = {tok.strip().lower() for tok in params.get("rel", "").split() if tok.strip()}
        link_type = params.get("type", "").lower()
        title = params.get("title", "")

        # Accept rel=alternate or rel=feed. rel=feed may omit type.
        if not (("alternate" in rel_tokens) or ("feed" in rel_tokens)):
            continue

        if link_type and not any(mt in link_type for mt in FEED_MIME_TYPES):
            continue

        absolute_url = urllib.parse.urljoin(base_url, href)
        feeds.append(
            {
                "url": absolute_url,
                "type": link_type or "unknown",
                "title": title,
                "method": "http_link_header",
            }
        )
    return feeds


def _extract_canonical_url(html_content: str, base_url: str) -> Optional[str]:
    try:
        if not _BS4_AVAILABLE or BeautifulSoup is None:
            return None
        soup = BeautifulSoup(html_content, "html.parser")

        # <link rel="canonical" href="...">
        link = soup.find("link", rel=lambda x: "canonical" in _parse_rel_tokens(x), href=True)
        if link and link.get("href"):
            return urllib.parse.urljoin(base_url, link["href"])

        # og:url fallback
        og = soup.find("meta", property="og:url", content=True)
        if og and og.get("content"):
            return urllib.parse.urljoin(base_url, og["content"])
    except Exception:
        return None
    return None


def _fetch_html(url: str) -> Tuple[Optional[str], Optional[str], dict[str, str]]:
    """
    Fetch HTML for a URL and return (final_url, html, headers).
    Uses timeouts and redirect limits.
    """
    try:
        session = get_session()
        resp = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        resp.raise_for_status()
        content_type = resp.headers.get("content-type", "").lower()
        if "html" not in content_type and "<html" not in resp.text.lower():
            # Still return text; some sites mislabel content-type
            pass
        return resp.url, resp.text, {k.lower(): v for k, v in resp.headers.items()}
    except Exception as e:
        logger.debug(f"Error fetching HTML from {url}: {e}")
        return None, None, {}


def _generate_candidate_bases(url: str, html_content: Optional[str]) -> List[str]:
    """
    Produce a prioritized list of pages to run feed discovery against.
    This is key for deep article URLs: we want /blog/, /news/, and root.
    """
    candidates: List[str] = []
    seen: set[str] = set()

    def add(u: str) -> None:
        u = u.rstrip("/") + "/"
        if u not in seen:
            seen.add(u)
            candidates.append(u)

    # Prefer canonical (if present), then walk up parents.
    canonical = None
    if html_content:
        canonical = _extract_canonical_url(html_content, url)
    if canonical:
        for p in _iter_parent_paths(canonical):
            add(p)
    for p in _iter_parent_paths(url):
        add(p)

    # Add common section roots if the URL path hints at them.
    root = _root_url(url)
    path_lower = urllib.parse.urlparse(url).path.lower()
    for section in COMMON_SECTION_PATHS:
        if section.strip("/").lower() in path_lower:
            add(urllib.parse.urljoin(root + "/", section))

    # Always ensure root exists.
    add(root + "/")
    return candidates


def is_valid_json_feed(content: str) -> bool:
    """Check if content is a valid JSON Feed."""
    try:
        data = json.loads(content)
        # JSON Feed must have version and items
        return (
            isinstance(data, dict)
            and data.get("version", "").startswith("https://jsonfeed.org/version/")
            and "items" in data
            and isinstance(data["items"], list)
        )
    except (json.JSONDecodeError, AttributeError):
        return False


def is_valid_feed(feed_url: str) -> Tuple[bool, Optional[str], int]:
    """
    Return (True, feed_type, entry_count) if the URL contains a valid RSS/Atom/JSON feed.
    feed_type can be 'rss', 'atom', 'json', or None
    """
    try:
        # Add a small random delay to avoid being too aggressive
        time.sleep(random.uniform(0.1, 0.3))

        session = get_session()
        response = session.get(feed_url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()

        content_type = response.headers.get("content-type", "").lower()

        # Check for JSON Feed first
        if "json" in content_type or feed_url.endswith(".json"):
            if is_valid_json_feed(response.text):
                items = 0
                try:
                    items = len(json.loads(response.text).get("items", []))
                except Exception:
                    items = 0
                return True, "json", items

        # Check XML-based feeds (RSS/Atom)
        content = response.content or b""
        lowered = content.lower()

        if _FEEDPARSER_AVAILABLE and feedparser is not None:
            feed = feedparser.parse(content)
            if feed.version and getattr(feed, "entries", []):
                entry_count = len(getattr(feed, "entries", []) or [])
                if "atom" in feed.version.lower():
                    return True, "atom", entry_count
                if "rss" in feed.version.lower():
                    return True, "rss", entry_count
                return True, "xml", entry_count  # Generic XML feed

        # Fallback: lightweight XML sniffing when feedparser isn't available
        # RSS often has <rss> with <item> entries; Atom has <feed> with <entry>.
        if b"<rss" in lowered or b"<rdf:rdf" in lowered:
            entry_count = int(lowered.count(b"<item"))
            return True, "rss", entry_count
        if b"<feed" in lowered and b"<entry" in lowered:
            entry_count = int(lowered.count(b"<entry"))
            return True, "atom", entry_count

    except RequestException as e:
        logger.debug(f"Request failed: {feed_url} - {e}")
    except Exception as e:
        logger.debug(f"Unexpected error: {feed_url} - {e}")

    return False, None, 0


def extract_feeds_from_html(html_content: str, base_url: str) -> List[Dict[str, str]]:
    """
    Extract feed URLs from HTML content by parsing meta headers and link tags.
    Returns list of dicts with 'url', 'type', 'title', and 'method' keys.
    """
    feeds = []

    try:
        if not _BS4_AVAILABLE or BeautifulSoup is None:
            return feeds
        soup = BeautifulSoup(html_content, "html.parser")

        # Method 1: Look for <link rel="alternate"> OR <link rel="feed"> tags
        link_tags = soup.find_all(
            "link",
            rel=lambda x: bool(_parse_rel_tokens(x).intersection({"alternate", "feed"})),
        )
        for link in link_tags:
            href = link.get("href")
            link_type = link.get("type", "").lower()
            title = link.get("title", "")

            # rel=feed may omit type, so accept if href looks feed-like
            if href and (
                any(feed_type in link_type for feed_type in FEED_MIME_TYPES)
                or _is_probable_feed_url(href)
            ):
                absolute_url = urllib.parse.urljoin(base_url, href)
                feeds.append(
                    {
                        "url": absolute_url,
                        "type": link_type,
                        "title": title,
                        "method": "html_link_rel",
                    }
                )

        # Method 2: Look for any <link> tags with feed-related types
        all_links = soup.find_all("link", type=True)
        for link in all_links:
            href = link.get("href")
            link_type = link.get("type", "").lower()
            title = link.get("title", "")

            if href and any(feed_type in link_type for feed_type in FEED_MIME_TYPES):
                absolute_url = urllib.parse.urljoin(base_url, href)
                # Avoid duplicates
                if not any(f["url"] == absolute_url for f in feeds):
                    feeds.append(
                        {
                            "url": absolute_url,
                            "type": link_type,
                            "title": title,
                            "method": "html_link_type",
                        }
                    )

        # Method 3: Look for <a> tags with feed-related URLs in content
        a_tags = soup.find_all("a", href=True)
        for a_tag in a_tags:
            href = a_tag.get("href", "")
            text = a_tag.get_text(strip=True).lower()

            # Check if URL or text suggests it's a feed
            if any(
                pattern in href.lower() for pattern in ["rss", "atom", "feed", ".xml"]
            ) or any(
                pattern in text for pattern in ["rss", "atom", "feed", "subscribe"]
            ):
                absolute_url = urllib.parse.urljoin(base_url, href)
                # Avoid duplicates and non-feed URLs
                if not any(f["url"] == absolute_url for f in feeds) and not any(
                    pattern in absolute_url.lower()
                    for pattern in ["javascript:", "mailto:", "#"]
                ):
                    feeds.append(
                        {
                            "url": absolute_url,
                            "type": "unknown",
                            "title": text,
                            "method": "html_content_link",
                        }
                    )

        # Method 4: Look in HTML comments for feed references
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for comment in comments:
            comment_text = str(comment).lower()
            if any(pattern in comment_text for pattern in ["rss", "atom", "feed"]):
                # Try to extract URLs from comments
                url_pattern = r'https?://[^\s<>"\']+(?:rss|atom|feed|xml)[^\s<>"\']*'
                urls = re.findall(url_pattern, comment_text, re.IGNORECASE)
                for url in urls:
                    if not any(f["url"] == url for f in feeds):
                        feeds.append(
                            {
                                "url": url,
                                "type": "unknown",
                                "title": "Found in HTML comment",
                                "method": "html_comment",
                            }
                        )

    except Exception as e:
        logger.debug(f"Error parsing HTML: {e}")

    return feeds


def check_robots_txt(base_url: str) -> List[str]:
    """Check robots.txt for feed references."""
    feeds = []
    parsed = urllib.parse.urlparse(base_url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"

    try:
        session = get_session()
        response = session.get(robots_url, timeout=ROBOTS_TIMEOUT)
        if response.status_code == 200:
            content = response.text.lower()
            # Look for feed-related entries
            lines = content.split("\n")
            for line in lines:
                if any(keyword in line for keyword in ["rss", "atom", "feed", "xml"]):
                    # Extract URLs from the line
                    url_pattern = r"https?://[^\s]+|/[^\s]+"
                    urls = re.findall(url_pattern, line)
                    for url in urls:
                        if any(
                            pattern in url.lower()
                            for pattern in ["rss", "atom", "feed", "xml"]
                        ):
                            absolute_url = urllib.parse.urljoin(base_url, url)
                            feeds.append(absolute_url)
    except Exception as e:
        logger.debug(f"Error checking robots.txt: {e}")

    return feeds


def extract_sitemaps_from_robots_txt(base_url: str) -> List[str]:
    """Extract sitemap URLs from robots.txt (Sitemap: https://... lines)."""
    parsed = urllib.parse.urlparse(base_url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    sitemaps: List[str] = []
    try:
        session = get_session()
        response = session.get(robots_url, timeout=ROBOTS_TIMEOUT)
        if response.status_code != 200:
            return []
        for line in response.text.splitlines():
            if line.strip().lower().startswith("sitemap:"):
                _, value = line.split(":", 1)
                url = value.strip()
                if url:
                    sitemaps.append(url)
    except Exception as e:
        logger.debug(f"Error extracting sitemaps from robots.txt: {e}")
    return sitemaps


def check_sitemap_xml(base_url: str) -> List[str]:
    """Check sitemap.xml for feed references."""
    feeds = []
    parsed = urllib.parse.urlparse(base_url)
    sitemap_urls = [
        f"{parsed.scheme}://{parsed.netloc}/sitemap.xml",
        f"{parsed.scheme}://{parsed.netloc}/sitemap_index.xml",
    ]

    for sitemap_url in sitemap_urls:
        try:
            session = get_session()
            response = session.get(sitemap_url, timeout=SITEMAP_TIMEOUT)
            if response.status_code == 200:
                # Look for feed URLs in sitemap
                content = response.text.lower()
                url_pattern = r"<loc>([^<]+)</loc>"
                urls = re.findall(url_pattern, content)
                for url in urls:
                    if any(
                        pattern in url.lower()
                        for pattern in ["rss", "atom", "feed", "xml"]
                    ):
                        feeds.append(url)
        except Exception as e:
            logger.debug(f"Error checking sitemap {sitemap_url}: {e}")

    return feeds


def extract_candidate_pages_from_sitemaps(
    base_url: str, sitemap_urls: List[str], limit: int = 30
) -> List[str]:
    """
    Use sitemap(s) to find likely blog/research/news landing pages to run HTML
    autodiscovery against. This is often better than looking for 'rss' in locs.
    """
    root = _root_url(base_url)
    candidates: List[str] = []
    seen: set[str] = set()

    def add(u: str) -> None:
        if u not in seen:
            seen.add(u)
            candidates.append(u)

    patterns = [
        "/blog/",
        "/news/",
        "/research/",
        "/insights/",
        "/articles/",
        "/threat-research/",
        "/threat-intelligence/",
        "/resources/",
    ]

    for sitemap_url in sitemap_urls:
        try:
            session = get_session()
            response = session.get(sitemap_url, timeout=SITEMAP_TIMEOUT)
            if response.status_code != 200:
                continue

            # Extract a bounded number of <loc> entries.
            locs = re.findall(r"<loc>([^<]+)</loc>", response.text, flags=re.IGNORECASE)
            for loc in locs[:1000]:
                loc = loc.strip()
                if not loc:
                    continue
                if not loc.startswith(("http://", "https://")):
                    loc = urllib.parse.urljoin(root + "/", loc)
                low = loc.lower()
                if any(p in low for p in patterns):
                    # Prefer "section" directories rather than deep articles
                    for p in patterns:
                        if p in low:
                            add(urllib.parse.urljoin(root + "/", p.lstrip("/")))
                    if len(candidates) >= limit:
                        return candidates
        except Exception as e:
            logger.debug(f"Error extracting candidate pages from sitemap {sitemap_url}: {e}")
            continue

    return candidates[:limit]


def discover_feeds_from_html(base_url: str) -> List[Dict[str, str]]:
    """Fetch HTML page and extract all possible feed URLs."""
    try:
        session = get_session()
        response = session.get(base_url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        feeds = extract_feeds_from_html(response.text, base_url)
        # Also parse HTTP Link header if present
        link_header = response.headers.get("Link") or response.headers.get("link") or ""
        feeds.extend(_parse_http_link_header(link_header, base_url))
        return feeds

    except Exception as e:
        logger.debug(f"Error fetching HTML from {base_url}: {e}")
        return []


def try_paths_from_root(base_url: str, paths: List[str]) -> Optional[Dict[str, str]]:
    """Try all paths from the root domain concurrently and return the first valid feed."""
    parsed = urllib.parse.urlparse(base_url)
    root_url = f"{parsed.scheme}://{parsed.netloc}"

    def check_path(path: str) -> Optional[Dict[str, str]]:
        test_url = urllib.parse.urljoin(root_url, path)
        is_valid, feed_type, entry_count = is_valid_feed(test_url)
        if is_valid:
            return {
                "url": test_url,
                "type": feed_type or "unknown",
                "title": f"Found at common path: {path}",
                "method": "common_path_root",
                "entries": str(entry_count),
            }
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_path = {executor.submit(check_path, path): path for path in paths}
        for future in concurrent.futures.as_completed(future_to_path):
            result = future.result()
            if result:
                return result
    return None


def try_paths_from_base(base_url: str, paths: List[str]) -> Optional[Dict[str, str]]:
    """Try all paths relative to the given base URL and return the first valid feed."""

    def check_path(path: str) -> Optional[Dict[str, str]]:
        # Only try relative paths (not starting with /) to avoid duplicating root domain attempts
        if path.startswith("/"):
            return None

        # Ensure proper path joining for relative paths
        if not path:
            test_url = base_url
        else:
            test_url = base_url.rstrip("/") + "/" + path.lstrip("/")

        is_valid, feed_type, entry_count = is_valid_feed(test_url)
        if is_valid:
            return {
                "url": test_url,
                "type": feed_type or "unknown",
                "title": f"Found at relative path: {path}",
                "method": "common_path_relative",
                "entries": str(entry_count),
            }
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_path = {executor.submit(check_path, path): path for path in paths}
        for future in concurrent.futures.as_completed(future_to_path):
            result = future.result()
            if result:
                return result
    return None


def try_paths_from_prefix(prefix_url: str, paths: List[str]) -> List[Dict[str, str]]:
    """
    Try feed paths under a specific section/prefix (e.g. https://site/blog/).
    Returns all valid feeds discovered from that prefix.
    """
    found: List[Dict[str, str]] = []
    seen: set[str] = set()

    def check_path(path: str) -> Optional[Dict[str, str]]:
        if not path:
            return None
        # Ensure we only join as relative path within prefix
        test_url = prefix_url.rstrip("/") + "/" + path.lstrip("/")
        ok, feed_type, entry_count = is_valid_feed(test_url)
        if ok:
            return {
                "url": test_url,
                "type": feed_type or "unknown",
                "title": f"Found at section path: {path}",
                "method": "common_path_section",
                "entries": str(entry_count),
            }
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_path, p) for p in paths]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result and result["url"] not in seen:
                seen.add(result["url"])
                found.append(result)
    return found


def _score_feed(feed: Dict[str, str]) -> int:
    method_weight = {
        "direct_url": 100,
        "http_link_header": 95,
        "html_link_rel": 90,
        "html_link_alternate": 90,
        "html_link_type": 85,
        "robots_txt": 70,
        "sitemap_xml": 65,
        "common_path_section": 62,
        "common_path_relative": 60,
        "common_path_root": 55,
        "html_content_link": 45,
        "html_comment": 40,
    }.get(feed.get("method", ""), 30)

    type_weight = {
        "rss": 8,
        "atom": 7,
        "json": 7,
        "xml": 5,
        "unknown": 0,
    }.get((feed.get("type") or "unknown").split(";")[0].strip(), 0)

    entries_bonus = 0
    try:
        entries_bonus = min(int(feed.get("entries", "0")), 50) // 5
    except Exception:
        entries_bonus = 0

    title_bonus = 2 if (feed.get("title") or "").strip() else 0
    https_bonus = 1 if feed.get("url", "").startswith("https://") else 0

    return method_weight + type_weight + entries_bonus + title_bonus + https_bonus


def find_all_feeds(base_url: str) -> List[Dict[str, str]]:
    """
    Find all RSS/Atom/JSON feeds for the given base URL using multiple discovery methods.
    Returns list of feed dictionaries with url, type, title, and method.
    """
    base_url = normalize_url(base_url)
    domain_key = _root_url(base_url)
    if domain_key in _DOMAIN_FEED_CACHE:
        return _DOMAIN_FEED_CACHE[domain_key]

    all_feeds = []
    seen_urls = set()

    # Fetch HTML once to derive better candidate bases and check Link header/canonical.
    final_url, html, headers = _fetch_html(base_url)
    effective_url = final_url or base_url
    candidate_bases = _generate_candidate_bases(effective_url, html)

    # Method 1: Check if the URL itself is a valid feed (original + effective)
    for direct in [base_url, effective_url]:
        if direct in seen_urls:
            continue
        is_valid, feed_type, entry_count = is_valid_feed(direct)
        if is_valid:
            feed_info = {
                "url": direct,
                "type": feed_type or "unknown",
                "title": "Direct URL is a feed",
                "method": "direct_url",
                "entries": str(entry_count),
            }
            all_feeds.append(feed_info)
            seen_urls.add(direct)
            # If direct is a feed, we still keep searching; some sites expose multiple feeds.

    # Method 2: Parse HTTP Link header from initial response (if any)
    link_header = headers.get("link", "")
    header_feeds = _parse_http_link_header(link_header, effective_url)
    for feed in header_feeds:
        if feed["url"] in seen_urls:
            continue
        is_valid, feed_type, entry_count = is_valid_feed(feed["url"])
        if is_valid:
            feed["type"] = feed_type or feed.get("type", "unknown")
            feed["entries"] = str(entry_count)
            all_feeds.append(feed)
            seen_urls.add(feed["url"])

    # Method 3: Parse HTML for feed links in meta headers for each candidate base
    for candidate in candidate_bases:
        logger.debug(f"Parsing HTML/meta/link header for feeds: {candidate}")
        html_feeds = discover_feeds_from_html(candidate)
        for feed in html_feeds:
            if feed["url"] in seen_urls:
                continue
            is_valid, feed_type, entry_count = is_valid_feed(feed["url"])
            if is_valid:
                feed["type"] = feed_type or feed.get("type", "unknown")
                feed["entries"] = str(entry_count)
                all_feeds.append(feed)
                seen_urls.add(feed["url"])

    # Method 4: Check robots.txt for feed references
    logger.debug("Checking robots.txt for feed references")
    robots_feeds = check_robots_txt(effective_url)
    for feed_url in robots_feeds:
        if feed_url not in seen_urls:
            is_valid, feed_type, entry_count = is_valid_feed(feed_url)
            if is_valid:
                feed_info = {
                    "url": feed_url,
                    "type": feed_type or "unknown",
                    "title": "Found in robots.txt",
                    "method": "robots_txt",
                    "entries": str(entry_count),
                }
                all_feeds.append(feed_info)
                seen_urls.add(feed_url)

    # Method 5: Check sitemap.xml and sitemap URLs discovered via robots.txt
    logger.debug("Checking sitemap.xml for feed references")
    sitemap_urls = list(
        dict.fromkeys(
            extract_sitemaps_from_robots_txt(effective_url)
            + [
                urllib.parse.urljoin(_root_url(effective_url) + "/", "sitemap.xml"),
                urllib.parse.urljoin(_root_url(effective_url) + "/", "sitemap_index.xml"),
            ]
        )
    )
    sitemap_feeds = check_sitemap_xml(effective_url)
    for feed_url in sitemap_feeds:
        if feed_url not in seen_urls:
            is_valid, feed_type, entry_count = is_valid_feed(feed_url)
            if is_valid:
                feed_info = {
                    "url": feed_url,
                    "type": feed_type or "unknown",
                    "title": "Found in sitemap.xml",
                    "method": "sitemap_xml",
                    "entries": str(entry_count),
                }
                all_feeds.append(feed_info)
                seen_urls.add(feed_url)

    # Method 6: Use sitemap(s) to find candidate landing pages, then autodiscover on them
    candidate_pages = extract_candidate_pages_from_sitemaps(effective_url, sitemap_urls)
    for page in candidate_pages:
        logger.debug(f"Running HTML autodiscovery on sitemap-derived page: {page}")
        for feed in discover_feeds_from_html(page):
            if feed["url"] in seen_urls:
                continue
            is_valid, feed_type, entry_count = is_valid_feed(feed["url"])
            if is_valid:
                feed["type"] = feed_type or feed.get("type", "unknown")
                feed["entries"] = str(entry_count)
                feed.setdefault("title", "Found via sitemap landing page")
                all_feeds.append(feed)
                seen_urls.add(feed["url"])

    # Method 7: Smarter bruteforce:
    # - Try relative paths from each candidate base (walk-up paths)
    # - Try section-aware paths (e.g. /blog/feed)
    for candidate in candidate_bases[:5]:
        logger.debug(f"Trying relative RSS paths from base: {candidate}")
        relative_result = try_paths_from_base(candidate, RELATIVE_RSS_PATHS)
        if relative_result and relative_result["url"] not in seen_urls:
            all_feeds.append(relative_result)
            seen_urls.add(relative_result["url"])

        # If candidate looks like a section root, try section-specific paths too
        parsed = urllib.parse.urlparse(candidate)
        if parsed.path and parsed.path != "/":
            for feed in try_paths_from_prefix(candidate, RELATIVE_RSS_PATHS + COMMON_RSS_PATHS):
                if feed["url"] not in seen_urls:
                    all_feeds.append(feed)
                    seen_urls.add(feed["url"])

    # Method 8: Try absolute paths from the root domain
    base_root = _root_url(effective_url)
    logger.debug(f"Trying absolute RSS paths from root domain: {base_root}")
    root_result = try_paths_from_root(effective_url, COMMON_RSS_PATHS)
    if root_result and root_result["url"] not in seen_urls:
        all_feeds.append(root_result)
        seen_urls.add(root_result["url"])

    # Sort best-first and cache per domain
    all_feeds.sort(key=_score_feed, reverse=True)
    _DOMAIN_FEED_CACHE[domain_key] = all_feeds
    return all_feeds


def find_rss_feed(base_url: str) -> Optional[str]:
    """Find the best RSS feed for the given base URL (backwards compatibility)."""
    feeds = find_all_feeds(base_url)
    if feeds:
        return feeds[0]["url"]
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Find RSS/Atom/JSON feeds for given URL(s)"
    )
    parser.add_argument(
        "urls", nargs="*", help="One or more URLs to check for RSS feeds"
    )
    parser.add_argument(
        "-f", "--file", type=str, help="Path to file containing one URL per line"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )
    parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        help="Show all discovered feeds, not just the first one",
    )
    parser.add_argument(
        "--json", action="store_true", help="Output results in JSON format"
    )
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    urls = args.urls
    if args.file:
        try:
            with open(args.file, "r") as f:
                urls.extend(line.strip() for line in f if line.strip())
        except Exception as e:
            logger.error(f"Failed to read file: {e}")
            return 1

    if not urls:
        logger.error("No URLs provided.")
        return 1

    results = []
    for url in urls:
        logger.info(f"Searching for feeds at {url}")

        if args.all:
            feeds = find_all_feeds(url)
            if feeds:
                if args.json:
                    results.append({"url": url, "feeds": feeds})
                else:
                    print(f"\n{url}:")
                    for i, feed in enumerate(feeds, 1):
                        print(f"  {i}. {feed['url']}")
                        print(f"     Type: {feed['type']}, Method: {feed['method']}")
                        if feed["title"]:
                            print(f"     Title: {feed['title']}")
            else:
                if args.json:
                    results.append({"url": url, "feeds": []})
                else:
                    print(f"{url} → No valid feeds found.")
        else:
            # Single feed mode (backwards compatibility)
            result = find_rss_feed(url)
            if result:
                if args.json:
                    results.append({"url": url, "feed": result})
                else:
                    print(f"{url} → {result}")
            else:
                if args.json:
                    results.append({"url": url, "feed": None})
                else:
                    print(f"{url} → No valid RSS feed found.")

    if args.json:
        print(json.dumps(results, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())
