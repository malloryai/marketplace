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
from typing import Optional, List, Dict, Tuple
import concurrent.futures
import time
import random
import re
import json

import feedparser
import requests
from requests.exceptions import RequestException
from bs4 import BeautifulSoup, Comment

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

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
    return session


def normalize_url(url: str) -> str:
    """Ensure URL has scheme."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


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


def is_valid_feed(feed_url: str) -> Tuple[bool, Optional[str]]:
    """
    Return (True, feed_type) if the URL contains a valid RSS/Atom/JSON feed.
    feed_type can be 'rss', 'atom', 'json', or None
    """
    try:
        # Add a small random delay to avoid being too aggressive
        time.sleep(random.uniform(0.1, 0.3))

        session = get_session()
        response = session.get(feed_url, timeout=10)
        response.raise_for_status()

        content_type = response.headers.get("content-type", "").lower()

        # Check for JSON Feed first
        if "json" in content_type or feed_url.endswith(".json"):
            if is_valid_json_feed(response.text):
                return True, "json"

        # Check XML-based feeds (RSS/Atom)
        feed = feedparser.parse(response.content)
        if feed.version and getattr(feed, "entries", []):
            if "atom" in feed.version.lower():
                return True, "atom"
            elif "rss" in feed.version.lower():
                return True, "rss"
            else:
                return True, "xml"  # Generic XML feed

    except RequestException as e:
        logger.debug(f"Request failed: {feed_url} - {e}")
    except Exception as e:
        logger.debug(f"Unexpected error: {feed_url} - {e}")

    return False, None


def extract_feeds_from_html(html_content: str, base_url: str) -> List[Dict[str, str]]:
    """
    Extract feed URLs from HTML content by parsing meta headers and link tags.
    Returns list of dicts with 'url', 'type', 'title', and 'method' keys.
    """
    feeds = []

    try:
        soup = BeautifulSoup(html_content, "html.parser")

        # Method 1: Look for <link rel="alternate"> tags in head
        link_tags = soup.find_all("link", rel=lambda x: x and "alternate" in x)
        for link in link_tags:
            href = link.get("href")
            link_type = link.get("type", "").lower()
            title = link.get("title", "")

            if href and any(feed_type in link_type for feed_type in FEED_MIME_TYPES):
                absolute_url = urllib.parse.urljoin(base_url, href)
                feeds.append(
                    {
                        "url": absolute_url,
                        "type": link_type,
                        "title": title,
                        "method": "html_link_alternate",
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
        response = session.get(robots_url, timeout=5)
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
            response = session.get(sitemap_url, timeout=5)
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


def discover_feeds_from_html(base_url: str) -> List[Dict[str, str]]:
    """Fetch HTML page and extract all possible feed URLs."""
    try:
        session = get_session()
        response = session.get(base_url, timeout=10)
        response.raise_for_status()

        return extract_feeds_from_html(response.text, base_url)

    except Exception as e:
        logger.debug(f"Error fetching HTML from {base_url}: {e}")
        return []


def try_paths_from_root(base_url: str, paths: List[str]) -> Optional[Dict[str, str]]:
    """Try all paths from the root domain concurrently and return the first valid feed."""
    parsed = urllib.parse.urlparse(base_url)
    root_url = f"{parsed.scheme}://{parsed.netloc}"

    def check_path(path: str) -> Optional[Dict[str, str]]:
        test_url = urllib.parse.urljoin(root_url, path)
        is_valid, feed_type = is_valid_feed(test_url)
        if is_valid:
            return {
                "url": test_url,
                "type": feed_type or "unknown",
                "title": f"Found at common path: {path}",
                "method": "common_path_root",
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

        is_valid, feed_type = is_valid_feed(test_url)
        if is_valid:
            return {
                "url": test_url,
                "type": feed_type or "unknown",
                "title": f"Found at relative path: {path}",
                "method": "common_path_relative",
            }
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_path = {executor.submit(check_path, path): path for path in paths}
        for future in concurrent.futures.as_completed(future_to_path):
            result = future.result()
            if result:
                return result
    return None


def find_all_feeds(base_url: str) -> List[Dict[str, str]]:
    """
    Find all RSS/Atom/JSON feeds for the given base URL using multiple discovery methods.
    Returns list of feed dictionaries with url, type, title, and method.
    """
    base_url = normalize_url(base_url)
    all_feeds = []
    seen_urls = set()

    # Method 1: Check if the URL itself is a valid feed
    is_valid, feed_type = is_valid_feed(base_url)
    if is_valid:
        feed_info = {
            "url": base_url,
            "type": feed_type or "unknown",
            "title": "Direct URL is a feed",
            "method": "direct_url",
        }
        all_feeds.append(feed_info)
        seen_urls.add(base_url)

    # Method 2: Parse HTML for feed links in meta headers
    logger.debug(f"Parsing HTML meta headers for feed links: {base_url}")
    html_feeds = discover_feeds_from_html(base_url)
    for feed in html_feeds:
        if feed["url"] not in seen_urls:
            # Validate the discovered feed
            is_valid, feed_type = is_valid_feed(feed["url"])
            if is_valid:
                feed["type"] = feed_type or feed["type"]
                all_feeds.append(feed)
                seen_urls.add(feed["url"])

    # Method 3: Check robots.txt
    logger.debug("Checking robots.txt for feed references")
    robots_feeds = check_robots_txt(base_url)
    for feed_url in robots_feeds:
        if feed_url not in seen_urls:
            is_valid, feed_type = is_valid_feed(feed_url)
            if is_valid:
                feed_info = {
                    "url": feed_url,
                    "type": feed_type or "unknown",
                    "title": "Found in robots.txt",
                    "method": "robots_txt",
                }
                all_feeds.append(feed_info)
                seen_urls.add(feed_url)

    # Method 4: Check sitemap.xml
    logger.debug("Checking sitemap.xml for feed references")
    sitemap_feeds = check_sitemap_xml(base_url)
    for feed_url in sitemap_feeds:
        if feed_url not in seen_urls:
            is_valid, feed_type = is_valid_feed(feed_url)
            if is_valid:
                feed_info = {
                    "url": feed_url,
                    "type": feed_type or "unknown",
                    "title": "Found in sitemap.xml",
                    "method": "sitemap_xml",
                }
                all_feeds.append(feed_info)
                seen_urls.add(feed_url)

    # Method 5: Try relative paths from the given URL base
    logger.debug(f"Trying relative RSS paths from given URL base: {base_url}")
    relative_result = try_paths_from_base(base_url, RELATIVE_RSS_PATHS)
    if relative_result and relative_result["url"] not in seen_urls:
        all_feeds.append(relative_result)
        seen_urls.add(relative_result["url"])

    # Method 6: Try absolute paths from the root domain
    parsed = urllib.parse.urlparse(base_url)
    base_root = f"{parsed.scheme}://{parsed.netloc}"
    logger.debug(f"Trying absolute RSS paths from root domain: {base_root}")
    root_result = try_paths_from_root(base_url, COMMON_RSS_PATHS)
    if root_result and root_result["url"] not in seen_urls:
        all_feeds.append(root_result)
        seen_urls.add(root_result["url"])

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
