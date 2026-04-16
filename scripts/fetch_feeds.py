"""Fetch articles from configured RSS feeds with full content extraction."""

from __future__ import annotations

import logging
import socket
import sys
from typing import Any

import feedparser

_FEED_TIMEOUT_SECONDS = 30

from scripts.config import load_feeds_config, get_tag_keywords, get_settings
from scripts.utils import (
    article_id,
    is_safe_url,
    parse_date,
    strip_html,
    strip_emoji,
    truncate,
    now_utc,
)

logger = logging.getLogger(__name__)


def _apply_tags(text: str, tag_keywords: dict[str, list[str]]) -> list[str]:
    """Return matching tag names when any keyword appears in text."""
    lower = text.lower()
    return sorted({
        tag for tag, keywords in tag_keywords.items()
        if any(kw in lower for kw in keywords)
    })


def _extract_full_content(entry: Any) -> str:
    """Pull the richest content available from a feedparser entry."""
    if hasattr(entry, "content") and entry.content:
        for c in entry.content:
            if c.get("type", "") in ("text/html", "text/plain"):
                return strip_emoji(strip_html(c.get("value", "")))
        # Fall back to first content entry regardless of type
        first_val = entry.content[0].get("value", "") if entry.content else ""
        if first_val:
            return strip_emoji(strip_html(first_val))

    raw = entry.get("summary") or entry.get("description") or ""
    return strip_emoji(strip_html(raw))


def _parse_entry(
    entry: Any, source_name: str, tag_keywords: dict[str, list[str]]
) -> dict[str, Any] | None:
    """Convert a single feedparser entry to our normalised schema."""
    title = strip_emoji((entry.get("title") or "").strip())
    link = (entry.get("link") or "").strip()
    if not title or not link:
        return None
    if not is_safe_url(link):
        logger.warning("Rejected unsafe URL scheme in '%s': %s", title[:60], link[:80])
        return None

    full_content = _extract_full_content(entry)
    summary = truncate(
        full_content.split("\n")[0] if full_content else title,
        400,
    )

    published_raw = entry.get("published") or entry.get("updated") or ""
    published_dt = parse_date(published_raw)

    searchable = f"{title} {full_content}"
    tags = _apply_tags(searchable, tag_keywords)

    return {
        "id": article_id(title, link),
        "title": title,
        "source": source_name,
        "link": link,
        "published": published_dt.isoformat(),
        "summary": summary,
        "full_content": full_content,
        "tags": tags,
        "day": published_dt.strftime("%Y-%m-%d"),
    }


def fetch_all_feeds() -> list[dict[str, Any]]:
    """Fetch every configured feed and return a flat list of articles."""
    config = load_feeds_config()
    tag_keywords = get_tag_keywords(config)
    feeds = config["feeds"]

    articles: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for feed_cfg in feeds:
        name = feed_cfg["name"]
        url = feed_cfg["url"]
        logger.info("Fetching feed: %s (%s)", name, url)

        prev_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(_FEED_TIMEOUT_SECONDS)
            parsed = feedparser.parse(url)
        except Exception as exc:
            logger.error("Failed to fetch %s: %s", name, exc)
            continue
        finally:
            socket.setdefaulttimeout(prev_timeout)

        if parsed.bozo and not parsed.entries:
            logger.warning(
                "Feed %s returned no entries (bozo: %s)", name, parsed.bozo_exception
            )
            continue

        count = 0
        for entry in parsed.entries:
            try:
                article = _parse_entry(entry, name, tag_keywords)
            except Exception as exc:
                logger.warning("Skipping bad entry in %s: %s", name, exc)
                continue

            if article is None:
                continue
            if article["id"] in seen_ids:
                continue

            seen_ids.add(article["id"])
            articles.append(article)
            count += 1

        logger.info("  → %d articles from %s", count, name)

    articles.sort(key=lambda a: a["published"], reverse=True)
    logger.info("Total fetched: %d unique articles", len(articles))
    return articles


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    articles = fetch_all_feeds()
    print(f"Fetched {len(articles)} articles")
    for a in articles[:5]:
        print(f"  [{a['day']}] {a['title'][:80]}")


if __name__ == "__main__":
    sys.exit(main() or 0)
