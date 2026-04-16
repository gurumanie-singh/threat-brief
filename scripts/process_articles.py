"""Merge newly fetched articles with existing data, deduplicate, prune old entries, and archive."""

from __future__ import annotations

import logging
import sys
from datetime import timedelta
from typing import Any

from scripts.config import (
    ARTICLES_FILE,
    ARCHIVE_DIR,
    load_feeds_config,
    get_settings,
)
from scripts.fetch_feeds import fetch_all_feeds
from scripts.utils import load_json, save_json, now_utc, today_str

logger = logging.getLogger(__name__)


def merge_articles(
    existing: list[dict[str, Any]],
    incoming: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge incoming into existing, deduplicating by article id."""
    index: dict[str, dict[str, Any]] = {a["id"]: a for a in existing}
    for article in incoming:
        index[article["id"]] = article
    merged = sorted(index.values(), key=lambda a: a["published"], reverse=True)
    return merged


def prune_old(articles: list[dict[str, Any]], max_age_days: int) -> list[dict[str, Any]]:
    """Remove articles older than max_age_days."""
    cutoff = (now_utc() - timedelta(days=max_age_days)).strftime("%Y-%m-%d")
    kept = [a for a in articles if a["day"] >= cutoff]
    removed = len(articles) - len(kept)
    if removed:
        logger.info("Pruned %d articles older than %s", removed, cutoff)
    return kept


def archive_today(articles: list[dict[str, Any]]) -> None:
    """Write today's articles to the daily archive snapshot."""
    day = today_str()
    todays = [a for a in articles if a["day"] == day]
    if not todays:
        logger.info("No articles for %s to archive", day)
        return
    archive_path = ARCHIVE_DIR / f"{day}.json"
    save_json(archive_path, todays)
    logger.info("Archived %d articles to %s", len(todays), archive_path.name)


def process() -> list[dict[str, Any]]:
    """Full pipeline: fetch → merge → prune → save → archive."""
    config = load_feeds_config()
    settings = get_settings(config)

    logger.info("Loading existing articles from %s", ARTICLES_FILE)
    existing = load_json(ARTICLES_FILE)
    logger.info("Existing articles: %d", len(existing))

    incoming = fetch_all_feeds()
    merged = merge_articles(existing, incoming)
    logger.info("After merge: %d articles", len(merged))

    pruned = prune_old(merged, settings["max_article_age_days"])
    logger.info("After prune: %d articles", len(pruned))

    save_json(ARTICLES_FILE, pruned)
    archive_today(pruned)

    return pruned


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    articles = process()
    print(f"Processed {len(articles)} articles total")


if __name__ == "__main__":
    sys.exit(main() or 0)
