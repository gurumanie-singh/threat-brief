"""Merge fetched articles with existing data, enrich, group, prune, and archive.

Data lifecycle:
  0-7 days   -> active (shown on homepage)
  7-30 days  -> archive (browsable, stored in data/archive/)
  >30 days   -> deleted from articles.json + archive JSON + generated pages
"""

from __future__ import annotations

import logging
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any

from scripts.config import (
    ARTICLES_FILE,
    ARCHIVE_DIR,
    load_feeds_config,
    get_settings,
    get_vendor_keywords,
    get_personalization,
)
from scripts.enrich import enrich_article, group_articles
from scripts.fetch_feeds import fetch_all_feeds
from scripts.utils import load_json, save_json, now_utc, today_str

logger = logging.getLogger(__name__)


def merge_articles(
    existing: list[dict[str, Any]],
    incoming: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge incoming into existing, deduplicating by article id."""
    index: dict[str, dict[str, Any]] = {a["id"]: a for a in existing}
    new_count = 0
    for article in incoming:
        if article["id"] not in index:
            new_count += 1
        index[article["id"]] = article
    if new_count:
        logger.info("  %d genuinely new articles added", new_count)
    return sorted(index.values(), key=lambda a: a["published"], reverse=True)


def prune_old(articles: list[dict[str, Any]], max_days: int) -> list[dict[str, Any]]:
    """Remove articles older than max_days."""
    cutoff = (now_utc() - timedelta(days=max_days)).strftime("%Y-%m-%d")
    kept = [a for a in articles if a["day"] >= cutoff]
    removed = len(articles) - len(kept)
    if removed:
        logger.info("Pruned %d articles older than %s (%d-day retention)", removed, cutoff, max_days)
    return kept


def archive_today(articles: list[dict[str, Any]]) -> None:
    """Save a daily snapshot of today's articles."""
    day = today_str()
    todays = [a for a in articles if a["day"] == day]
    if not todays:
        logger.info("No articles for %s to archive", day)
        return
    archive_path = ARCHIVE_DIR / f"{day}.json"
    save_json(archive_path, todays)
    logger.info("Archived %d articles to %s", len(todays), archive_path.name)


def cleanup_old_archives(max_days: int) -> int:
    """Delete archive JSON files older than max_days. Returns count deleted."""
    if not ARCHIVE_DIR.exists():
        return 0
    cutoff = (now_utc() - timedelta(days=max_days)).strftime("%Y-%m-%d")
    deleted = 0
    for path in sorted(ARCHIVE_DIR.glob("*.json")):
        day_str = path.stem
        if day_str < cutoff:
            path.unlink()
            deleted += 1
            logger.info("Deleted old archive %s", path.name)
    return deleted


def process() -> list[dict[str, Any]]:
    """Full pipeline: fetch -> enrich -> merge -> group -> prune -> save -> archive -> cleanup."""
    config = load_feeds_config()
    settings = get_settings(config)
    vendor_kw = get_vendor_keywords(config)
    personalization = get_personalization(config)
    max_retention = settings.get("max_retention_days", 30)

    logger.info("Loading existing articles from %s", ARTICLES_FILE)
    existing = load_json(ARTICLES_FILE)
    logger.info("Existing articles: %d", len(existing))

    incoming = fetch_all_feeds()

    logger.info("Enriching %d incoming articles...", len(incoming))
    enriched: list[dict[str, Any]] = []
    for article in incoming:
        try:
            enriched.append(enrich_article(article, vendor_kw, personalization))
        except Exception as exc:
            logger.warning("Enrichment failed for '%s': %s", article.get("title", "?"), exc)
            enriched.append(article)

    merged = merge_articles(existing, enriched)
    logger.info("After merge: %d articles", len(merged))

    pre_group = len(merged)
    merged = group_articles(merged)
    grouped_count = pre_group - len(merged)
    if grouped_count:
        logger.info("Story grouping consolidated %d duplicates", grouped_count)

    pruned = prune_old(merged, max_retention)
    logger.info("After prune (%d-day retention): %d articles", max_retention, len(pruned))

    save_json(ARTICLES_FILE, pruned)
    archive_today(pruned)

    old_cleaned = cleanup_old_archives(max_retention)
    if old_cleaned:
        logger.info("Cleaned %d archive files older than %d days", old_cleaned, max_retention)

    return pruned


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    articles = process()
    print(f"Processed {len(articles)} articles total")
    enriched = sum(1 for a in articles if a.get("sections"))
    grouped = sum(1 for a in articles if a.get("related_sources"))
    action = sum(1 for a in articles if a.get("action_required"))
    print(f"  {enriched} with enriched sections")
    print(f"  {grouped} with related sources (grouped)")
    print(f"  {action} flagged as action-required")


if __name__ == "__main__":
    sys.exit(main() or 0)
