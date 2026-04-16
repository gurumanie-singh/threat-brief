"""Merge fetched articles with existing data, enrich, group, prune, and archive."""

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
    for article in incoming:
        index[article["id"]] = article
    merged = sorted(index.values(), key=lambda a: a["published"], reverse=True)
    return merged


def prune_old(articles: list[dict[str, Any]], max_age_days: int) -> list[dict[str, Any]]:
    cutoff = (now_utc() - timedelta(days=max_age_days)).strftime("%Y-%m-%d")
    kept = [a for a in articles if a["day"] >= cutoff]
    removed = len(articles) - len(kept)
    if removed:
        logger.info("Pruned %d articles older than %s", removed, cutoff)
    return kept


def archive_today(articles: list[dict[str, Any]]) -> None:
    day = today_str()
    todays = [a for a in articles if a["day"] == day]
    if not todays:
        logger.info("No articles for %s to archive", day)
        return
    archive_path = ARCHIVE_DIR / f"{day}.json"
    save_json(archive_path, todays)
    logger.info("Archived %d articles to %s", len(todays), archive_path.name)


def process() -> list[dict[str, Any]]:
    """Full pipeline: fetch → enrich → merge → group → prune → save → archive."""
    config = load_feeds_config()
    settings = get_settings(config)
    vendor_kw = get_vendor_keywords(config)
    personalization = get_personalization(config)

    logger.info("Loading existing articles from %s", ARTICLES_FILE)
    existing = load_json(ARTICLES_FILE)
    logger.info("Existing articles: %d", len(existing))

    incoming = fetch_all_feeds()

    logger.info("Enriching %d incoming articles…", len(incoming))
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

    pruned = prune_old(merged, settings["max_article_age_days"])
    logger.info("After prune: %d articles", len(pruned))

    save_json(ARTICLES_FILE, pruned)
    archive_today(pruned)

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
