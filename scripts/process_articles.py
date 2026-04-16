"""Incremental article processing with per-day JSON storage.

Storage layout:
  data/days/YYYY-MM-DD.json  -- each day's articles (max ~20 per file)

Lifecycle:
  0-7 days   -> active (shown on homepage)
  7-30 days  -> archive (browsable via archive pages)
  >30 days   -> deleted automatically

Key optimisations over the previous monolithic approach:
  - Only new articles are enriched (existing articles are left untouched)
  - full_content is stripped before storage (saves ~40% per article)
  - Only changed day files are written (minimal git diff)
  - Per-day files cap at max_articles_per_day
"""

from __future__ import annotations

import logging
import sys
from collections import defaultdict
from datetime import timedelta
from typing import Any

from scripts.config import (
    DAYS_DIR,
    _LEGACY_ARTICLES_FILE,
    load_feeds_config,
    get_settings,
    get_vendor_keywords,
    get_personalization,
)
from scripts.enrich import enrich_article, group_articles
from scripts.fetch_feeds import fetch_all_feeds
from scripts.utils import (
    load_day, save_day, list_day_files, load_json,
    now_utc,
)

logger = logging.getLogger(__name__)

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _migrate_legacy(max_retention_days: int) -> None:
    """One-time migration: split monolithic articles.json into per-day files."""
    if not _LEGACY_ARTICLES_FILE.exists():
        return

    logger.info("Migrating legacy articles.json to per-day files...")
    articles = load_json(_LEGACY_ARTICLES_FILE)
    if not articles:
        _LEGACY_ARTICLES_FILE.unlink(missing_ok=True)
        return

    by_day: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for a in articles:
        a.pop("full_content", None)
        by_day[a["day"]].append(a)

    cutoff = (now_utc() - timedelta(days=max_retention_days)).strftime("%Y-%m-%d")
    written = 0
    for day_str, day_articles in by_day.items():
        if day_str < cutoff:
            continue
        save_day(DAYS_DIR, day_str, day_articles)
        written += 1

    _LEGACY_ARTICLES_FILE.unlink(missing_ok=True)
    logger.info("Migration complete: %d day files written, legacy file removed", written)


def _strip_for_storage(article: dict[str, Any]) -> dict[str, Any]:
    """Remove transient fields that don't need to be persisted."""
    article.pop("full_content", None)
    return article


def _rank_article(a: dict[str, Any]) -> tuple[int, int, str]:
    """Sort key: severity asc (critical first), action_required desc, then recency."""
    sev = _SEVERITY_RANK.get(a.get("severity") or "", 99)
    action = 0 if a.get("action_required") else 1
    return (sev, action, a.get("published", ""))


def cleanup_old_days(max_days: int) -> int:
    """Delete per-day files older than max_days. Returns count deleted."""
    cutoff = (now_utc() - timedelta(days=max_days)).strftime("%Y-%m-%d")
    deleted = 0
    for day_str, path in list_day_files(DAYS_DIR):
        if day_str < cutoff:
            path.unlink()
            deleted += 1
            logger.info("Deleted expired day file %s", path.name)
    return deleted


def process() -> list[dict[str, Any]]:
    """Incremental pipeline: fetch -> enrich new -> merge per-day -> prune -> save."""
    config = load_feeds_config()
    settings = get_settings(config)
    vendor_kw = get_vendor_keywords(config)
    personalization = get_personalization(config)
    max_retention = settings.get("max_retention_days", 30)
    max_per_day = settings.get("max_articles_per_day", 20)

    _migrate_legacy(max_retention)

    incoming = fetch_all_feeds()

    retention_cutoff = (now_utc() - timedelta(days=max_retention)).strftime("%Y-%m-%d")
    incoming_by_day: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for a in incoming:
        if a["day"] >= retention_cutoff:
            incoming_by_day[a["day"]].append(a)

    total_new = 0
    total_stored = 0
    days_written = 0

    for day_str, day_incoming in sorted(incoming_by_day.items()):
        existing = load_day(DAYS_DIR, day_str)
        existing_ids = {a["id"] for a in existing}

        new_articles: list[dict[str, Any]] = []
        for article in day_incoming:
            if article["id"] in existing_ids:
                continue
            try:
                enriched = enrich_article(article, vendor_kw, personalization)
                new_articles.append(_strip_for_storage(enriched))
            except Exception as exc:
                logger.warning("Enrichment failed for '%s': %s", article.get("title", "?"), exc)
                new_articles.append(_strip_for_storage(article))

        if not new_articles:
            total_stored += len(existing)
            continue

        total_new += len(new_articles)
        merged = existing + new_articles

        merged = group_articles(merged)
        merged.sort(key=_rank_article)
        if len(merged) > max_per_day:
            logger.info("Day %s: capped from %d to %d articles", day_str, len(merged), max_per_day)
            merged = merged[:max_per_day]

        save_day(DAYS_DIR, day_str, merged)
        days_written += 1
        total_stored += len(merged)

    logger.info(
        "Processing complete: %d new articles across %d day files (%d total stored)",
        total_new, days_written, total_stored,
    )

    deleted = cleanup_old_days(max_retention)
    if deleted:
        logger.info("Lifecycle: removed %d day files older than %d days", deleted, max_retention)

    # Also clean legacy archive dir if empty
    from scripts.config import DATA_DIR
    archive_dir = DATA_DIR / "archive"
    if archive_dir.exists():
        for old_file in archive_dir.glob("*.json"):
            old_file.unlink()
        # Remove .gitkeep if it's the only thing left, but keep the dir
    
    return _load_all_current()


def _load_all_current() -> list[dict[str, Any]]:
    """Load all articles from per-day files for downstream consumers."""
    from scripts.utils import load_all_days
    return load_all_days(DAYS_DIR)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    articles = process()
    print(f"Processed {len(articles)} articles total")
    enriched = sum(1 for a in articles if a.get("sections"))
    grouped = sum(1 for a in articles if a.get("related_sources"))
    action = sum(1 for a in articles if a.get("action_required"))
    days = len(set(a["day"] for a in articles))
    print(f"  {days} day files")
    print(f"  {enriched} with enriched sections")
    print(f"  {grouped} with related sources (grouped)")
    print(f"  {action} flagged as action-required")


if __name__ == "__main__":
    sys.exit(main() or 0)
