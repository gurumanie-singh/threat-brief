"""Generate the static GitHub Pages site into docs/.

Produces:
  docs/index.html            -- homepage with recent articles (last active_days)
  docs/daily/YYYY-MM-DD.html -- per-day briefing pages
  docs/articles/{id}.html    -- individual article pages with structured sections
  docs/archive/index.html    -- archive listing
  docs/assets/style.css      -- design system stylesheet
  docs/assets/app.js         -- client-side interactions

Reads from data/days/YYYY-MM-DD.json (per-day article files).
Cleans up stale generated pages for articles/days that no longer exist.
"""

from __future__ import annotations

import json
import logging
import shutil
import sys
from collections import Counter, defaultdict
from datetime import timedelta
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader
from markupsafe import Markup

from scripts.config import (
    DATA_DIR,
    DAYS_DIR,
    DOCS_DIR,
    TEMPLATES_DIR,
    load_feeds_config,
    get_settings,
)
from scripts.enrich import generate_landscape_bullets, extract_top_threats
from scripts.utils import (
    load_all_days, list_day_files, load_day,
    format_date_human, format_datetime_local, now_utc,
)
from scripts.scheduler import get_local_today, get_timezone, local_now

logger = logging.getLogger(__name__)


def _paragraphs_filter(text: str) -> Markup:
    if not text:
        return Markup("")
    paras = text.strip().split("\n\n")
    html_parts = []
    for p in paras:
        cleaned = p.strip().replace("\n", " ")
        if cleaned:
            html_parts.append(f"<p>{Markup.escape(cleaned)}</p>")
    return Markup("\n".join(html_parts))


def _group_by_day(articles: list[dict[str, Any]]) -> list[tuple[str, list[dict[str, Any]]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for article in articles:
        grouped[article["day"]].append(article)
    return sorted(grouped.items(), key=lambda x: x[0], reverse=True)


def _collect_all(articles: list[dict[str, Any]], key: str) -> list[str]:
    counter: Counter = Counter()
    for a in articles:
        counter.update(a.get(key, []))
    return [item for item, _ in counter.most_common()]


def _setup_jinja(settings: dict[str, Any]) -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.globals["site_title"] = settings["site_title"]
    env.globals["site_description"] = settings["site_description"]
    env.globals["site_base_url"] = settings.get("site_base_url", "")
    env.filters["paragraphs"] = _paragraphs_filter
    env.filters["human_date"] = format_date_human
    tz = get_timezone()
    env.filters["article_time"] = lambda iso_str: format_datetime_local(iso_str, tz)
    return env


def _copy_static_assets() -> None:
    dst = DOCS_DIR / "assets"
    dst.mkdir(parents=True, exist_ok=True)
    for filename in ("style.css", "app.js"):
        src = TEMPLATES_DIR / filename
        if src.exists():
            shutil.copy2(src, dst / filename)


def _write_last_updated(iso_str: str, human: str, timezone_str: str) -> None:
    """Write site freshness metadata to data/last_updated.json."""
    path = DATA_DIR / "last_updated.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "updated_at_iso": iso_str,
        "updated_at_human": human,
        "timezone": timezone_str,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


def _cleanup_stale_pages(
    valid_article_ids: set[str], valid_days: set[str]
) -> None:
    """Delete generated HTML pages for articles/days no longer in the dataset."""
    articles_dir = DOCS_DIR / "articles"
    if articles_dir.exists():
        deleted = 0
        for f in articles_dir.glob("*.html"):
            if f.stem not in valid_article_ids:
                f.unlink()
                deleted += 1
        if deleted:
            logger.info("Cleaned %d stale article pages", deleted)

    daily_dir = DOCS_DIR / "daily"
    if daily_dir.exists():
        deleted = 0
        for f in daily_dir.glob("*.html"):
            if f.stem not in valid_days:
                f.unlink()
                deleted += 1
        if deleted:
            logger.info("Cleaned %d stale daily pages", deleted)


def generate_site() -> None:
    config = load_feeds_config()
    settings = get_settings(config)
    env = _setup_jinja(settings)

    articles = load_all_days(DAYS_DIR)
    if not articles:
        logger.warning("No articles found -- generating empty site")

    active_days_count = settings.get("active_days", 7)
    all_days_grouped = _group_by_day(articles)
    today = get_local_today()
    today_human = format_date_human(today)

    now_local = local_now()
    last_updated_human = (
        f"{now_local.day} {now_local.strftime('%B')} {now_local.year}, "
        f"{now_local.strftime('%H:%M')}"
    )
    last_updated_iso = now_local.isoformat()
    _write_last_updated(last_updated_iso, last_updated_human, str(get_timezone()))

    active_cutoff = (now_utc() - timedelta(days=active_days_count)).strftime("%Y-%m-%d")
    active_articles = [a for a in articles if a["day"] >= active_cutoff]

    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    (DOCS_DIR / "daily").mkdir(parents=True, exist_ok=True)
    (DOCS_DIR / "articles").mkdir(parents=True, exist_ok=True)
    (DOCS_DIR / "archive").mkdir(parents=True, exist_ok=True)

    _copy_static_assets()

    all_tags = _collect_all(active_articles, "tags")
    all_vendors = _collect_all(active_articles, "vendors")
    all_severities = []
    for sev in ("critical", "high", "medium", "low"):
        if any(a.get("severity") == sev for a in active_articles):
            all_severities.append(sev)

    todays_articles = [a for a in articles if a["day"] == today]
    if not todays_articles and all_days_grouped:
        todays_articles = all_days_grouped[0][1]

    severity_counts: dict[str, int] = {}
    action_count = 0
    for a in todays_articles:
        sev = a.get("severity")
        if sev:
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        if a.get("action_required"):
            action_count += 1

    tz_abbr = now_local.strftime("%Z") or str(get_timezone())

    landscape_bullets = generate_landscape_bullets(todays_articles)

    cutoff_7d = (now_utc() - timedelta(days=7)).strftime("%Y-%m-%d")
    week_articles = [a for a in articles if a["day"] >= cutoff_7d]
    top_threats = extract_top_threats(week_articles)

    # -- Homepage (active articles only) --------------------------------------
    max_homepage = settings["max_articles_per_page"]
    homepage_articles = active_articles[:max_homepage]
    homepage_days = _group_by_day(homepage_articles)

    index_tpl = env.get_template("index.html")
    index_html = index_tpl.render(
        prefix="",
        articles=homepage_articles,
        days_grouped=homepage_days,
        generated_at=today,
        generated_at_human=today_human,
        last_updated_human=last_updated_human,
        last_updated_iso=last_updated_iso,
        timezone_abbr=tz_abbr,
        severity_counts=severity_counts,
        action_count=action_count,
        total_today=len(todays_articles),
        landscape_bullets=landscape_bullets,
        top_threats=top_threats,
        all_tags=all_tags,
        all_vendors=all_vendors,
        all_severities=all_severities,
    )
    (DOCS_DIR / "index.html").write_text(index_html, encoding="utf-8")
    logger.info("Generated docs/index.html with %d articles", len(homepage_articles))

    # -- Daily pages ----------------------------------------------------------
    day_tpl = env.get_template("day.html")
    for day_str, day_articles in all_days_grouped:
        day_tags = _collect_all(day_articles, "tags")
        day_vendors = _collect_all(day_articles, "vendors")
        day_severities = []
        for sev in ("critical", "high", "medium", "low"):
            if any(a.get("severity") == sev for a in day_articles):
                day_severities.append(sev)
        day_bullets = generate_landscape_bullets(day_articles)

        day_html = day_tpl.render(
            prefix="../",
            day=day_str,
            day_human=format_date_human(day_str),
            articles=day_articles,
            landscape_bullets=day_bullets,
            all_tags=day_tags,
            all_vendors=day_vendors,
            all_severities=day_severities,
        )
        (DOCS_DIR / "daily" / f"{day_str}.html").write_text(day_html, encoding="utf-8")
    logger.info("Generated %d daily pages", len(all_days_grouped))

    # -- Individual article pages ---------------------------------------------
    article_tpl = env.get_template("article.html")
    for article in articles:
        sections = article.get("sections", {})
        art_html = article_tpl.render(
            prefix="../",
            article=article,
            sections=sections,
        )
        (DOCS_DIR / "articles" / f"{article['id']}.html").write_text(art_html, encoding="utf-8")
    logger.info("Generated %d individual article pages", len(articles))

    # -- Archive index --------------------------------------------------------
    archive_tpl = env.get_template("archive_index.html")
    day_summaries = []
    for day_str, day_articles in all_days_grouped:
        tag_counter: Counter = Counter()
        sev_counter: Counter = Counter()
        for a in day_articles:
            tag_counter.update(a.get("tags", []))
            s = a.get("severity")
            if s:
                sev_counter[s] += 1
        top_tags = [t for t, _ in tag_counter.most_common(4)]
        top_sev = sev_counter.most_common(1)[0][0] if sev_counter else None
        day_summaries.append({
            "day": day_str,
            "day_human": format_date_human(day_str),
            "count": len(day_articles),
            "top_tags": top_tags,
            "top_severity": top_sev,
        })

    archive_html = archive_tpl.render(prefix="../", days=day_summaries)
    (DOCS_DIR / "archive" / "index.html").write_text(archive_html, encoding="utf-8")
    logger.info("Generated docs/archive/index.html with %d days", len(day_summaries))

    # -- Clean up stale generated pages ---------------------------------------
    valid_ids = {a["id"] for a in articles}
    valid_days = {day_str for day_str, _ in all_days_grouped}
    _cleanup_stale_pages(valid_ids, valid_days)

    logger.info("Site generation complete")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    generate_site()


if __name__ == "__main__":
    sys.exit(main() or 0)
