"""Generate the static GitHub Pages site into docs/.

Produces:
  docs/index.html            — homepage with latest articles grouped by day
  docs/daily/YYYY-MM-DD.html — per-day briefing pages
  docs/articles/{id}.html    — individual article pages with structured sections
  docs/archive/index.html    — archive listing of all days
  docs/assets/style.css      — design system stylesheet
  docs/assets/app.js         — client-side interactions
"""

from __future__ import annotations

import logging
import shutil
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader
from markupsafe import Markup

from scripts.config import (
    ARTICLES_FILE,
    DOCS_DIR,
    TEMPLATES_DIR,
    load_feeds_config,
    get_settings,
)
from scripts.utils import load_json, today_str, format_date_human

logger = logging.getLogger(__name__)


# ── Custom Jinja2 filters ──────────────────────────────────────────

def _paragraphs_filter(text: str) -> Markup:
    """Convert plain text with blank-line separators into HTML paragraphs."""
    if not text:
        return Markup("")
    paras = text.strip().split("\n\n")
    html_parts = []
    for p in paras:
        cleaned = p.strip().replace("\n", " ")
        if cleaned:
            html_parts.append(f"<p>{Markup.escape(cleaned)}</p>")
    return Markup("\n".join(html_parts))


# ── Helpers ─────────────────────────────────────────────────────────

def _group_by_day(articles: list[dict[str, Any]]) -> list[tuple[str, list[dict[str, Any]]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for article in articles:
        grouped[article["day"]].append(article)
    return sorted(grouped.items(), key=lambda x: x[0], reverse=True)


def _collect_tags(articles: list[dict[str, Any]]) -> list[str]:
    counter: Counter = Counter()
    for a in articles:
        counter.update(a.get("tags", []))
    return [tag for tag, _ in counter.most_common()]


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
    return env


def _copy_static_assets() -> None:
    """Copy style.css and app.js from templates/ to docs/assets/."""
    dst = DOCS_DIR / "assets"
    dst.mkdir(parents=True, exist_ok=True)
    for filename in ("style.css", "app.js"):
        src = TEMPLATES_DIR / filename
        if src.exists():
            shutil.copy2(src, dst / filename)
            logger.info("Copied %s → docs/assets/%s", filename, filename)


# ── Site generation ─────────────────────────────────────────────────

def generate_site() -> None:
    config = load_feeds_config()
    settings = get_settings(config)
    env = _setup_jinja(settings)

    articles = load_json(ARTICLES_FILE)
    if not articles:
        logger.warning("No articles found — generating empty site")

    days_grouped = _group_by_day(articles)
    all_days_sorted = [d for d, _ in days_grouped]
    today = today_str()

    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    (DOCS_DIR / "daily").mkdir(parents=True, exist_ok=True)
    (DOCS_DIR / "articles").mkdir(parents=True, exist_ok=True)
    (DOCS_DIR / "archive").mkdir(parents=True, exist_ok=True)

    _copy_static_assets()

    # ── Homepage ─────────────────────────────────────────
    max_articles = settings["max_articles_per_page"]
    homepage_articles = articles[:max_articles]
    homepage_days = _group_by_day(homepage_articles)

    index_tpl = env.get_template("index.html")
    index_html = index_tpl.render(
        prefix="",
        articles=homepage_articles,
        days_grouped=homepage_days,
        generated_at=today,
    )
    (DOCS_DIR / "index.html").write_text(index_html, encoding="utf-8")
    logger.info("Generated docs/index.html with %d articles", len(homepage_articles))

    # ── Daily pages ──────────────────────────────────────
    day_tpl = env.get_template("day.html")
    for day_str, day_articles in days_grouped:
        day_html = day_tpl.render(
            prefix="../",
            day=day_str,
            day_human=format_date_human(day_str),
            articles=day_articles,
        )
        (DOCS_DIR / "daily" / f"{day_str}.html").write_text(day_html, encoding="utf-8")
    logger.info("Generated %d daily pages", len(days_grouped))

    # ── Individual article pages ─────────────────────────
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

    # ── Archive index ────────────────────────────────────
    archive_tpl = env.get_template("archive_index.html")
    day_summaries = []
    for day_str, day_articles in days_grouped:
        tag_counter: Counter = Counter()
        for a in day_articles:
            tag_counter.update(a.get("tags", []))
        top_tags = [t for t, _ in tag_counter.most_common(4)]
        day_summaries.append({
            "day": day_str,
            "count": len(day_articles),
            "top_tags": top_tags,
        })

    archive_html = archive_tpl.render(prefix="../", days=day_summaries)
    (DOCS_DIR / "archive" / "index.html").write_text(archive_html, encoding="utf-8")
    logger.info("Generated docs/archive/index.html")

    logger.info("Site generation complete")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    generate_site()


if __name__ == "__main__":
    sys.exit(main() or 0)
