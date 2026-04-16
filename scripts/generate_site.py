"""Generate the static GitHub Pages site into docs/."""

from __future__ import annotations

import logging
import shutil
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from scripts.config import (
    ARTICLES_FILE,
    DOCS_DIR,
    TEMPLATES_DIR,
    load_feeds_config,
    get_settings,
)
from scripts.utils import load_json, today_str

logger = logging.getLogger(__name__)


def _group_by_day(articles: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for article in articles:
        grouped[article["day"]].append(article)
    return dict(sorted(grouped.items(), reverse=True))


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
    return env


def _copy_static_assets() -> None:
    """Ensure docs/assets/ has the CSS and JS files."""
    assets_src = TEMPLATES_DIR  # We generate assets separately; nothing to copy.
    assets_dst = DOCS_DIR / "assets"
    assets_dst.mkdir(parents=True, exist_ok=True)


def generate_site() -> None:
    """Main site generation: index, daily pages, archive index."""
    config = load_feeds_config()
    settings = get_settings(config)
    env = _setup_jinja(settings)

    articles = load_json(ARTICLES_FILE)
    if not articles:
        logger.warning("No articles found — generating empty site")

    days = _group_by_day(articles)
    today = today_str()
    all_days_sorted = sorted(days.keys(), reverse=True)

    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    (DOCS_DIR / "daily").mkdir(parents=True, exist_ok=True)
    (DOCS_DIR / "archive").mkdir(parents=True, exist_ok=True)
    _copy_static_assets()

    # ── index.html (latest headlines) ────────────────────────────
    max_articles = settings["max_articles_per_page"]
    latest_articles = articles[:max_articles]
    index_tpl = env.get_template("index.html")
    index_html = index_tpl.render(
        articles=latest_articles,
        today=today,
        days=all_days_sorted[:30],
        generated_at=today,
    )
    (DOCS_DIR / "index.html").write_text(index_html, encoding="utf-8")
    logger.info("Generated docs/index.html with %d articles", len(latest_articles))

    # ── daily pages ──────────────────────────────────────────────
    day_tpl = env.get_template("day.html")
    for day_str, day_articles in days.items():
        day_html = day_tpl.render(
            day=day_str,
            articles=day_articles,
            days=all_days_sorted[:30],
        )
        (DOCS_DIR / "daily" / f"{day_str}.html").write_text(day_html, encoding="utf-8")
    logger.info("Generated %d daily pages", len(days))

    # ── archive index ────────────────────────────────────────────
    archive_tpl = env.get_template("archive_index.html")
    day_summaries = [
        {"day": d, "count": len(days[d])} for d in all_days_sorted
    ]
    archive_html = archive_tpl.render(days=day_summaries)
    (DOCS_DIR / "archive" / "index.html").write_text(archive_html, encoding="utf-8")
    logger.info("Generated docs/archive/index.html")

    # ── write style.css and app.js ───────────────────────────────
    _write_css()
    _write_js()

    logger.info("Site generation complete")


def _write_css() -> None:
    css = (DOCS_DIR / "assets" / "style.css")
    css.write_text(CSS_CONTENT, encoding="utf-8")


def _write_js() -> None:
    js = (DOCS_DIR / "assets" / "app.js")
    js.write_text(JS_CONTENT, encoding="utf-8")


# ── Inline CSS ──────────────────────────────────────────────────────

CSS_CONTENT = """\
:root {
  --bg: #0f1117;
  --surface: #1a1d27;
  --border: #2a2d3a;
  --text: #e2e4ea;
  --text-muted: #8b8fa3;
  --accent: #6c72cb;
  --accent-light: #8f94e8;
  --tag-bg: #252836;
  --tag-text: #a5a9c4;
  --danger: #e85d6f;
  --success: #4ecdc4;
  --radius: 8px;
  --max-w: 860px;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
}

a { color: var(--accent-light); text-decoration: none; }
a:hover { text-decoration: underline; }

.container { max-width: var(--max-w); margin: 0 auto; padding: 0 1.25rem; }

/* Header */
header {
  border-bottom: 1px solid var(--border);
  padding: 1.5rem 0;
  margin-bottom: 2rem;
}
header .container { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 0.75rem; }
header h1 { font-size: 1.5rem; font-weight: 700; letter-spacing: -0.02em; }
header h1 span { color: var(--accent-light); }
header nav a { margin-left: 1.25rem; font-size: 0.9rem; color: var(--text-muted); }
header nav a:hover { color: var(--text); }

/* Day heading */
.day-heading {
  font-size: 0.85rem;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin: 2rem 0 1rem;
  padding-bottom: 0.5rem;
  border-bottom: 1px solid var(--border);
}

/* Article card */
.article-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1.25rem;
  margin-bottom: 0.75rem;
  transition: border-color 0.15s;
}
.article-card:hover { border-color: var(--accent); }
.article-card h3 { font-size: 1.05rem; font-weight: 600; margin-bottom: 0.35rem; line-height: 1.35; }
.article-card h3 a { color: var(--text); }
.article-card h3 a:hover { color: var(--accent-light); text-decoration: none; }
.article-meta { font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.5rem; }
.article-meta .source { font-weight: 500; }
.article-summary { font-size: 0.92rem; color: var(--text-muted); line-height: 1.55; }

/* Tags */
.tags { display: flex; flex-wrap: wrap; gap: 0.35rem; margin-top: 0.6rem; }
.tag {
  font-size: 0.7rem;
  background: var(--tag-bg);
  color: var(--tag-text);
  padding: 0.15rem 0.55rem;
  border-radius: 3px;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

/* Sidebar / day list */
.day-list { list-style: none; }
.day-list li { margin-bottom: 0.3rem; }
.day-list a { font-size: 0.88rem; color: var(--text-muted); }
.day-list a:hover { color: var(--text); }

/* Archive table */
.archive-table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
.archive-table th, .archive-table td { text-align: left; padding: 0.6rem 0.75rem; border-bottom: 1px solid var(--border); }
.archive-table th { font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.05em; }
.archive-table td { font-size: 0.92rem; }

/* Layout */
.layout { display: grid; grid-template-columns: 1fr 200px; gap: 2rem; }
.layout .sidebar { position: sticky; top: 1rem; align-self: start; }
.sidebar h4 { font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.06em; margin-bottom: 0.6rem; }

@media (max-width: 700px) {
  .layout { grid-template-columns: 1fr; }
  .layout .sidebar { display: none; }
}

/* Footer */
footer {
  margin-top: 3rem;
  padding: 1.5rem 0;
  border-top: 1px solid var(--border);
  text-align: center;
  font-size: 0.8rem;
  color: var(--text-muted);
}

/* Filter bar */
.filter-bar { margin-bottom: 1.5rem; display: flex; flex-wrap: wrap; gap: 0.4rem; }
.filter-btn {
  font-size: 0.75rem;
  padding: 0.3rem 0.7rem;
  border-radius: 3px;
  border: 1px solid var(--border);
  background: transparent;
  color: var(--text-muted);
  cursor: pointer;
  transition: all 0.15s;
}
.filter-btn:hover, .filter-btn.active { background: var(--accent); color: #fff; border-color: var(--accent); }
"""


JS_CONTENT = """\
document.addEventListener("DOMContentLoaded", () => {
  const buttons = document.querySelectorAll(".filter-btn");
  const cards = document.querySelectorAll(".article-card");

  buttons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const tag = btn.dataset.tag;

      if (btn.classList.contains("active")) {
        btn.classList.remove("active");
        cards.forEach((c) => (c.style.display = ""));
        return;
      }

      buttons.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");

      cards.forEach((card) => {
        const cardTags = (card.dataset.tags || "").split(",");
        card.style.display = cardTags.includes(tag) ? "" : "none";
      });
    });
  });
});
"""


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    generate_site()


if __name__ == "__main__":
    sys.exit(main() or 0)
