"""Central configuration loaded from feeds.yaml and environment variables."""

from __future__ import annotations

import os
import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

ROOT_DIR = Path(__file__).resolve().parent.parent
FEEDS_FILE = ROOT_DIR / "feeds.yaml"
DATA_DIR = ROOT_DIR / "data"
ARTICLES_FILE = DATA_DIR / "articles.json"
ARCHIVE_DIR = DATA_DIR / "archive"
SENT_DIR = DATA_DIR / "sent"
TEMPLATES_DIR = ROOT_DIR / "templates"
DOCS_DIR = ROOT_DIR / "docs"

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
EMAIL_SENDER = os.getenv("EMAIL_SENDER", "")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")
EMAIL_RECEIVER = os.getenv("EMAIL_RECEIVER", "")


def load_feeds_config() -> dict[str, Any]:
    """Load and validate feeds.yaml, returning the full config dict."""
    if not FEEDS_FILE.exists():
        raise FileNotFoundError(f"Feed config not found: {FEEDS_FILE}")

    with open(FEEDS_FILE, "r", encoding="utf-8") as fh:
        config = yaml.safe_load(fh)

    if not config or "feeds" not in config:
        raise ValueError("feeds.yaml must contain a 'feeds' key with at least one entry")

    feeds = config["feeds"]
    if not isinstance(feeds, list) or len(feeds) == 0:
        raise ValueError("feeds.yaml 'feeds' must be a non-empty list")

    for feed in feeds:
        if "url" not in feed or "name" not in feed:
            raise ValueError(f"Each feed entry needs 'name' and 'url': {feed}")

    return config


def get_settings(config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the settings block with defaults applied."""
    defaults = {
        "max_article_age_days": 7,
        "max_articles_per_page": 50,
        "email_max_articles": 15,
        "site_title": "Threat Brief",
        "site_description": "Daily cybersecurity news aggregator",
        "site_base_url": "",
    }
    if config is None:
        config = load_feeds_config()
    settings = config.get("settings", {})
    return {**defaults, **(settings or {})}


def get_tag_keywords(config: dict[str, Any] | None = None) -> dict[str, list[str]]:
    """Return tag→keywords mapping from config."""
    if config is None:
        config = load_feeds_config()
    return config.get("tag_keywords", {})
