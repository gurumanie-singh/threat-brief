"""Shared utility functions: hashing, date helpers, JSON I/O, text cleaning."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

logger = logging.getLogger(__name__)


# ── Text normalisation ──────────────────────────────────────────────

def normalize_text(text: str) -> str:
    """Lowercase, strip accents, collapse whitespace."""
    text = unicodedata.normalize("NFKD", text)
    text = text.encode("ascii", "ignore").decode("ascii")
    text = text.lower().strip()
    text = re.sub(r"\s+", " ", text)
    return text


def normalize_url(url: str) -> str:
    """Strip query params, fragments, and trailing slashes for dedup."""
    parsed = urlparse(url)
    clean = urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", ""))
    return clean.lower()


def article_id(title: str, link: str) -> str:
    """Stable deduplication hash from normalised title + canonical link."""
    key = normalize_text(title) + "|" + normalize_url(link)
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


# ── HTML cleaning ───────────────────────────────────────────────────

_TAG_RE = re.compile(r"<[^>]+>")
_ENTITY_MAP = {
    "&amp;": "&", "&lt;": "<", "&gt;": ">",
    "&quot;": '"', "&apos;": "'", "&nbsp;": " ",
    "&#39;": "'", "&#x27;": "'", "&#34;": '"',
}
_ENTITY_RE = re.compile(r"&[#\w]+;")


def _replace_entity(match: re.Match) -> str:
    return _ENTITY_MAP.get(match.group(0), " ")


def strip_html(text: str) -> str:
    """Remove HTML tags and common entities, returning clean plain text."""
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"</p>", "\n\n", text, flags=re.IGNORECASE)
    text = re.sub(r"</li>", "\n", text, flags=re.IGNORECASE)
    text = _TAG_RE.sub(" ", text)
    text = _ENTITY_RE.sub(_replace_entity, text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def truncate(text: str, max_chars: int = 280) -> str:
    """Truncate text to max_chars, breaking at word boundary."""
    if len(text) <= max_chars:
        return text
    truncated = text[:max_chars].rsplit(" ", 1)[0]
    return truncated.rstrip(".,;:!?") + "…"


# ── Date helpers ────────────────────────────────────────────────────

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def today_str() -> str:
    return now_utc().strftime("%Y-%m-%d")


def format_date_human(date_str: str) -> str:
    """Convert 'YYYY-MM-DD' to 'April 15, 2026' style."""
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%d")
        return dt.strftime("%B %-d, %Y")
    except (ValueError, AttributeError):
        return date_str


def parse_date(date_str: str | None) -> datetime:
    """Best-effort date parse; falls back to now."""
    if not date_str:
        return now_utc()
    from dateutil import parser as dateutil_parser
    try:
        dt = dateutil_parser.parse(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, OverflowError):
        logger.warning("Unparseable date '%s', using now", date_str)
        return now_utc()


# ── JSON I/O ────────────────────────────────────────────────────────

def load_json(path: Path) -> list[dict[str, Any]]:
    """Load a JSON file, returning [] on missing or corrupt file."""
    if not path.exists():
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to load %s: %s", path, exc)
        return []


def save_json(path: Path, data: list[dict[str, Any]]) -> None:
    """Atomically write JSON list to path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str, ensure_ascii=False)
        fh.write("\n")
    tmp.replace(path)
