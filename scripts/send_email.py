"""Send the daily Threat Brief email digest, structured by severity tiers.

Duplicate prevention is handled by the scheduler's state.json. This module
exposes two entry points:
  - send_email_now()  -- send unconditionally (called by run_daily.py after gate check)
  - send_email()      -- standalone entry with its own dedup check (backward compat)
"""

from __future__ import annotations

import logging
import smtplib
import sys
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

from jinja2 import Environment, FileSystemLoader

from scripts.config import (
    DAYS_DIR,
    TEMPLATES_DIR,
    EMAIL_SENDER,
    EMAIL_PASSWORD,
    EMAIL_RECEIVER,
    SMTP_HOST,
    SMTP_PORT,
    load_feeds_config,
    get_settings,
    get_personalization,
)
from scripts.enrich import generate_landscape_bullets
from scripts.scheduler import get_local_today, should_send_email, mark_email_sent
from scripts.utils import load_day, load_all_days, format_date_human

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_SEVERITY_LABEL = {"critical": "[!!]", "high": "[!]", "medium": "[--]", "low": "[i]"}


def _bucket_by_severity(articles: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    buckets: dict[str, list[dict[str, Any]]] = {
        "critical": [], "high": [], "medium": [], "other": [],
    }
    for a in articles:
        sev = a.get("severity", "")
        if sev in buckets:
            buckets[sev].append(a)
        else:
            buckets["other"].append(a)
    return buckets


def _build_plain_text(
    articles: list[dict[str, Any]], day: str, base_url: str
) -> str:
    day_human = format_date_human(day)
    bullets = generate_landscape_bullets(articles)
    lines = [
        f"THREAT BRIEF -- {day_human}",
        "=" * 44,
    ]
    if bullets:
        lines.append("")
        lines.append("TODAY'S LANDSCAPE:")
        for b in bullets:
            lines.append(f"  - {b}")
    lines.append("")
    lines.append(f"{len(articles)} articles from today's cybersecurity landscape.")
    lines.append("")

    buckets = _bucket_by_severity(articles)
    idx = 1
    for label, key in [
        (f"{_SEVERITY_LABEL['critical']} CRITICAL", "critical"),
        (f"{_SEVERITY_LABEL['high']} HIGH", "high"),
        (f"{_SEVERITY_LABEL['medium']} MEDIUM", "medium"),
        ("OTHER", "other"),
    ]:
        items = buckets[key]
        if not items:
            continue
        lines.append(f"--- {label} ---")
        lines.append("")
        for a in items:
            summary = a.get("email_summary") or a.get("summary", "")
            action = " [ACTION REQUIRED]" if a.get("action_required") else ""
            lines.append(f"{idx}. {a['title']}{action}")
            vendors = a.get("vendors", [])
            if vendors:
                lines.append(f"   Vendors: {', '.join(vendors)}")
            lines.append(f"   {summary[:300]}")
            lines.append(f"   Source: {a['source']}")
            if base_url:
                lines.append(f"   Read more: {base_url}/articles/{a['id']}.html")
            else:
                lines.append(f"   Link: {a['link']}")
            lines.append("")
            idx += 1

    if base_url:
        lines.extend(["", f"Full briefing: {base_url}/daily/{day}.html"])
    return "\n".join(lines)


def _build_html(
    articles: list[dict[str, Any]], day: str, settings: dict[str, Any]
) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=True,
    )
    env.filters["human_date"] = format_date_human
    buckets = _bucket_by_severity(articles)
    bullets = generate_landscape_bullets(articles)
    tpl = env.get_template("email.html")
    return tpl.render(
        articles=articles,
        day=day,
        day_human=format_date_human(day),
        base_url=settings.get("site_base_url", ""),
        site_title=settings["site_title"],
        buckets=buckets,
        landscape_bullets=bullets,
    )


def _do_send(articles: list[dict[str, Any]], day: str, settings: dict[str, Any]) -> bool:
    """Actually connect and send the email."""
    if not EMAIL_SENDER or not EMAIL_PASSWORD or not EMAIL_RECEIVER:
        logger.error(
            "Missing email credentials. Set EMAIL_SENDER, EMAIL_PASSWORD, "
            "and EMAIL_RECEIVER as environment variables or GitHub Secrets."
        )
        return False

    base_url = settings.get("site_base_url", "")
    day_human = format_date_human(day)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"Threat Brief -- {day_human}"
    msg["From"] = EMAIL_SENDER
    msg["To"] = EMAIL_RECEIVER

    plain = _build_plain_text(articles, day, base_url)
    html = _build_html(articles, day, settings)

    msg.attach(MIMEText(plain, "plain", "utf-8"))
    msg.attach(MIMEText(html, "html", "utf-8"))

    try:
        logger.info("Connecting to %s:%d ...", SMTP_HOST, SMTP_PORT)
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, [EMAIL_RECEIVER], msg.as_string())
        logger.info("Email sent successfully to %s", EMAIL_RECEIVER)
        return True
    except smtplib.SMTPException as exc:
        logger.error("SMTP error: %s", exc)
        return False
    except OSError as exc:
        logger.error("Network error: %s", exc)
        return False


def _prepare_articles(day: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Load and filter articles for the given day."""
    config = load_feeds_config()
    settings = get_settings(config)
    personalization = get_personalization(config)

    todays = load_day(DAYS_DIR, day)
    if not todays:
        all_articles = load_all_days(DAYS_DIR)
        todays = sorted(all_articles, key=lambda a: a.get("published", ""), reverse=True)
        todays = todays[:settings["email_max_articles"]]

    if not todays:
        return [], settings

    min_sev = personalization.get("email_min_severity", "")
    if min_sev and min_sev in _SEVERITY_ORDER:
        threshold = _SEVERITY_ORDER[min_sev]
        todays = [a for a in todays if _SEVERITY_ORDER.get(a.get("severity", ""), 99) <= threshold]

    todays = sorted(todays, key=lambda a: _SEVERITY_ORDER.get(a.get("severity", ""), 99))
    todays = todays[:settings["email_max_articles"]]
    return todays, settings


def send_email_now() -> bool:
    """Send the daily email unconditionally (no dedup check).

    Called by run_daily.py which has already verified via scheduler.should_send_email().
    """
    day = get_local_today()
    articles, settings = _prepare_articles(day)
    if not articles:
        logger.warning("No articles available to send")
        return False
    return _do_send(articles, day, settings)


def send_email() -> bool:
    """Standalone entry: checks state-based dedup, then sends.

    Used when calling `python -m scripts.send_email` directly.
    """
    ok, reason = should_send_email()
    if not ok:
        logger.info("Email skip: %s", reason)
        return True

    day = get_local_today()
    articles, settings = _prepare_articles(day)
    if not articles:
        logger.warning("No articles available to send")
        return False

    success = _do_send(articles, day, settings)
    if success:
        mark_email_sent()
    return success


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    success = send_email()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
