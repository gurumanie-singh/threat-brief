"""Send the daily Threat Brief email digest."""

from __future__ import annotations

import logging
import smtplib
import sys
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from scripts.config import (
    ARTICLES_FILE,
    SENT_DIR,
    TEMPLATES_DIR,
    EMAIL_SENDER,
    EMAIL_PASSWORD,
    EMAIL_RECEIVER,
    SMTP_HOST,
    SMTP_PORT,
    load_feeds_config,
    get_settings,
)
from scripts.utils import load_json, today_str

logger = logging.getLogger(__name__)


def _sent_marker(day: str) -> Path:
    return SENT_DIR / f"{day}.sent"


def already_sent_today() -> bool:
    marker = _sent_marker(today_str())
    return marker.exists()


def mark_sent(day: str) -> None:
    SENT_DIR.mkdir(parents=True, exist_ok=True)
    _sent_marker(day).write_text(day, encoding="utf-8")
    logger.info("Marked email as sent for %s", day)


def _build_plain_text(
    articles: list[dict[str, Any]], day: str, base_url: str
) -> str:
    lines = [
        f"THREAT BRIEF — {day}",
        "=" * 44,
        f"{len(articles)} articles from today's cybersecurity landscape.",
        "",
    ]
    for i, a in enumerate(articles, 1):
        summary = a.get("email_summary") or a.get("summary", "")
        severity = a.get("severity")

        lines.append(f"{i}. {a['title']}")
        if severity:
            lines.append(f"   Severity: {severity.upper()}")
        lines.append(f"   {summary[:300]}")
        lines.append(f"   Source: {a['source']}")

        if base_url:
            lines.append(f"   Read more: {base_url}/articles/{a['id']}.html")
        else:
            lines.append(f"   Link: {a['link']}")
        lines.append("")

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
    tpl = env.get_template("email.html")
    return tpl.render(
        articles=articles,
        day=day,
        base_url=settings.get("site_base_url", ""),
        site_title=settings["site_title"],
    )


def send_email() -> bool:
    """Send the daily digest. Returns True on success."""
    day = today_str()

    if already_sent_today():
        logger.info("Email already sent for %s — skipping", day)
        return True

    if not EMAIL_SENDER or not EMAIL_PASSWORD or not EMAIL_RECEIVER:
        logger.error(
            "Missing email credentials. Set EMAIL_SENDER, EMAIL_PASSWORD, "
            "and EMAIL_RECEIVER as environment variables or GitHub Secrets."
        )
        return False

    config = load_feeds_config()
    settings = get_settings(config)
    articles = load_json(ARTICLES_FILE)

    todays = [a for a in articles if a["day"] == day]
    if not todays:
        all_articles = sorted(
            articles, key=lambda a: a["published"], reverse=True
        )
        todays = all_articles[:settings["email_max_articles"]]
        if not todays:
            logger.warning("No articles available to send")
            return False

    todays = todays[:settings["email_max_articles"]]
    base_url = settings.get("site_base_url", "")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"Threat Brief — {day}"
    msg["From"] = EMAIL_SENDER
    msg["To"] = EMAIL_RECEIVER

    plain = _build_plain_text(todays, day, base_url)
    html = _build_html(todays, day, settings)

    msg.attach(MIMEText(plain, "plain", "utf-8"))
    msg.attach(MIMEText(html, "html", "utf-8"))

    try:
        logger.info("Connecting to %s:%d …", SMTP_HOST, SMTP_PORT)
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, [EMAIL_RECEIVER], msg.as_string())
        logger.info("Email sent successfully to %s", EMAIL_RECEIVER)
        mark_sent(day)
        return True
    except smtplib.SMTPException as exc:
        logger.error("SMTP error: %s", exc)
        return False
    except OSError as exc:
        logger.error("Network error: %s", exc)
        return False


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    success = send_email()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
