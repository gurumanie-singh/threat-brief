"""Unified daily pipeline entry point.

Called by the GitHub Actions workflow every 30 minutes. The scheduler
decides whether the current invocation should actually execute based on
the user's configured timezone and the persistent state in state.json.

Flow:
  1. Check schedule gate (timezone + dedup)
  2. Fetch, enrich, merge, group, prune articles
  3. Generate static site + clean stale pages
  4. Mark pipeline run complete in state
  5. Check email gate (dedup)
  6. Send email if not yet sent today
  7. Mark email sent in state
"""

from __future__ import annotations

import logging
import os
import sys

from scripts.scheduler import (
    should_run,
    should_send_email,
    mark_run_complete,
    mark_email_sent,
)
from scripts.process_articles import process
from scripts.generate_site import generate_site
from scripts.send_email import send_email_now

logger = logging.getLogger(__name__)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    force = os.getenv("FORCE_RUN", "").lower() in ("1", "true", "yes")

    run_ok, run_reason = should_run(force=force)
    logger.info("Schedule: %s -- %s", "RUN" if run_ok else "SKIP", run_reason)

    if not run_ok:
        return

    articles = process()
    logger.info("Pipeline: %d articles processed", len(articles))

    generate_site()

    mark_run_complete()

    email_ok, email_reason = should_send_email()
    if email_ok:
        logger.info("Email: sending daily digest...")
        success = send_email_now()
        if success:
            mark_email_sent()
        else:
            logger.warning("Email: send failed -- will retry next eligible run")
    else:
        logger.info("Email: %s", email_reason)

    logger.info("Daily pipeline finished")


if __name__ == "__main__":
    sys.exit(main() or 0)
