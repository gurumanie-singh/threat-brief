# Threat Brief

**Automated daily cybersecurity intelligence briefing.**

Threat Brief aggregates headlines from top cybersecurity RSS feeds, enriches each article with structured analysis sections, publishes a premium editorial-style static site to GitHub Pages, and sends a single daily email digest -- all powered by a single GitHub Actions workflow with zero servers and zero cost.

---

## How It Works

```
RSS Feeds
    |
    v
+---------------+     +-------------+     +-----------------+
|  fetch_feeds  |---->|   enrich    |---->| process_articles |
|  (feedparser) |     | (sections,  |     |  (merge, dedup,  |
|               |     |  severity,  |     |   prune, save)   |
|               |     |  CVEs)      |     |                  |
+---------------+     +-------------+     +--------+--------+
                                                   |
                                                   v
                                           data/articles.json
                                                   |
                         +-------------------------+----------------+
                         v                         v                v
                 +---------------+        +--------------+   +----------+
                 | generate_site |        |  send_email  |   |  archive |
                 | (Jinja2->HTML)|        |  (SMTP)      |   |  (JSON)  |
                 +-------+-------+        +--------------+   +----------+
                         |
                         v
                   docs/ (GitHub Pages)
                     index.html
                     articles/{id}.html
                     daily/{date}.html
                     archive/index.html
```

### Scheduling Architecture

```
GitHub Actions cron (every 30 min, UTC)
    |
    v
run_daily.py
    |
    +--> scheduler.should_run()
    |      |
    |      +--> Load timezone from feeds.yaml
    |      +--> Convert current UTC to user's local time
    |      +--> Check: is it 07:00-07:59 local?
    |      +--> Check: already ran today? (state.json)
    |      |
    |      +--> YES -> run pipeline
    |      +--> NO  -> exit cleanly (zero work done)
    |
    +--> process_articles.process()
    +--> generate_site.generate_site()
    +--> mark_run_complete() -> state.json
    |
    +--> scheduler.should_send_email()
    |      +--> Check state.json for last_email_date
    |
    +--> send_email_now() (if not already sent)
    +--> mark_email_sent() -> state.json
```

### Data Lifecycle

| Age        | Location            | Visibility                   |
|------------|---------------------|------------------------------|
| 0-7 days   | data/articles.json  | Homepage (active articles)   |
| 7-30 days  | data/articles.json  | Archive pages + daily pages  |
| >30 days   | Deleted             | Automatically cleaned up     |

### Content Enrichment Pipeline

Each article goes through deterministic enrichment (no paid APIs):

1. **Full content extraction** -- captures the richest content from each RSS entry
2. **CVE detection** -- regex extraction of CVE identifiers
3. **CVSS scoring** -- detects CVSS scores when present
4. **Severity inference** -- critical / high / medium / low based on CVSS, keywords, context
5. **Structured sections** -- Overview, Technical Details, Impact, Mitigation, Additional Context
6. **Email summary** -- concise 2-4 sentence summary
7. **Vendor detection** -- auto-tags Microsoft, Cisco, AWS, etc.
8. **Action required** -- flags articles needing immediate response
9. **Story grouping** -- clusters related articles from multiple sources

---

## Repository Structure

```
threat-brief/
+-- .github/workflows/
|   +-- threat-brief.yml            # Unified: runs every 30min, Python decides
+-- scripts/
|   +-- __init__.py
|   +-- config.py                   # Central config from feeds.yaml + env vars
|   +-- utils.py                    # Hashing, dates, JSON I/O, text cleaning
|   +-- enrich.py                   # Content enrichment: sections, severity, CVEs
|   +-- fetch_feeds.py              # RSS fetcher with full content extraction
|   +-- process_articles.py         # Merge, enrich, dedup, prune, archive, cleanup
|   +-- generate_site.py            # Static site generator (Jinja2 -> docs/)
|   +-- send_email.py               # Daily email sender (SMTP)
|   +-- scheduler.py                # Timezone-aware execution gate + state
|   +-- run_daily.py                # Unified pipeline entry point
+-- templates/
|   +-- base.html                   # Shared layout (nav, footer, fonts, assets)
|   +-- index.html                  # Homepage with day-grouped article cards
|   +-- day.html                    # Daily briefing page
|   +-- article.html                # Individual article page with sections
|   +-- archive_index.html          # Archive listing with day cards
|   +-- email.html                  # HTML email template
|   +-- style.css                   # Design system stylesheet
|   +-- app.js                      # Theme toggle, filters, scroll reveal
+-- data/
|   +-- articles.json               # All articles (0-30 day retention)
|   +-- archive/                    # Daily JSON snapshots (auto-cleaned >30 days)
|   +-- state.json                  # Scheduling + email state tracking
|   +-- sent/                       # Legacy email markers (deprecated)
+-- docs/                           # GitHub Pages root
|   +-- index.html
|   +-- articles/                   # Individual article pages
|   +-- daily/                      # Per-day briefing pages
|   +-- archive/index.html
|   +-- assets/
|       +-- style.css
|       +-- app.js
+-- feeds.yaml                      # Feeds, tags, vendors, timezone, settings
+-- requirements.txt
+-- LICENSE
+-- README.md
```

---

## Quick Start

### 1. Fork or Clone

```bash
git clone https://github.com/YOUR_USERNAME/threat-brief.git
cd threat-brief
```

### 2. Configure Your Timezone

Edit `feeds.yaml`:

```yaml
settings:
  timezone: "America/Chicago"  # Your IANA timezone
```

The pipeline will run at 07:00 in your local timezone. Common examples:

| Timezone              | Morning run |
|-----------------------|-------------|
| America/New_York      | 07:00 ET    |
| America/Chicago       | 07:00 CT    |
| America/Los_Angeles   | 07:00 PT    |
| Europe/London         | 07:00 GMT   |
| Asia/Tokyo            | 07:00 JST   |

### 3. Add GitHub Secrets

Go to **Settings -> Secrets and variables -> Actions -> New repository secret** and add:

| Secret | Description |
|---|---|
| `EMAIL_SENDER` | Gmail address to send from (e.g. `you@gmail.com`) |
| `EMAIL_PASSWORD` | Gmail **App Password** (not your login password -- see below) |
| `EMAIL_RECEIVER` | Recipient email address |

Optional (defaults to Gmail):

| Secret | Default |
|---|---|
| `SMTP_HOST` | `smtp.gmail.com` |
| `SMTP_PORT` | `587` |

### 4. Enable GitHub Pages

1. **Settings -> Pages**
2. Source: **Deploy from a branch**
3. Branch: `main`, Folder: `/docs`
4. **Save**

Site will be live at `https://YOUR_USERNAME.github.io/threat-brief/`

### 5. Update `site_base_url`

Edit `feeds.yaml`:

```yaml
settings:
  site_base_url: "https://YOUR_USERNAME.github.io/threat-brief"
```

This makes email "Read more" links point to your hosted article pages.

### 6. Trigger the First Run

1. Go to **Actions** tab
2. Click **Threat Brief Daily Pipeline** -> **Run workflow**
3. Check **Force a full pipeline run** to bypass the time-window check
4. Click **Run workflow**

Within minutes, your site will show live cybersecurity news.

---

## Scheduling and Timezone

### How It Works

The GitHub Actions workflow runs **every 30 minutes** using UTC cron. Inside Python:

1. `scheduler.py` loads the timezone from `feeds.yaml`
2. Converts the current UTC time to the user's local time
3. Checks if the local time is between **07:00 and 07:59**
4. Checks `data/state.json` to see if today's run already completed
5. If both conditions pass -> full pipeline executes
6. Otherwise -> clean exit (no work done, no git commit)

### Duplicate Prevention

`data/state.json` tracks:

```json
{
  "last_run_date": "2026-04-15",
  "last_run_iso": "2026-04-15T07:23:00-05:00",
  "last_email_date": "2026-04-15",
  "last_email_iso": "2026-04-15T07:23:05-05:00",
  "timezone": "America/Chicago"
}
```

Even if GitHub Actions fires multiple times within the 07:00 hour, only the first successful execution counts. Subsequent runs within the same local date are skipped.

### Edge Cases Handled

- **Missing state.json** -- starts fresh, runs immediately if in window
- **Corrupt state.json** -- logs warning, treats as fresh state
- **Manual workflow_dispatch** -- set "Force run" to bypass time window (still respects daily dedup)
- **Delayed GitHub Actions** -- the 60-minute window (07:00-07:59) accommodates late starts
- **DST transitions** -- uses `zoneinfo` which handles DST correctly
- **Partial failure** -- if email fails but site generated, run is marked complete; email retries next eligible run

---

## Data Lifecycle

### Retention Rules

| Setting             | Default | Purpose                        |
|---------------------|---------|--------------------------------|
| `active_days`       | 7       | Days shown on homepage         |
| `max_retention_days`| 30      | Days before automatic deletion |

### Automatic Cleanup

On every pipeline run:

1. Articles older than `max_retention_days` are removed from `articles.json`
2. Archive JSON files (in `data/archive/`) older than 30 days are deleted
3. Generated HTML pages for deleted articles are removed from `docs/articles/`
4. Generated daily pages for empty dates are removed from `docs/daily/`

This keeps the repository small and prevents unbounded data growth.

---

## Gmail App Password Setup

**Never use your normal Gmail password.**

1. Go to [myaccount.google.com](https://myaccount.google.com/)
2. **Security -> 2-Step Verification** (enable if needed)
3. **Security -> App passwords**
4. Select **Mail**, enter "Threat Brief"
5. Copy the 16-character password
6. Use this as your `EMAIL_PASSWORD` GitHub Secret

---

## Customizing Feeds

Edit `feeds.yaml` to add/remove RSS feeds:

```yaml
feeds:
  - name: My Custom Feed
    url: https://example.com/rss.xml
```

### Tag Keywords

Articles are auto-tagged when keywords appear in their title or content:

```yaml
tag_keywords:
  my-tag:
    - keyword one
    - keyword two
```

### Vendor Keywords

Detect vendors/technologies automatically:

```yaml
vendor_keywords:
  MyVendor:
    - myvendor
    - product-name
```

---

## Date Format

All dates use the format **15 April 2026** consistently across:
- Website (homepage, article pages, daily pages, archive)
- Email (subject line, header, body)
- Internal state uses ISO 8601 (`YYYY-MM-DD`, `YYYY-MM-DDTHH:MM:SS±HH:MM`)

---

## How Deduplication Works

Each article gets a stable ID:

```
SHA-256( normalize(title) + "|" + canonicalize(url) )[:16]
```

Title normalization strips accents, lowercases, and collapses whitespace. URL canonicalization removes query params, fragments, and trailing slashes.

Additionally, story grouping uses Jaccard similarity on titles and shared CVE references to cluster related articles from different sources.

---

## Article Page Structure

Each article gets a dedicated page with:

1. **Header** -- title, source, date, severity badge, tags, CVE references
2. **Overview** -- what happened and why it matters
3. **Technical Details** -- vulnerability type, attack method, CVE details
4. **Impact** -- who's affected, severity assessment, CVSS score
5. **Mitigation** -- patches, workarounds, defensive actions
6. **Additional Context** -- threat landscape trends, related incidents
7. **Source Link** -- external link to the original article

---

## Local Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Check schedule status
python3 -m scripts.scheduler

# Force a full pipeline run (bypasses time-window)
FORCE_RUN=true python3 -m scripts.run_daily

# Run individual steps
python3 -m scripts.process_articles     # Fetch + enrich + save
python3 -m scripts.generate_site        # Generate from existing data

# Preview
cd docs && python3 -m http.server 8000
# Open http://localhost:8000
```

### Test email locally

```bash
export EMAIL_SENDER="you@gmail.com"
export EMAIL_PASSWORD="your-app-password"
export EMAIL_RECEIVER="recipient@example.com"
python3 -m scripts.send_email
```

---

## Manually Triggering Workflows

1. **Actions** tab -> **Threat Brief Daily Pipeline**
2. Click **Run workflow**
3. Check **Force a full pipeline run** to bypass time-window
4. Click **Run workflow**

---

## Troubleshooting

| Problem | Solution |
|---|---|
| Actions not running | Settings -> Actions -> General -> Allow all actions |
| Pipeline skipping | Check `python3 -m scripts.scheduler` output. Verify timezone. Use force run. |
| Email not sending | Verify secrets. Check logs for SMTP errors. Use Gmail App Password. |
| Pages 404 | Set Pages source to `main` / `/docs`. Wait a few minutes. |
| No articles | Trigger workflow with force run. Check logs for feed errors. |
| Old articles not pruning | Adjust `max_retention_days` in feeds.yaml |
| Wrong timezone | Edit `timezone` in feeds.yaml. Use IANA format. |

---

## Security Notes

- No credentials in code -- all secrets stored in GitHub Secrets
- App passwords only -- never use primary account passwords
- Article data is public -- no sensitive information stored
- Workflows request only `contents: write` permission

---

## License

[MIT](LICENSE)
