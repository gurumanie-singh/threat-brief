# Threat Brief

**Automated daily cybersecurity intelligence briefing.**

Threat Brief aggregates headlines from top cybersecurity RSS feeds, enriches each article with structured analysis sections, publishes a premium editorial-style static site to GitHub Pages (updated every 2 hours), and sends a single daily email digest — all powered by GitHub Actions with zero servers and zero cost.

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

### Content Enrichment Pipeline

Each article goes through deterministic enrichment (no paid APIs):

1. **Full content extraction** — captures the richest content available from each RSS entry
2. **CVE detection** — regex extraction of CVE identifiers from title and content
3. **CVSS scoring** — detects CVSS scores when present in text
4. **Severity inference** — classifies as critical / high / medium / low based on CVSS scores, keywords, and context
5. **Structured sections** — generates Overview, Technical Details, Impact, Mitigation, and Additional Context by classifying sentences and supplementing with tag-based analysis
6. **Email summary** — produces a concise 2-4 sentence summary stating what happened, what's affected, and the severity

---

## Repository Structure

```
threat-brief/
├── .github/workflows/
│   ├── update-site.yml           # Every 2 hours: fetch -> enrich -> generate -> deploy
│   └── daily-email.yml           # Once daily: fetch -> enrich -> email
├── scripts/
│   ├── __init__.py
│   ├── config.py                 # Central config from feeds.yaml + env vars
│   ├── utils.py                  # Hashing, dates, JSON I/O, text cleaning
│   ├── enrich.py                 # Content enrichment: sections, severity, CVEs
│   ├── fetch_feeds.py            # RSS fetcher with full content extraction
│   ├── process_articles.py       # Merge, enrich, dedup, prune, archive
│   ├── generate_site.py          # Static site generator (Jinja2 -> docs/)
│   └── send_email.py             # Daily email sender (SMTP)
├── templates/
│   ├── base.html                 # Shared layout (nav, footer, fonts, assets)
│   ├── index.html                # Homepage with day-grouped article cards
│   ├── day.html                  # Daily briefing page
│   ├── article.html              # Individual article page with sections
│   ├── archive_index.html        # Archive listing with day cards
│   ├── email.html                # HTML email template
│   ├── style.css                 # Design system stylesheet
│   └── app.js                    # Theme toggle, filters, scroll reveal
├── data/
│   ├── articles.json             # Current article database (enriched)
│   ├── archive/                  # Daily JSON snapshots
│   └── sent/                     # Email sent markers
├── docs/                         # GitHub Pages root
│   ├── index.html                # Homepage
│   ├── articles/                 # Individual article pages
│   ├── daily/                    # Per-day briefing pages
│   ├── archive/index.html        # Archive
│   └── assets/
│       ├── style.css
│       └── app.js
├── feeds.yaml                    # Feeds, tag keywords, settings
├── requirements.txt
├── LICENSE
└── README.md
```

---

## Quick Start

### 1. Fork or Clone

```bash
git clone https://github.com/YOUR_USERNAME/threat-brief.git
cd threat-brief
```

### 2. Add GitHub Secrets

Go to **Settings -> Secrets and variables -> Actions -> New repository secret** and add:

| Secret | Description |
|---|---|
| `EMAIL_SENDER` | Gmail address to send from (e.g. `you@gmail.com`) |
| `EMAIL_PASSWORD` | Gmail **App Password** (not your login password — see below) |
| `EMAIL_RECEIVER` | Recipient email address |

Optional (defaults to Gmail):

| Secret | Default |
|---|---|
| `SMTP_HOST` | `smtp.gmail.com` |
| `SMTP_PORT` | `587` |

### 3. Enable GitHub Pages

1. **Settings -> Pages**
2. Source: **Deploy from a branch**
3. Branch: `main`, Folder: `/docs`
4. **Save**

Site will be live at `https://YOUR_USERNAME.github.io/threat-brief/`

### 4. Update `site_base_url`

Edit `feeds.yaml`:

```yaml
settings:
  site_base_url: "https://YOUR_USERNAME.github.io/threat-brief"
```

This makes email "Read more" links point to your hosted article pages.

### 5. Trigger the First Run

1. Go to **Actions** tab
2. Click **Update Site** -> **Run workflow**

Within minutes, your site will show live cybersecurity news with full article pages.

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

---

## How Deduplication Works

Each article gets a stable ID:

```
SHA-256( normalize(title) + "|" + canonicalize(url) )[:16]
```

Title normalization strips accents, lowercases, and collapses whitespace. URL canonicalization removes query params, fragments, and trailing slashes.

---

## How Duplicate Emails Are Prevented

`send_email.py` checks for `data/sent/YYYY-MM-DD.sent` before sending. After a successful send, the marker is created and committed to the repo.

---

## Article Page Structure

Each article gets a dedicated page with:

1. **Header** — title, source, date, severity badge, tags, CVE references
2. **Overview** — what happened and why it matters
3. **Technical Details** — vulnerability type, attack method, CVE details
4. **Impact** — who's affected, severity assessment, CVSS score
5. **Mitigation** — patches, workarounds, defensive actions
6. **Additional Context** — threat landscape trends, related incidents
7. **Source Link** — external link to the original article

Content is generated deterministically from RSS data using keyword classification and tag-based contextual analysis.

---

## Local Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Full pipeline
python -m scripts.process_articles

# Generate site
python -m scripts.generate_site

# Preview
cd docs && python -m http.server 8000
# Open http://localhost:8000
```

### Test individual modules

```bash
python -m scripts.fetch_feeds          # Fetch only
python -m scripts.process_articles     # Fetch + enrich + save
python -m scripts.generate_site        # Generate from existing data
```

### Test email locally

```bash
export EMAIL_SENDER="you@gmail.com"
export EMAIL_PASSWORD="your-app-password"
export EMAIL_RECEIVER="recipient@example.com"
python -m scripts.send_email
```

---

## Manually Triggering Workflows

Both workflows support `workflow_dispatch`:

1. **Actions** tab -> select workflow
2. Click **Run workflow**

---

## Troubleshooting

| Problem | Solution |
|---|---|
| Actions not running | Settings -> Actions -> General -> Allow all actions |
| Email not sending | Verify secrets. Check logs for SMTP errors. Use Gmail App Password. |
| Pages 404 | Set Pages source to `main` / `/docs`. Wait a few minutes. |
| No articles | Trigger Update Site manually. Check logs for feed errors. |
| Old articles not pruning | Adjust `max_article_age_days` in feeds.yaml |

---

## Security Notes

- No credentials in code — all secrets stored in GitHub Secrets
- App passwords only — never use primary account passwords
- Article data is public — no sensitive information stored
- Workflows request only `contents: write` permission

---

## License

[MIT](LICENSE)
