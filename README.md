# ⚡ Threat Brief

**Automated daily cybersecurity news aggregator and email notifier.**

Threat Brief fetches headlines from top cybersecurity RSS feeds, deduplicates and tags them, publishes a static site to GitHub Pages (updated every 2 hours), and sends a single daily email digest — all powered by GitHub Actions with zero backend servers and zero paid services.

---

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                    GitHub Actions (cron)                     │
│                                                             │
│  ┌──────────────┐   ┌──────────────┐   ┌────────────────┐  │
│  │ fetch_feeds   │──▶│ process_     │──▶│ generate_site  │  │
│  │ (RSS parse)   │   │ articles     │   │ (Jinja2→HTML)  │  │
│  └──────────────┘   │ (merge/dedup)│   └───────┬────────┘  │
│                      └──────┬───────┘           │           │
│                             │                   │           │
│                      ┌──────▼───────┐   ┌───────▼────────┐  │
│                      │ data/        │   │ docs/          │  │
│                      │ articles.json│   │ (GitHub Pages) │  │
│                      └──────────────┘   └────────────────┘  │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ send_email (daily cron, once per day, SMTP/Gmail)    │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Fetch** — RSS feeds listed in `feeds.yaml` are parsed with `feedparser`.
2. **Process** — New articles are merged with existing ones in `data/articles.json`. Duplicates are detected via a hash of normalized title + canonical URL. Articles older than 7 days are pruned.
3. **Tag** — Each article is auto-tagged by keyword matching (zero-day, ransomware, CVE, etc.) against its title and summary.
4. **Generate** — Jinja2 templates produce a static site under `docs/` (index, daily pages, archive).
5. **Email** — Once per day, the top headlines are formatted into an HTML email and sent via SMTP. A marker file in `data/sent/` prevents duplicate sends.

---

## Repository Structure

```
threat-brief/
├── .github/workflows/
│   ├── update-site.yml        # Runs every 2 hours: fetch → process → generate → deploy
│   └── daily-email.yml        # Runs once daily: fetch → process → email
├── scripts/
│   ├── __init__.py
│   ├── config.py              # Central config, loads feeds.yaml + env vars
│   ├── utils.py               # Hashing, date parsing, JSON I/O, text helpers
│   ├── fetch_feeds.py         # RSS fetcher and normalizer
│   ├── process_articles.py    # Merge, dedup, prune, archive
│   ├── generate_site.py       # Static site generator (Jinja2 → docs/)
│   └── send_email.py          # Daily email sender (SMTP)
├── templates/
│   ├── index.html             # Homepage template
│   ├── day.html               # Daily briefing page template
│   ├── archive_index.html     # Archive listing template
│   ├── article_card.html      # Reusable article card partial
│   └── email.html             # HTML email template
├── data/
│   ├── articles.json          # Current article database
│   ├── archive/               # Daily JSON snapshots (YYYY-MM-DD.json)
│   └── sent/                  # Email sent markers (YYYY-MM-DD.sent)
├── docs/                      # GitHub Pages root
│   ├── index.html
│   ├── assets/
│   │   ├── style.css
│   │   └── app.js
│   ├── daily/                 # Per-day HTML pages
│   └── archive/
│       └── index.html
├── feeds.yaml                 # Feed URLs, tag keywords, and settings
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

Go to **Settings → Secrets and variables → Actions → New repository secret** and add:

| Secret | Description |
|---|---|
| `EMAIL_SENDER` | Gmail address to send from (e.g. `you@gmail.com`) |
| `EMAIL_PASSWORD` | Gmail **App Password** (not your login password — see below) |
| `EMAIL_RECEIVER` | Recipient email address |

**Optional secrets** (defaults to Gmail):

| Secret | Default |
|---|---|
| `SMTP_HOST` | `smtp.gmail.com` |
| `SMTP_PORT` | `587` |

### 3. Enable GitHub Pages

1. Go to **Settings → Pages**.
2. Under **Source**, select **Deploy from a branch**.
3. Set branch to `main` and folder to `/docs`.
4. Click **Save**.

Your site will be live at `https://YOUR_USERNAME.github.io/threat-brief/`.

### 4. Enable GitHub Actions

Actions are enabled by default on new repos. If they're disabled:

1. Go to **Settings → Actions → General**.
2. Select **Allow all actions and reusable workflows**.
3. Click **Save**.

### 5. Trigger the First Run

1. Go to the **Actions** tab.
2. Click **Update Site** in the left sidebar.
3. Click **Run workflow → Run workflow**.

This fetches feeds, processes articles, and generates the site. Within a few minutes your GitHub Pages site will show live cybersecurity news.

### 6. Update `site_base_url` (for email links)

Edit `feeds.yaml` and set:

```yaml
settings:
  site_base_url: "https://YOUR_USERNAME.github.io/threat-brief"
```

This makes "Read more" links in the daily email point to your GitHub Pages site.

---

## Gmail App Password Setup

**Do not use your normal Gmail password.** Google blocks sign-ins from "less secure apps" by default.

1. Go to [myaccount.google.com](https://myaccount.google.com/).
2. Navigate to **Security → 2-Step Verification** (enable it if not already on).
3. Go to **Security → App passwords** (or search "App passwords" in settings).
4. Select **Mail** and **Other (Custom name)**, enter "Threat Brief".
5. Click **Generate**. Copy the 16-character password.
6. Use this as your `EMAIL_PASSWORD` GitHub Secret.

> **Security note:** App passwords grant full email access. Never commit them to the repository. Store them only in GitHub Secrets.

---

## Customizing Feeds

Edit `feeds.yaml` to add, remove, or modify RSS feeds:

```yaml
feeds:
  - name: My Custom Feed
    url: https://example.com/rss.xml
```

Changes take effect on the next scheduled (or manual) workflow run.

### Tag Keywords

Tags are automatically applied when any keyword appears in an article's title or summary. Edit the `tag_keywords` section in `feeds.yaml`:

```yaml
tag_keywords:
  my-tag:
    - keyword one
    - keyword two
```

---

## How Deduplication Works

Each article gets a stable ID computed as:

```
SHA-256( normalize(title) + "|" + canonicalize(url) )[:16]
```

- **Title normalization**: lowercased, accents stripped, whitespace collapsed.
- **URL canonicalization**: scheme + host + path (no query params, fragments, or trailing slashes), lowercased.

This ensures the same article from different feeds (or with minor URL variations) is stored only once.

---

## How Duplicate Emails Are Prevented

Before sending, `send_email.py` checks for a marker file at `data/sent/YYYY-MM-DD.sent`. If it exists, the email is skipped. After a successful send, the marker is created and committed back to the repository.

---

## Local Development

### Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Run Each Script

```bash
# Fetch and process feeds
python -m scripts.process_articles

# Generate the static site
python -m scripts.generate_site

# Preview the site (Python built-in server)
cd docs && python -m http.server 8000
# Open http://localhost:8000

# Test email (requires env vars)
export EMAIL_SENDER="you@gmail.com"
export EMAIL_PASSWORD="your-app-password"
export EMAIL_RECEIVER="recipient@example.com"
python -m scripts.send_email
```

### Test Individual Modules

```bash
# Fetch only (no merge/save)
python -m scripts.fetch_feeds

# Process (fetch + merge + prune + save)
python -m scripts.process_articles

# Generate site from existing data
python -m scripts.generate_site
```

---

## Manually Triggering Workflows

Both workflows support `workflow_dispatch`:

1. Go to **Actions** tab on GitHub.
2. Select the workflow (**Update Site** or **Daily Email**).
3. Click **Run workflow**.

---

## Troubleshooting

| Problem | Solution |
|---|---|
| **Actions not running** | Check Settings → Actions → General. Ensure workflows are allowed. |
| **Email not sending** | Verify GitHub Secrets are set. Check Actions logs for SMTP errors. Confirm you're using a Gmail App Password, not your regular password. |
| **GitHub Pages 404** | Ensure Pages source is set to `main` branch, `/docs` folder. Wait a few minutes after deployment. |
| **No articles showing** | Manually trigger the Update Site workflow. Check Actions logs for feed fetch errors. Some feeds may be temporarily down. |
| **Duplicate articles** | This is handled automatically by the dedup hash. If you see duplicates, the articles likely have different titles or URLs across feeds. |
| **Old articles not pruning** | Adjust `max_article_age_days` in `feeds.yaml` settings. |
| **YAML syntax error** | Validate `feeds.yaml` at [yamllint.com](https://www.yamllint.com/) or run `python -c "import yaml; yaml.safe_load(open('feeds.yaml'))"`. |

---

## GitHub Pages URL Pattern

After enabling Pages, your site structure will be:

```
https://YOUR_USERNAME.github.io/threat-brief/                  → Latest headlines
https://YOUR_USERNAME.github.io/threat-brief/daily/2026-04-15.html → Daily page
https://YOUR_USERNAME.github.io/threat-brief/archive/          → Archive index
```

---

## Security Notes

- **No credentials in code.** All secrets are stored in GitHub Secrets and injected as environment variables at runtime.
- **App passwords only.** Never use your primary Google account password.
- **Public repo visibility.** Article data and the generated site are public. No private or sensitive information is stored.
- **Workflow permissions.** Both workflows only request `contents: write` to commit data/site updates back to the repo.

---

## License

[MIT](LICENSE)
