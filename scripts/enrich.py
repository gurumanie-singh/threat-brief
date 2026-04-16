"""Content enrichment: severity, CVEs, vendors, action-required, structured sections.

All enrichment is deterministic — no external AI APIs. Uses keyword analysis,
regex patterns, and heuristic classification.
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from typing import Any

logger = logging.getLogger(__name__)

# ── CVE / CVSS extraction ──────────────────────────────────────────

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_CVSS_RE = re.compile(r"CVSS[:\s]*(?:score)?[:\s]*([\d]+\.[\d]+)", re.IGNORECASE)
_CVSS_ALT_RE = re.compile(r"([\d]+\.[\d]+)\s*/\s*10", re.IGNORECASE)


def extract_cves(text: str) -> list[str]:
    return sorted(set(m.upper() for m in _CVE_RE.findall(text)))


def extract_cvss(text: str) -> float | None:
    for pattern in (_CVSS_RE, _CVSS_ALT_RE):
        match = pattern.search(text)
        if match:
            try:
                score = float(match.group(1))
                if 0.0 <= score <= 10.0:
                    return score
            except ValueError:
                pass
    return None


# ── Severity classification (layered, score-based) ─────────────────
#
# Every article MUST receive a severity. The classifier uses:
#   Priority 1: CVSS score (authoritative structured data)
#   Priority 2: Weighted keyword scoring across all text fields
#   Priority 3: Guaranteed fallback → "medium"
#
# Scoring: each matched phrase adds points. Total maps to severity band.
#   >= 15  →  critical   (active exploitation, zero-day, or combined highs)
#   >= 6   →  high       (RCE, priv-esc, auth bypass, etc.)
#   >= 2   →  medium     (general vulnerability/threat/malware signals)
#   == 1   →  low        (advisory-only, guidance, awareness)
#   == 0   →  medium     (fallback for unclassified cybersecurity news)

_SEVERITY_SIGNALS: list[tuple[str, int]] = [
    # ── Active exploitation / Zero-day (Critical alone) ──
    ("actively exploited", 20),
    ("exploited in the wild", 20),
    ("under active exploitation", 20),
    ("known exploited vulnerability", 18),
    ("added to kev", 18),
    ("zero-day", 18),
    ("zero day", 18),
    ("0-day", 18),
    ("0day", 15),
    ("unauthenticated rce", 18),
    ("unauthenticated remote code execution", 18),
    ("pre-auth rce", 18),
    ("wormable", 15),
    ("arbitrary code execution", 10),
    ("emergency patch", 10),

    # ── Strong technical (High alone, Critical when combined) ──
    ("remote code execution", 7),
    ("privilege escalation", 7),
    ("authentication bypass", 7),
    ("security bypass", 6),
    ("sandbox escape", 7),
    ("supply chain attack", 7),
    ("supply chain compromise", 7),
    ("exploit available", 6),
    ("public exploit", 6),
    ("proof-of-concept", 5),
    ("proof of concept", 5),
    ("emergency update", 7),
    ("pre-authentication", 6),
    ("lateral movement", 5),
    ("command injection", 5),
    ("sql injection", 5),
    ("code execution", 5),

    # ── Explicit severity labels in advisory text ──
    ("critical severity", 8),
    ("critical vulnerability", 8),
    ("critical flaw", 8),
    ("severity critical", 8),
    ("rated critical", 8),
    ("high severity", 6),
    ("high-severity", 6),
    ("severity high", 6),
    ("rated high", 6),
    ("important vulnerability", 5),
    ("moderate severity", 3),
    ("medium severity", 3),

    # ── Medium-strength technical / threat signals ──
    ("vulnerability", 2),
    ("security flaw", 3),
    ("security vulnerability", 3),
    ("patch released", 3),
    ("patch available", 3),
    ("patches available", 3),
    ("update available", 2),
    ("fix available", 2),
    ("hotfix", 2),
    ("cross-site scripting", 3),
    ("xss", 3),
    ("information disclosure", 3),
    ("denial of service", 3),
    ("ddos", 3),
    ("buffer overflow", 4),
    ("memory corruption", 4),
    ("use-after-free", 4),
    ("heap overflow", 4),
    ("type confusion", 4),
    ("integer overflow", 3),
    ("deserialization", 3),
    ("path traversal", 3),
    ("directory traversal", 3),
    ("ssrf", 3),
    ("server-side request forgery", 3),
    ("security update", 2),
    ("security advisory", 2),
    ("security bulletin", 2),
    ("ransomware", 3),
    ("malware", 2),
    ("trojan", 2),
    ("backdoor", 3),
    ("botnet", 2),
    ("phishing", 2),
    ("social engineering", 2),
    ("data breach", 3),
    ("data leak", 3),
    ("data exposure", 3),
    ("credential theft", 3),
    ("credential stuffing", 2),
    ("spyware", 2),
    ("rootkit", 3),
    ("threat actor", 2),
    ("apt group", 2),
    ("nation-state", 3),
    ("cyberattack", 2),
    ("cyber attack", 2),
    ("brute force", 2),
    ("brute-force", 2),
    ("unauthorized access", 3),

    # ── Weak / low signals ──
    ("advisory", 1),
    ("guidance", 1),
    ("best practices", 1),
    ("awareness", 1),
    ("hardening", 1),
    ("informational", 1),
    ("security tip", 1),
    ("compliance", 1),
]

_EXPLICIT_LOW_MARKERS = (
    "low severity", "low-severity", "rated low", "severity low", "severity: low",
)

_SCORE_CRITICAL = 15
_SCORE_HIGH = 6
_SCORE_MEDIUM = 2
_DEFAULT_SEVERITY = "medium"


def _score_text(text: str, cves: list[str] | None = None) -> tuple[int, list[tuple[str, int]]]:
    """Score text against weighted severity signals. Returns (total, matched)."""
    lower = text.lower()
    matched: list[tuple[str, int]] = []
    for phrase, weight in _SEVERITY_SIGNALS:
        if phrase in lower:
            matched.append((phrase, weight))
    total = sum(w for _, w in matched)
    if cves:
        total += 2
        matched.append(("cve-present", 2))
        if len(cves) >= 3:
            total += 3
            matched.append(("multiple-cves", 3))
    return total, matched


def classify_severity(
    text: str,
    cvss: float | None = None,
    cves: list[str] | None = None,
) -> str:
    """Layered severity classifier. ALWAYS returns a valid severity string.

    Priority 1: CVSS score (authoritative structured data)
    Priority 2: Weighted keyword scoring across all text
    Priority 3: Guaranteed fallback → medium
    """
    method = "score"

    # Priority 1: CVSS score → direct mapping
    if cvss is not None:
        method = "cvss"
        if cvss >= 9.0:
            sev = "critical"
        elif cvss >= 7.0:
            sev = "high"
        elif cvss >= 4.0:
            sev = "medium"
        else:
            sev = "low"
        logger.debug("Severity[%s] CVSS=%.1f → %s", method, cvss, sev)
        return sev

    # Priority 2: Weighted keyword scoring
    score, matched = _score_text(text, cves)

    if score >= _SCORE_CRITICAL:
        sev = "critical"
    elif score >= _SCORE_HIGH:
        sev = "high"
    elif score >= _SCORE_MEDIUM:
        sev = "medium"
    elif score > 0:
        sev = "low"
    else:
        lower = text.lower()
        if any(m in lower for m in _EXPLICIT_LOW_MARKERS):
            sev = "low"
        else:
            sev = _DEFAULT_SEVERITY

    if matched:
        top = sorted(matched, key=lambda x: x[1], reverse=True)[:4]
        top_str = ", ".join(f"{p}({w})" for p, w in top)
        logger.debug("Severity[%s] score=%d → %s  [%s]", method, score, sev, top_str)
    else:
        logger.debug("Severity[%s] score=0 → %s (fallback)", method, sev)

    return sev


def validate_severity_distribution(articles: list[dict[str, Any]]) -> None:
    """Log severity distribution and warn on blank severity or implausible skew."""
    from collections import Counter as C
    dist: C[str] = C()
    blank = 0
    for a in articles:
        sev = a.get("severity")
        if not sev:
            blank += 1
        else:
            dist[sev] += 1
    total = len(articles)
    if not total:
        return
    parts = [f"{s}={c}" for s, c in sorted(dist.items(), key=lambda x: x[1], reverse=True)]
    logger.info("Severity distribution (%d articles): %s", total, ", ".join(parts))
    if blank:
        logger.error("SEVERITY BUG: %d/%d articles have blank severity", blank, total)
    if total >= 10:
        for sev, count in dist.items():
            pct = count / total * 100
            if pct > 80:
                logger.warning(
                    "Severity skew: %s is %.0f%% (%d/%d) — check classification rules",
                    sev, pct, count, total,
                )


# Keep old name as alias for any external callers
def infer_severity(text: str, cvss: float | None = None) -> str:
    return classify_severity(text, cvss)


# ── Vendor / technology detection ──────────────────────────────────

def detect_vendors(text: str, vendor_keywords: dict[str, list[str]]) -> list[str]:
    lower = text.lower()
    return sorted({
        vendor for vendor, keywords in vendor_keywords.items()
        if any(kw in lower for kw in keywords)
    })


# ── Action required detection ──────────────────────────────────────

_ACTION_REQUIRED_KW = [
    "patch now", "patch released", "patch available", "patches available",
    "update immediately", "update now", "update as soon as",
    "actively exploited", "under active exploitation", "exploited in the wild",
    "emergency patch", "emergency update", "emergency advisory",
    "urged to update", "urged to patch", "urged to apply",
    "should update", "should patch", "must update", "must patch",
    "mitigation required", "action required",
    "fix available", "hotfix released", "hotfix available",
    "security update released", "security advisory",
    "critical update", "critical patch",
]


def detect_action_required(text: str) -> bool:
    lower = text.lower()
    return any(kw in lower for kw in _ACTION_REQUIRED_KW)


# ── Story grouping helpers ─────────────────────────────────────────

_STOPWORDS = frozenset(
    "a an the and or but in on at to for of is are was were be been being "
    "has have had do does did will would shall should may might can could "
    "this that these those with from by as not no its it they them their "
    "new how what who where when why which all also into over more than "
    "about after before between through during".split()
)


def _significant_words(text: str) -> set[str]:
    words = re.findall(r"[a-z0-9]+", text.lower())
    return {w for w in words if len(w) > 2 and w not in _STOPWORDS}


def compute_title_similarity(title_a: str, title_b: str) -> float:
    words_a = _significant_words(title_a)
    words_b = _significant_words(title_b)
    if not words_a or not words_b:
        return 0.0
    union = words_a | words_b
    return len(words_a & words_b) / len(union) if union else 0.0


def group_articles(articles: list[dict[str, Any]], threshold: float = 0.45) -> list[dict[str, Any]]:
    """Annotate articles with related_sources for stories covered by multiple feeds."""
    if not articles:
        return articles

    used: set[str] = set()
    result: list[dict[str, Any]] = []

    for i, primary in enumerate(articles):
        if primary["id"] in used:
            continue
        used.add(primary["id"])
        related: list[dict[str, str]] = []

        primary_cves = set(primary.get("cves", []))

        for j in range(i + 1, len(articles)):
            other = articles[j]
            if other["id"] in used:
                continue
            if other.get("source") == primary.get("source"):
                continue

            shared_cve = bool(primary_cves and primary_cves & set(other.get("cves", [])))
            similar_title = compute_title_similarity(primary["title"], other["title"]) >= threshold

            if shared_cve or similar_title:
                related.append({"source": other["source"], "link": other["link"]})
                used.add(other["id"])

        primary["related_sources"] = related
        result.append(primary)

    for a in articles:
        if a["id"] not in used:
            a["related_sources"] = []
            result.append(a)

    result.sort(key=lambda a: a["published"], reverse=True)
    return result


# ── Trend / landscape summary generation ───────────────────────────

def generate_landscape_bullets(articles: list[dict[str, Any]]) -> list[str]:
    """Generate 2-4 concise landscape summary bullets from today's articles."""
    if not articles:
        return []

    bullets: list[str] = []
    tags = Counter()
    vendors = Counter()
    severities = Counter()
    action_count = 0

    for a in articles:
        tags.update(a.get("tags", []))
        vendors.update(a.get("vendors", []))
        sev = a.get("severity")
        if sev:
            severities[sev] += 1
        if a.get("action_required"):
            action_count += 1

    crit = severities.get("critical", 0)
    high = severities.get("high", 0)
    if crit:
        bullets.append(
            f"{crit} critical-severity {'issue' if crit == 1 else 'issues'} detected"
            + (" with active exploitation reported" if tags.get("exploit") or tags.get("zero-day") else "")
        )
    elif high:
        bullets.append(f"{high} high-severity {'advisory' if high == 1 else 'advisories'} published today")

    if action_count:
        bullets.append(f"{action_count} {'item requires' if action_count == 1 else 'items require'} immediate action — patches or mitigations available")

    top_vendors = [v for v, _ in vendors.most_common(2) if vendors[v] >= 2]
    if top_vendors:
        bullets.append(f"{', '.join(top_vendors)} {'ecosystem' if len(top_vendors) == 1 else 'ecosystems'} affected by multiple advisories")

    if tags.get("ransomware", 0) >= 2:
        bullets.append("Elevated ransomware activity reported across multiple sources")
    elif tags.get("phishing", 0) >= 2:
        bullets.append("Multiple phishing campaigns identified targeting enterprises")
    elif tags.get("breach", 0) >= 2:
        bullets.append("Several new data breach disclosures reported")

    return bullets[:4]


def extract_top_threats(articles: list[dict[str, Any]], max_items: int = 6) -> list[dict[str, Any]]:
    """Find recurring topics/entities across this week's articles."""
    phrase_counter: Counter = Counter()
    phrase_articles: dict[str, list[str]] = {}

    for a in articles:
        title_lower = a.get("title", "").lower()
        words = re.findall(r"[a-z][a-z0-9\-]+", title_lower)
        significant = [w for w in words if len(w) > 3 and w not in _STOPWORDS]

        for i in range(len(significant)):
            for length in (1, 2):
                if i + length <= len(significant):
                    phrase = " ".join(significant[i:i + length])
                    if len(phrase) > 4:
                        phrase_counter[phrase] += 1
                        phrase_articles.setdefault(phrase, []).append(a["id"])

        for cve in a.get("cves", []):
            phrase_counter[cve.lower()] += 1
            phrase_articles.setdefault(cve.lower(), []).append(a["id"])

    seen_ids: set[str] = set()
    results: list[dict[str, Any]] = []
    for phrase, count in phrase_counter.most_common(30):
        if count < 2:
            break
        article_ids = phrase_articles[phrase]
        key = frozenset(article_ids[:3])
        if key in seen_ids:
            continue
        seen_ids.add(key)
        results.append({"topic": phrase, "count": count})
        if len(results) >= max_items:
            break

    return results


# ── Personalization ────────────────────────────────────────────────

def apply_personalization(
    article: dict[str, Any], personalization: dict[str, Any]
) -> dict[str, Any]:
    preferred_vendors = set(v.lower() for v in personalization.get("preferred_vendors", []))
    highlight_kw = [kw.lower() for kw in personalization.get("highlight_keywords", [])]

    highlighted = False
    if preferred_vendors:
        article_vendors = {v.lower() for v in article.get("vendors", [])}
        if article_vendors & preferred_vendors:
            highlighted = True
    if highlight_kw:
        searchable = f"{article.get('title', '')} {article.get('summary', '')}".lower()
        if any(kw in searchable for kw in highlight_kw):
            highlighted = True

    article["highlighted"] = highlighted
    return article


# ── Sentence utilities ──────────────────────────────────────────────

_SENT_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z])")


def split_sentences(text: str) -> list[str]:
    raw = _SENT_SPLIT.split(text.strip())
    return [s.strip() for s in raw if len(s.strip()) > 15]


def _score_sentence(sentence: str, keywords: list[str]) -> int:
    lower = sentence.lower()
    return sum(1 for kw in keywords if kw in lower)


def _pick_sentences(sentences: list[str], keywords: list[str], max_count: int = 4) -> list[str]:
    scored = [(s, _score_sentence(s, keywords)) for s in sentences]
    scored.sort(key=lambda x: x[1], reverse=True)
    return [s for s, sc in scored[:max_count] if sc > 0]


# ── Section builders ────────────────────────────────────────────────

_TECHNICAL_KW = [
    "vulnerability", "exploit", "flaw", "bug", "cve-", "attack vector",
    "remote code execution", "rce", "sql injection", "xss", "cross-site",
    "buffer overflow", "heap", "stack", "use-after-free", "memory corruption",
    "deserialization", "command injection", "path traversal", "ssrf",
    "authentication bypass", "privilege escalation", "code execution",
    "proof of concept", "poc", "payload", "shellcode", "backdoor",
    "trojan", "malware", "ransomware", "loader", "dropper", "c2",
    "command and control", "lateral movement", "initial access",
    "firmware", "api", "endpoint", "protocol",
]

_IMPACT_KW = [
    "affect", "impact", "victim", "target", "million", "billion",
    "thousands", "hundreds", "user", "customer", "organization",
    "enterprise", "government", "hospital", "school", "bank",
    "compromise", "stolen", "leaked", "exposed", "breach",
    "data loss", "downtime", "disruption", "ransom", "payment",
    "critical infrastructure", "supply chain", "sensitive data",
    "personal information", "credentials", "financial",
]

_MITIGATION_KW = [
    "patch", "update", "fix", "upgrade", "mitigat", "workaround",
    "recommend", "advise", "should", "must", "urged", "action",
    "defense", "protect", "detect", "monitor", "block", "disable",
    "configuration", "firewall", "segmentation", "backup",
    "multi-factor", "mfa", "2fa", "incident response",
    "indicator", "ioc", "signature", "rule",
]


def _build_overview(sentences: list[str], title: str, summary: str) -> str:
    if len(sentences) >= 2:
        text = " ".join(sentences[:3])
        if len(text) > 80:
            return text
    if summary and len(summary) > 80:
        return summary
    return f"{title}. {summary}" if summary else title


def _build_technical(sentences: list[str], tags: list[str], cves: list[str]) -> str:
    picked = _pick_sentences(sentences, _TECHNICAL_KW, 4)
    parts: list[str] = []
    if picked:
        parts.append(" ".join(picked))
    if cves:
        parts.append(f"Referenced vulnerabilities: {', '.join(cves[:5])}.")
    if not parts:
        tag_set = set(tags)
        ctx_parts: list[str] = []
        if "ransomware" in tag_set:
            ctx_parts.append("This involves a ransomware operation, typically leveraging initial access through phishing, exposed services, or supply chain compromise.")
        if "malware" in tag_set and "ransomware" not in tag_set:
            ctx_parts.append("This involves malicious software designed to compromise, exfiltrate, or disrupt targeted systems.")
        if "vulnerability" in tag_set or "cve" in tag_set:
            ctx_parts.append("A security vulnerability has been identified that could allow attackers to compromise affected systems.")
        if "exploit" in tag_set:
            ctx_parts.append("Active exploitation or proof-of-concept exploit code has been reported.")
        if "phishing" in tag_set:
            ctx_parts.append("The attack leverages social engineering techniques to trick users into revealing credentials or executing malicious payloads.")
        parts.append(" ".join(ctx_parts) if ctx_parts else "Specific technical details are available in the original source article.")
    return "\n\n".join(parts)


def _build_impact(sentences: list[str], tags: list[str], severity: str | None, cves: list[str], cvss: float | None) -> str:
    picked = _pick_sentences(sentences, _IMPACT_KW, 3)
    parts: list[str] = []
    if picked:
        parts.append(" ".join(picked))
    sev_parts: list[str] = []
    if severity:
        sev_parts.append(f"Assessed severity: {severity.upper()}.")
    if cvss is not None:
        sev_parts.append(f"CVSS score: {cvss}/10.")
    if sev_parts:
        parts.append(" ".join(sev_parts))
    if not picked:
        tag_set = set(tags)
        if "breach" in tag_set:
            parts.append("Organizations and individuals whose data was exposed may face follow-on phishing, credential stuffing, or identity fraud.")
        elif "ransomware" in tag_set:
            parts.append("Affected organizations may face operational disruption, data loss, and potential extortion demands.")
        elif "vulnerability" in tag_set:
            parts.append("Systems running affected software versions are at risk until patches or mitigations are applied.")
    return "\n\n".join(parts) if parts else "Impact assessment details are available in the full source article."


def _build_mitigation(sentences: list[str], tags: list[str]) -> str:
    picked = _pick_sentences(sentences, _MITIGATION_KW, 4)
    parts: list[str] = []
    if picked:
        parts.append(" ".join(picked))
    tag_set = set(tags)
    guidance: list[str] = []
    if {"vulnerability", "cve", "patch"} & tag_set:
        guidance.append("Apply vendor-supplied patches as soon as possible. If patching is not immediately feasible, implement recommended workarounds and compensating controls.")
    if "ransomware" in tag_set:
        guidance.append("Ensure offline backups are current and tested. Implement network segmentation and monitor for lateral movement indicators.")
    if "phishing" in tag_set:
        guidance.append("Reinforce security awareness training. Ensure email filtering, link scanning, and multi-factor authentication are enabled.")
    if "malware" in tag_set:
        guidance.append("Review endpoint detection rules and update threat intelligence feeds. Scan for known indicators of compromise.")
    if "breach" in tag_set:
        guidance.append("Affected users should rotate credentials, enable MFA, and monitor accounts for suspicious activity.")
    if guidance:
        parts.append(" ".join(guidance))
    return "\n\n".join(parts) if parts else (
        "Consult the original source for specific remediation guidance. "
        "General best practices include keeping systems patched, monitoring "
        "for indicators of compromise, and following vendor advisories."
    )


def _build_context(tags: list[str], title: str) -> str:
    contexts: list[str] = []
    tag_set = set(tags)
    if "ransomware" in tag_set:
        contexts.append("Ransomware continues to be one of the most financially impactful categories of cyber threats, with attacks increasingly targeting critical infrastructure and leveraging double-extortion tactics.")
    if "zero-day" in tag_set:
        contexts.append("Zero-day vulnerabilities represent the highest-priority threats as they are exploited before vendors can issue patches. Rapid detection and compensating controls are essential.")
    if "apt" in tag_set:
        contexts.append("Advanced persistent threat groups typically conduct long-running, targeted campaigns often aligned with nation-state interests.")
    if "phishing" in tag_set:
        contexts.append("Phishing remains the most common initial access vector. Security awareness training combined with technical controls like email filtering and MFA are key defenses.")
    if {"vulnerability", "cve", "patch"} & tag_set:
        contexts.append("Timely vulnerability management and patch prioritization remain critical components of any defensive security program.")
    if "breach" in tag_set:
        contexts.append("Data breaches carry significant regulatory, financial, and reputational consequences. Affected organizations and individuals should monitor for follow-on attacks using exposed data.")
    if "malware" in tag_set and "ransomware" not in tag_set:
        contexts.append("Modern malware campaigns frequently use multi-stage delivery chains and evasion techniques. Defense-in-depth strategies including EDR, network monitoring, and application allowlisting help reduce exposure.")
    if not contexts:
        contexts.append("This story reflects ongoing developments in the cybersecurity threat landscape. Staying informed through trusted sources and maintaining robust security hygiene are always recommended.")
    return "\n\n".join(contexts)


# ── Email summary builder ──────────────────────────────────────────

def build_email_summary(article: dict[str, Any]) -> str:
    title = article.get("title", "")
    summary = article.get("summary", "")
    full = article.get("full_content", "") or summary
    cves = article.get("cves", [])
    severity = article.get("severity")

    sentences = split_sentences(full)
    lead = sentences[0] if sentences else summary.split(". ")[0] if summary else title
    if not lead.endswith("."):
        lead = lead.rstrip(".!?") + "."
    parts = [lead]
    if cves:
        parts.append(f"Tracked as {', '.join(cves[:3])}.")
    if severity and severity in ("critical", "high"):
        parts.append(f"Severity is rated {severity}.")
    if len(parts) == 1 and len(sentences) >= 2:
        second = sentences[1]
        if not second.endswith("."):
            second = second.rstrip(".!?") + "."
        parts.append(second)
    result = " ".join(parts)
    return result[:500] if len(result) <= 500 else result[:497].rsplit(" ", 1)[0] + "…"


# ── Main enrichment entry point ────────────────────────────────────

def enrich_article(
    article: dict[str, Any],
    vendor_keywords: dict[str, list[str]] | None = None,
    personalization: dict[str, Any] | None = None,
) -> dict[str, Any]:
    full_text = article.get("full_content", "") or ""
    title = article.get("title", "")
    summary = article.get("summary", "")
    tags = article.get("tags", [])
    searchable = f"{title} {summary} {full_text}"

    cves = extract_cves(searchable)
    cvss = extract_cvss(searchable)
    severity = classify_severity(searchable, cvss, cves)
    vendors = detect_vendors(searchable, vendor_keywords or {})
    action_required = detect_action_required(searchable)

    sentences = split_sentences(full_text)
    sections = {
        "overview": _build_overview(sentences, title, summary),
        "technical": _build_technical(sentences, tags, cves),
        "impact": _build_impact(sentences, tags, severity, cves, cvss),
        "mitigation": _build_mitigation(sentences, tags),
        "context": _build_context(tags, title),
    }

    article["cves"] = cves
    article["cvss"] = cvss
    article["severity"] = severity
    article["vendors"] = vendors
    article["action_required"] = action_required
    article["sections"] = sections
    article["email_summary"] = build_email_summary(article)
    article["related_sources"] = article.get("related_sources", [])
    article["highlighted"] = False

    if personalization:
        apply_personalization(article, personalization)

    return article
