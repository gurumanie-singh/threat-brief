"""Content enrichment: structured sections, severity, CVEs, and email summaries.

All enrichment is deterministic — no external AI APIs. Works by extracting
structure from available RSS content using keyword analysis, regex patterns,
and heuristic section classification.
"""

from __future__ import annotations

import logging
import re
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


# ── Severity inference ──────────────────────────────────────────────

_SEVERITY_RULES: list[tuple[str, list[str]]] = [
    ("critical", [
        "critical", "critical severity", "critical vulnerability",
        "critical flaw", "actively exploited", "emergency patch",
        "wormable", "unauthenticated rce",
    ]),
    ("high", [
        "high severity", "high-severity", "important vulnerability",
        "zero-day", "zero day", "0-day", "remote code execution",
        "privilege escalation", "authentication bypass",
    ]),
    ("medium", [
        "medium severity", "moderate severity", "moderate",
        "cross-site scripting", "information disclosure",
        "denial of service", "dos attack",
    ]),
    ("low", [
        "low severity", "low-severity", "informational",
    ]),
]


def infer_severity(text: str, cvss: float | None = None) -> str | None:
    if cvss is not None:
        if cvss >= 9.0:
            return "critical"
        if cvss >= 7.0:
            return "high"
        if cvss >= 4.0:
            return "medium"
        return "low"

    lower = text.lower()
    for level, keywords in _SEVERITY_RULES:
        if any(kw in lower for kw in keywords):
            return level
    return None


# ── Sentence utilities ──────────────────────────────────────────────

_SENT_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z])")
_ABBREVS = {"mr.", "mrs.", "dr.", "ms.", "inc.", "ltd.", "corp.", "etc.", "e.g.", "i.e.", "u.s.", "u.k."}


def split_sentences(text: str) -> list[str]:
    raw = _SENT_SPLIT.split(text.strip())
    sentences = []
    for s in raw:
        s = s.strip()
        if len(s) > 15:
            sentences.append(s)
    return sentences


def _score_sentence(sentence: str, keywords: list[str]) -> int:
    lower = sentence.lower()
    return sum(1 for kw in keywords if kw in lower)


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


def _pick_sentences(sentences: list[str], keywords: list[str], max_count: int = 4) -> list[str]:
    scored = [(s, _score_sentence(s, keywords)) for s in sentences]
    scored.sort(key=lambda x: x[1], reverse=True)
    return [s for s, sc in scored[:max_count] if sc > 0]


def _build_overview(sentences: list[str], title: str, summary: str) -> str:
    if len(sentences) >= 2:
        overview_sents = sentences[:3]
        text = " ".join(overview_sents)
        if len(text) > 80:
            return text

    if summary and len(summary) > 80:
        return summary

    return f"{title}. {summary}" if summary else title


def _build_technical(
    sentences: list[str], tags: list[str], cves: list[str]
) -> str:
    picked = _pick_sentences(sentences, _TECHNICAL_KW, 4)
    parts: list[str] = []

    if picked:
        parts.append(" ".join(picked))

    if cves:
        cve_str = ", ".join(cves[:5])
        parts.append(f"Referenced vulnerabilities: {cve_str}.")

    if not parts:
        tag_context = _tag_technical_context(tags)
        if tag_context:
            parts.append(tag_context)
        else:
            parts.append(
                "Specific technical details are available in the original source article."
            )

    return "\n\n".join(parts)


def _build_impact(
    sentences: list[str],
    tags: list[str],
    severity: str | None,
    cves: list[str],
    cvss: float | None,
) -> str:
    picked = _pick_sentences(sentences, _IMPACT_KW, 3)
    parts: list[str] = []

    if picked:
        parts.append(" ".join(picked))

    severity_parts: list[str] = []
    if severity:
        severity_parts.append(f"Assessed severity: {severity.upper()}.")
    if cvss is not None:
        severity_parts.append(f"CVSS score: {cvss}/10.")
    if severity_parts:
        parts.append(" ".join(severity_parts))

    if not picked:
        impact_ctx = _tag_impact_context(tags)
        if impact_ctx:
            parts.append(impact_ctx)

    return "\n\n".join(parts) if parts else (
        "Impact assessment details are available in the full source article."
    )


def _build_mitigation(sentences: list[str], tags: list[str]) -> str:
    picked = _pick_sentences(sentences, _MITIGATION_KW, 4)
    parts: list[str] = []

    if picked:
        parts.append(" ".join(picked))

    generic = _tag_mitigation_guidance(tags)
    if generic:
        parts.append(generic)

    return "\n\n".join(parts) if parts else (
        "Consult the original source for specific remediation guidance. "
        "General best practices include keeping systems patched, monitoring "
        "for indicators of compromise, and following vendor advisories."
    )


def _build_context(tags: list[str], title: str) -> str:
    contexts: list[str] = []

    tag_set = set(tags)
    if "ransomware" in tag_set:
        contexts.append(
            "Ransomware continues to be one of the most financially impactful "
            "categories of cyber threats, with attacks increasingly targeting "
            "critical infrastructure and leveraging double-extortion tactics."
        )
    if "zero-day" in tag_set:
        contexts.append(
            "Zero-day vulnerabilities represent some of the highest-priority "
            "threats as they are exploited before vendors can issue patches. "
            "Rapid detection and compensating controls are essential."
        )
    if "apt" in tag_set:
        contexts.append(
            "Advanced persistent threat groups typically conduct long-running, "
            "targeted campaigns often aligned with nation-state interests. "
            "These operations require heightened vigilance and threat intelligence."
        )
    if "phishing" in tag_set:
        contexts.append(
            "Phishing remains the most common initial access vector in cyber "
            "attacks. Security awareness training combined with technical "
            "controls like email filtering and MFA are key defenses."
        )
    if {"vulnerability", "cve", "patch"} & tag_set:
        contexts.append(
            "Timely vulnerability management and patch prioritization remain "
            "critical components of any defensive security program."
        )
    if "breach" in tag_set:
        contexts.append(
            "Data breaches carry significant regulatory, financial, and "
            "reputational consequences. Affected organizations and individuals "
            "should monitor for follow-on attacks using exposed data."
        )
    if "malware" in tag_set and "ransomware" not in tag_set:
        contexts.append(
            "Modern malware campaigns frequently use multi-stage delivery "
            "chains and evasion techniques. Defense-in-depth strategies "
            "including EDR, network monitoring, and application allowlisting "
            "help reduce exposure."
        )

    if not contexts:
        contexts.append(
            "This story reflects ongoing developments in the cybersecurity "
            "threat landscape. Staying informed through trusted sources and "
            "maintaining robust security hygiene are always recommended."
        )

    return "\n\n".join(contexts)


# ── Tag-based fallback content ──────────────────────────────────────

def _tag_technical_context(tags: list[str]) -> str:
    parts: list[str] = []
    tag_set = set(tags)
    if "ransomware" in tag_set:
        parts.append("This involves a ransomware operation, typically leveraging initial access through phishing, exposed services, or supply chain compromise.")
    if "malware" in tag_set and "ransomware" not in tag_set:
        parts.append("This involves malicious software designed to compromise, exfiltrate, or disrupt targeted systems.")
    if "vulnerability" in tag_set or "cve" in tag_set:
        parts.append("A security vulnerability has been identified that could allow attackers to compromise affected systems.")
    if "exploit" in tag_set:
        parts.append("Active exploitation or proof-of-concept exploit code has been reported for this issue.")
    if "phishing" in tag_set:
        parts.append("The attack leverages social engineering techniques to trick users into revealing credentials or executing malicious payloads.")
    return " ".join(parts)


def _tag_impact_context(tags: list[str]) -> str:
    tag_set = set(tags)
    if "breach" in tag_set:
        return "Organizations and individuals whose data was exposed may face follow-on phishing, credential stuffing, or identity fraud."
    if "ransomware" in tag_set:
        return "Affected organizations may face operational disruption, data loss, and potential extortion demands."
    if "vulnerability" in tag_set:
        return "Systems running affected software versions are at risk until patches or mitigations are applied."
    return ""


def _tag_mitigation_guidance(tags: list[str]) -> str:
    guidance: list[str] = []
    tag_set = set(tags)
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
    return " ".join(guidance)


# ── Email summary builder ──────────────────────────────────────────

def build_email_summary(article: dict[str, Any]) -> str:
    """Build a 2-4 sentence email summary: what happened, who's affected, why it matters."""
    title = article.get("title", "")
    summary = article.get("summary", "")
    full = article.get("full_content", "") or summary
    tags = article.get("tags", [])
    cves = article.get("cves", [])
    severity = article.get("severity")

    sentences = split_sentences(full)

    lead = sentences[0] if sentences else summary.split(". ")[0] if summary else title
    if not lead.endswith("."):
        lead = lead.rstrip(".!?") + "."

    parts = [lead]

    if cves:
        cve_part = ", ".join(cves[:3])
        parts.append(f"Tracked as {cve_part}.")

    if severity and severity in ("critical", "high"):
        parts.append(f"Severity is rated {severity}.")

    if len(parts) == 1 and len(sentences) >= 2:
        second = sentences[1]
        if not second.endswith("."):
            second = second.rstrip(".!?") + "."
        parts.append(second)

    result = " ".join(parts)
    if len(result) > 500:
        result = result[:497].rsplit(" ", 1)[0] + "…"

    return result


# ── Main enrichment entry point ────────────────────────────────────

def enrich_article(article: dict[str, Any]) -> dict[str, Any]:
    """Add structured sections, severity, CVEs, and email summary to an article."""
    full_text = article.get("full_content", "") or article.get("summary", "")
    title = article.get("title", "")
    summary = article.get("summary", "")
    tags = article.get("tags", [])
    searchable = f"{title} {full_text}"

    cves = extract_cves(searchable)
    cvss = extract_cvss(searchable)
    severity = infer_severity(searchable, cvss)

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
    article["sections"] = sections
    article["email_summary"] = build_email_summary(article)

    return article
