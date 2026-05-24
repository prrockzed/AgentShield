"""
Browser security interceptor — DOM-level HTML threat detection.
evaluate_browser_request() never raises.
"""
from __future__ import annotations
import logging
import re
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_INJECTION_KEYWORDS = [
    "ignore", "override", "system prompt", "instructions", "jailbreak",
    "forget", "disregard", "new task", "exfiltrate", "reveal",
]
_HIDDEN_STYLES = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0",
    re.IGNORECASE,
)
_MALICIOUS_JS = re.compile(
    r"eval\s*\(|atob\s*\(|fromCharCode|document\.write\s*\(", re.IGNORECASE
)


def _domain(url: str) -> str:
    try:
        return urlparse(url).netloc.lower().lstrip("www.")
    except Exception:
        return ""


def evaluate_browser_request(url: str, html_content: str) -> dict:
    """
    DOM-level HTML threat analysis.
    Returns {"decision", "reason", "severity", "findings", "score"}.
    Never raises.
    """
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html_content, "lxml")
        score = 0.0
        findings: list[dict] = []
        page_domain = _domain(url)

        # Rule 1 — HIDDEN_INJECTION
        for tag in soup.find_all(style=_HIDDEN_STYLES):
            text = tag.get_text(" ", strip=True).lower()
            if any(kw in text for kw in _INJECTION_KEYWORDS):
                score += 0.5
                findings.append({"rule": "HIDDEN_INJECTION", "evidence": text[:120], "severity": "CRITICAL"})

        # Rule 2 — MALICIOUS_SCRIPT
        for script in soup.find_all("script"):
            if script.get("src"):
                continue
            code = script.string or ""
            if _MALICIOUS_JS.search(code):
                score += 0.3
                findings.append({"rule": "MALICIOUS_SCRIPT", "evidence": code[:120], "severity": "HIGH"})

        # Rule 3 — IFRAME_HIJACK
        for iframe in soup.find_all("iframe"):
            src = iframe.get("src", "")
            if src and _domain(src) and _domain(src) != page_domain:
                score += 0.2
                findings.append({"rule": "IFRAME_HIJACK", "evidence": src[:120], "severity": "MEDIUM"})

        # Rule 4 — META_REDIRECT
        for meta in soup.find_all("meta", attrs={"http-equiv": re.compile(r"refresh", re.I)}):
            content = meta.get("content", "")
            match = re.search(r"url=([^\s;]+)", content, re.IGNORECASE)
            if match and _domain(match.group(1)) != page_domain:
                score += 0.4
                findings.append({"rule": "META_REDIRECT", "evidence": content[:120], "severity": "HIGH"})

        # Rule 5 — CREDENTIAL_FORM
        for form in soup.find_all("form"):
            has_password = bool(form.find("input", attrs={"type": "password"}))
            action = form.get("action", "")
            if has_password and action and _domain(action) and _domain(action) != page_domain:
                score += 0.5
                findings.append({"rule": "CREDENTIAL_FORM", "evidence": action[:120], "severity": "HIGH"})

        score = min(round(score, 3), 1.0)
        if score > 0.7:
            decision, severity = "BLOCKED", "CRITICAL"
            reason = findings[0]["rule"] if findings else "high_risk_content"
        elif score > 0.3:
            decision, severity = "FLAGGED", "HIGH"
            reason = findings[0]["rule"] if findings else "suspicious_content"
        else:
            decision, severity = "ALLOWED", "INFO"
            reason = ""

        return {"decision": decision, "reason": reason, "severity": severity,
                "findings": findings, "score": score}

    except Exception as exc:
        logger.warning("browser_interceptor: error: %s", exc)
        return {"decision": "ALLOWED", "reason": "", "severity": "INFO",
                "findings": [], "score": 0.0}
