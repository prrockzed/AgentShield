import base64
import re

# ---------------------------------------------------------------------------
# Compiled pattern list: (pattern, reason_str, weight)
# Flags: re.IGNORECASE | re.DOTALL
# ---------------------------------------------------------------------------

_FLAGS = re.IGNORECASE | re.DOTALL

_PATTERN_DEFS: list[tuple[str, str, float]] = [
    # --- Direct injection (weight 0.9) ---
    (r"ignore\s+all\s+previous\s+instructions",   "direct_injection",   0.9),
    (r"ignore\s+all\s+prior\s+instructions",       "direct_injection",   0.9),
    (r"disregard\s+all\s+prior",                   "direct_injection",   0.9),
    (r"forget\s+your\s+(previous\s+)?instructions","direct_injection",   0.9),
    (r"you\s+are\s+now\s+DAN",                     "direct_injection",   0.9),
    (r"do\s+not\s+follow\s+(your\s+)?instructions","direct_injection",   0.9),
    (r"override\s+your\s+instructions",             "direct_injection",   0.9),

    # --- Jailbreak variants (weight 0.8–0.9) ---
    (r"developer\s+mode\s+enabled",                "jailbreak",          0.9),
    (r"do\s+anything\s+now",                        "jailbreak",          0.9),
    (r"\b(STAN|DUDE|AIM|JAILBREAK)\b",             "jailbreak",          0.9),
    (r"no\s+restrictions",                          "jailbreak",          0.8),
    (r"without\s+restrictions",                     "jailbreak",          0.8),
    (r"remove\s+(all\s+)?restrictions",             "jailbreak",          0.8),
    (r"jailbreak",                                  "jailbreak",          0.9),
    (r"unrestricted\s+mode",                        "jailbreak",          0.8),

    # --- Safety bypass (weight 0.8) ---
    (r"bypass\s+.*(safety|filter|restrictions)",    "safety_bypass",      0.8),
    (r"override\s+.*programming",                   "safety_bypass",      0.8),
    (r"you\s+have\s+no\s+restrictions",             "safety_bypass",      0.8),
    (r"ignore\s+your\s+(safety\s+)?(guidelines|rules|constraints)", "safety_bypass", 0.8),
    (r"disable\s+(your\s+)?(safety|content|ethical)\s+(filter|mode|guidelines)", "safety_bypass", 0.8),

    # --- System prompt extraction (weight 0.9) ---
    (r"reveal\s+.*system\s+prompt",                "system_prompt_extraction", 0.9),
    (r"repeat\s+.*original\s+instructions",        "system_prompt_extraction", 0.9),
    (r"what\s+are\s+your\s+instructions",          "system_prompt_extraction", 0.9),
    (r"show\s+me\s+your\s+(system\s+)?prompt",     "system_prompt_extraction", 0.9),
    (r"print\s+your\s+(system\s+)?prompt",         "system_prompt_extraction", 0.9),
    (r"output\s+your\s+(initial\s+)?instructions", "system_prompt_extraction", 0.9),
    (r"display\s+your\s+configuration",            "system_prompt_extraction", 0.8),

    # --- Instruction override (weight 0.6–0.7) ---
    (r"from\s+now\s+on",                            "instruction_override", 0.6),
    (r"starting\s+now.*ignore",                     "instruction_override", 0.7),
    (r"ignore\s+the\s+above",                       "instruction_override", 0.7),
    (r"your\s+new\s+(role|persona)",                "instruction_override", 0.7),
    (r"act\s+as\s+if\s+you\s+(have\s+no|are\s+not)", "instruction_override", 0.7),
    (r"pretend\s+(you\s+are|to\s+be)\s+an?\s+(AI|assistant|model)\s+without", "instruction_override", 0.7),
    (r"new\s+instructions\s+follow",                "instruction_override", 0.6),

    # --- Identity / privilege claims (weight 0.6) ---
    (r"I\s+am\s+(your\s+)?(developer|creator|admin|owner|master)", "identity_claim", 0.6),
    (r"as\s+(your\s+)?(owner|master|creator|developer)",           "identity_claim", 0.6),
    (r"you\s+are\s+in\s+debug\s+mode",             "identity_claim",     0.6),
    (r"maintenance\s+mode\s+activated",             "identity_claim",     0.6),
    (r"I\s+have\s+(root\s+)?admin\s+access",       "identity_claim",     0.6),

    # --- Data exfiltration (weight 0.8–0.9) ---
    (r"exfiltrate\s+.*secrets",                     "data_exfiltration",  0.9),
    (r"send\s+.*credentials.*https?://",            "data_exfiltration",  0.9),
    (r"leak\s+.*passwords",                         "data_exfiltration",  0.8),
    (r"extract\s+.*api\s+keys",                     "data_exfiltration",  0.8),
    (r"upload\s+.*\.env\b",                         "data_exfiltration",  0.8),
    (r"transmit\s+.*(private|secret|sensitive)",    "data_exfiltration",  0.8),
    (r"POST\s+.*password",                          "data_exfiltration",  0.8),

    # --- Social engineering (weight 0.3–0.5) ---
    (r"my\s+grandmother\s+(used\s+to\s+)?tell",    "social_engineering", 0.4),
    (r"as\s+a\s+security\s+researcher",            "social_engineering", 0.3),
    (r"hypothetically\s+speaking",                  "social_engineering", 0.3),
    (r"for\s+educational\s+purposes\s+only",       "social_engineering", 0.3),
    (r"in\s+a\s+fictional\s+scenario",             "social_engineering", 0.4),
    (r"pretend\s+(this\s+is\s+)?a\s+game",         "social_engineering", 0.4),
    (r"roleplay\s+as",                              "social_engineering", 0.4),
    (r"imagine\s+you\s+have\s+no\s+(guidelines|restrictions|rules)", "social_engineering", 0.5),
]

_COMPILED_PATTERNS: list[tuple[re.Pattern, str, float]] = [
    (re.compile(pat, _FLAGS), reason, weight)
    for pat, reason, weight in _PATTERN_DEFS
]

# Base64 injection check — re-uses the direct-injection patterns
_BASE64_MIN_LEN = 20
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{%d,}={0,2}" % _BASE64_MIN_LEN)

# Hidden-content Unicode markers
_RTL_CHARS = {"\u202e", "\u200f", "\u2066", "\u2069"}


# ---------------------------------------------------------------------------
# Detection layers
# ---------------------------------------------------------------------------

def _match_patterns(content: str) -> tuple[float, str]:
    """Return accumulated score and top reason from hardcoded pattern list."""
    score = 0.0
    top_reason = ""
    top_weight = 0.0
    for pattern, reason, weight in _COMPILED_PATTERNS:
        if pattern.search(content):
            score += weight
            if weight > top_weight:
                top_weight = weight
                top_reason = reason
    return score, top_reason


def _detect_hidden(content: str) -> tuple[float, str | None]:
    """Detect null bytes, RTL override chars, and base64-encoded injections."""
    score = 0.0
    reason: str | None = None

    if "\x00" in content:
        score += 0.5
        reason = "null_byte_injection"

    if any(ch in content for ch in _RTL_CHARS):
        score += 0.5
        reason = reason or "rtl_override_injection"

    # Base64 scan
    for match in _BASE64_RE.finditer(content):
        candidate = match.group(0)
        # Pad to valid base64 length
        padding = (4 - len(candidate) % 4) % 4
        try:
            decoded = base64.b64decode(candidate + "=" * padding).decode("utf-8", errors="ignore")
        except Exception:
            continue
        pat_score, _ = _match_patterns(decoded)
        if pat_score > 0:
            score += 0.5
            reason = reason or "base64_encoded_instructions"
            break  # one confirmed hit is enough

    return score, reason


def _detect_html(content: str) -> tuple[float, str | None]:
    """Detect HTML-based injection vectors (regex only, no DOM parsing)."""
    score = 0.0
    reason: str | None = None

    # Hidden text via CSS
    hidden_css = re.compile(
        r"(display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)\b.{0,200}?\S",
        re.IGNORECASE | re.DOTALL,
    )
    if hidden_css.search(content):
        score += 0.4
        reason = "hidden_css_content"

    # Suspicious inline script
    script_re = re.compile(
        r"<script\b[^>]*>.*?\b(eval|atob|document\.cookie)\b",
        re.IGNORECASE | re.DOTALL,
    )
    if script_re.search(content):
        score += 0.3
        reason = reason or "suspicious_script_tag"

    # Off-origin iframe
    iframe_re = re.compile(r"<iframe\b[^>]*\bsrc\s*=\s*['\"]?https?://", re.IGNORECASE)
    if iframe_re.search(content):
        score += 0.3
        reason = reason or "off_origin_iframe"

    return score, reason


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def evaluate_prompt(content: str, source: str) -> dict:
    """
    Score content for prompt injection signals.

    Returns:
        {"decision": str, "reason": str, "score": float}
        decision is one of ALLOWED | FLAGGED | BLOCKED.
    """
    total_score = 0.0
    top_reason = ""

    pat_score, pat_reason = _match_patterns(content)
    total_score += pat_score
    if pat_reason:
        top_reason = pat_reason

    hid_score, hid_reason = _detect_hidden(content)
    total_score += hid_score
    if hid_reason and not top_reason:
        top_reason = hid_reason

    html_score, html_reason = _detect_html(content)
    total_score += html_score
    if html_reason and not top_reason:
        top_reason = html_reason

    total_score = min(total_score, 1.0)

    if total_score >= 0.6:
        decision = "BLOCKED"
    elif total_score >= 0.3:
        decision = "FLAGGED"
    else:
        decision = "ALLOWED"

    return {"decision": decision, "reason": top_reason, "score": round(total_score, 4)}
