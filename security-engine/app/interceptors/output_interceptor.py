import math
import re

# ---------------------------------------------------------------------------
# Structured secrets — compiled at import time
# ---------------------------------------------------------------------------
_SECRET_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE), "AWS_KEY"),
    (re.compile(r"ghp_[A-Za-z0-9_]{36,255}"), "GITHUB_TOKEN"),
    (re.compile(r"gho_[A-Za-z0-9_]{36,255}"), "GITHUB_TOKEN"),
    (re.compile(r"sk_live_[0-9a-zA-Z]{20,}"), "STRIPE_KEY"),
    (re.compile(r"rk_live_[0-9a-zA-Z]{20,}"), "STRIPE_KEY"),
    (re.compile(r"sk-ant-[A-Za-z0-9\-]{20,}"), "ANTHROPIC_KEY"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "OPENAI_KEY"),
    (re.compile(r"api[_\-]?key\s*[=:]\s*[A-Za-z0-9\-_]{16,}", re.IGNORECASE), "API_KEY"),
    (re.compile(r"-----BEGIN\s+(?:\w+\s+)?PRIVATE KEY-----", re.IGNORECASE), "SSH_PRIVATE_KEY"),
    (re.compile(r"ey[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"), "JWT_TOKEN"),
    (re.compile(r"password\s*[=:]\s*\S{8,}", re.IGNORECASE), "PASSWORD"),
]

# ---------------------------------------------------------------------------
# PII patterns
# ---------------------------------------------------------------------------
_PII_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"), "EMAIL"),
    (re.compile(r"(?:\+1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}"), "PHONE"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "SSN"),
    (re.compile(r"\b(\d{13,16})\b"), "CREDIT_CARD"),  # validated separately via Luhn
]

# ---------------------------------------------------------------------------
# Internal path / env-file patterns
# ---------------------------------------------------------------------------
_PATH_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"~/\.ssh/\S+"), "SENSITIVE_PATH"),
    (re.compile(r"/etc/shadow|/etc/passwd"), "SENSITIVE_PATH"),
    (re.compile(r"~/\.aws/credentials"), "SENSITIVE_PATH"),
    (re.compile(r"\S+\.(pem|key|p12|pfx)\b", re.IGNORECASE), "SENSITIVE_PATH"),
    (re.compile(r"(?m)^[A-Z_][A-Z0-9_]*\s*=\s*(?!\[REDACTED:)\S{8,}$"), "ENV_FILE_CONTENT"),
]

# Entropy threshold
_ENTROPY_THRESHOLD = 4.5
_MIN_TOKEN_LENGTH = 20


# ---------------------------------------------------------------------------
# Luhn check
# ---------------------------------------------------------------------------
def _luhn_check(digits: str) -> bool:
    total = 0
    reverse = digits[::-1]
    for i, ch in enumerate(reverse):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


# ---------------------------------------------------------------------------
# Detection layers
# ---------------------------------------------------------------------------
def _detect_secrets(content: str) -> tuple[str, list[dict]]:
    detections: list[dict] = []
    for pattern, label in _SECRET_PATTERNS:
        def _replace(m: re.Match, _label: str = label) -> str:
            detections.append({"type": _label})
            return f"[REDACTED:{_label}]"
        content = pattern.sub(_replace, content)
    return content, detections


def _detect_pii(content: str) -> tuple[str, list[dict]]:
    detections: list[dict] = []
    for pattern, label in _PII_PATTERNS:
        if label == "CREDIT_CARD":
            def _replace_cc(m: re.Match) -> str:
                digits = m.group(1)
                if _luhn_check(digits):
                    detections.append({"type": "CREDIT_CARD"})
                    return f"[REDACTED:CREDIT_CARD]"
                return m.group(0)
            content = pattern.sub(_replace_cc, content)
        else:
            def _replace(m: re.Match, _label: str = label) -> str:
                detections.append({"type": _label})
                return f"[REDACTED:{_label}]"
            content = pattern.sub(_replace, content)
    return content, detections


def _detect_paths(content: str) -> tuple[str, list[dict]]:
    detections: list[dict] = []
    for pattern, label in _PATH_PATTERNS:
        def _replace(m: re.Match, _label: str = label) -> str:
            detections.append({"type": _label})
            return f"[REDACTED:{_label}]"
        content = pattern.sub(_replace, content)
    return content, detections


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _detect_entropy(content: str) -> tuple[str, list[dict]]:
    detections: list[dict] = []
    # Split on whitespace but keep the separators so we can reconstruct the
    # original string (preserving newlines, tabs, multiple spaces, etc.)
    parts = re.split(r"(\s+)", content)
    result_parts: list[str] = []
    for part in parts:
        if (
            len(part) >= _MIN_TOKEN_LENGTH
            and not part.startswith("[REDACTED:")
            and _shannon_entropy(part) >= _ENTROPY_THRESHOLD
        ):
            detections.append({"type": "HIGH_ENTROPY_SECRET"})
            result_parts.append("[REDACTED:HIGH_ENTROPY_SECRET]")
        else:
            result_parts.append(part)
    return "".join(result_parts), detections


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def evaluate_output(content: str) -> dict:
    """Scan agent output for secrets, PII, paths, and high-entropy tokens.

    Returns:
        {
            "decision": "REDACTED" | "ALLOWED",
            "redacted_content": str,
            "detections": list[dict],
        }
    """
    all_detections: list[dict] = []

    content, d = _detect_secrets(content)
    all_detections.extend(d)

    content, d = _detect_pii(content)
    all_detections.extend(d)

    content, d = _detect_paths(content)
    all_detections.extend(d)

    content, d = _detect_entropy(content)
    all_detections.extend(d)

    decision = "REDACTED" if all_detections else "ALLOWED"
    return {
        "decision": decision,
        "redacted_content": content,
        "detections": all_detections,
    }
