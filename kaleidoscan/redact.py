"""Secret redaction. Applied at normalization so no output ever carries a secret."""
from __future__ import annotations

import re

REDACTED = "[REDACTED]"
_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
]
# key = value / key: "value" with a secret-looking key: keep the key, drop the value.
_KV = re.compile(
    r"""(?ix)((?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth)[\w-]*
    \s*[:=]\s*)(?:"[^"\n]*"|'[^'\n]*'|[^\s,;"']+)"""
)


def redact(text: str) -> tuple[str, bool]:
    """Return (redacted_text, changed)."""
    out = text
    for p in _PATTERNS:
        out = p.sub(REDACTED, out)
    out = _KV.sub(lambda m: m.group(1) + REDACTED, out)
    return out, out != text
