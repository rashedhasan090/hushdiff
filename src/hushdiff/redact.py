from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class RedactionSummary:
    """Counts of redactions by pattern family."""

    counts: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    def bump(self, family: str, n: int = 1) -> None:
        self.counts[family] = self.counts.get(family, 0) + n

    def as_dict(self) -> dict:
        return {"total": self.total, "by_family": dict(sorted(self.counts.items()))}


def _mask_keep_edges(value: str, family: str, keep: int = 4) -> str:
    if len(value) <= keep * 2:
        return f"[REDACTED:{family}]"
    return f"{value[:keep]}****REDACTED****{value[-keep:]}"


# Ordered list of (family, pattern, replacer). First match wins per span via
# sequential application; later patterns run on already-redacted text, so
# placeholders containing no secrets stay stable.
_PATTERNS: list[tuple[str, re.Pattern[str], Callable[[re.Match[str]], str]]] = []


def _register(
    family: str,
    pattern: str,
    flags: int = 0,
    replacer: Callable[[re.Match[str]], str] | None = None,
) -> None:
    rx = re.compile(pattern, flags)

    def default_repl(m: re.Match[str]) -> str:
        return _mask_keep_edges(m.group(0), family)

    _PATTERNS.append((family, rx, replacer or default_repl))


_register("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b")
_register("github_pat", r"\b(?:ghp|gho)_[A-Za-z0-9]{20,}\b")
_register("github_pat", r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")
_register("slack_token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")
_register(
    "jwt",
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    replacer=lambda m: "[REDACTED:jwt]",
)
_register(
    "private_key_block",
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    replacer=lambda m: "[REDACTED:private_key_block]",
)
_register(
    "secret_assignment",
    r"(?i)\b((?:api[_-]?key|password|passwd|secret|token|access[_-]?key|client[_-]?secret))\s*([:=])\s*([\"']?)([^\s\"']{8,})\3",
    replacer=lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}[REDACTED:secret_assignment]{m.group(3)}",
)


def redact_text(text: str) -> tuple[str, RedactionSummary]:
    """Apply all redaction patterns to arbitrary text."""
    summary = RedactionSummary()
    out = text
    for family, rx, replacer in _PATTERNS:

        def _counted(m: re.Match[str], fam: str = family, rep: Callable = replacer) -> str:
            summary.bump(fam)
            return rep(m)

        out = rx.sub(_counted, out)
    return out, summary


def redact_diff(diff_text: str) -> tuple[str, RedactionSummary]:
    """Redact secret-shaped tokens in a unified diff string."""
    return redact_text(diff_text)
