"""hushdiff: redact secret-shaped tokens from unified diffs."""

from .redact import RedactionSummary, redact_diff

__all__ = ["RedactionSummary", "redact_diff"]
__version__ = "0.1.0"
