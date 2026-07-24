"""Shared helpers for redacted static-analysis findings."""


def line_number(content: str, offset: int) -> int:
    """Return the one-based line containing a character offset."""
    return content.count("\n", 0, offset) + 1
