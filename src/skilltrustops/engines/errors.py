"""Errors raised by optional scanner engines."""


class ScannerError(RuntimeError):
    """An external scanner was unavailable or could not complete safely."""
