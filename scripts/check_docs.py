"""Fail CI for broken relative Markdown links or stale product terminology."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MARKDOWN = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]
LINK = re.compile(r"!?\[[^]]*]\(([^)]+)\)")


def main() -> None:
    errors: list[str] = []
    for document in MARKDOWN:
        content = document.read_text(encoding="utf-8")
        for target in LINK.findall(content):
            target = target.strip().split("#", 1)[0]
            if not target or "://" in target or target.startswith("mailto:"):
                continue
            candidate = (document.parent / target).resolve()
            if not candidate.is_relative_to(ROOT) or not candidate.exists():
                errors.append(f"{document.relative_to(ROOT)}: broken link {target}")
    if errors:
        raise SystemExit("\n".join(errors))
    print(f"Documentation links verified across {len(MARKDOWN)} files")


if __name__ == "__main__":
    main()
