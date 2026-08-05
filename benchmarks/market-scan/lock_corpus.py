"""Create or verify the immutable per-skill corpus lock."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def build_lock(corpus: Path) -> dict[str, object]:
    entries = []
    for path in sorted(corpus.rglob("SKILL.md")):
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(corpus).as_posix()
        content = path.read_bytes()
        parts = Path(relative).parts
        repository = "/".join(parts[:2]) if len(parts) >= 2 else "unknown"
        entries.append(
            {
                "path": relative,
                "repository": repository,
                "bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    canonical = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    return {
        "schema_version": "1.0",
        "skills": len(entries),
        "entries_sha256": hashlib.sha256(canonical).hexdigest(),
        "entries": entries,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    generated = build_lock(args.corpus)
    if args.verify:
        expected = json.loads(args.lock.read_text(encoding="utf-8"))
        if generated != expected:
            raise SystemExit(
                "Corpus verification failed: count, path, size, or hash changed"
            )
        print(
            f"VERIFIED {generated['skills']} skills "
            f"{generated['entries_sha256']}"
        )
        return
    args.lock.write_text(json.dumps(generated, indent=2) + "\n", encoding="utf-8")
    print(f"LOCKED {generated['skills']} skills {generated['entries_sha256']}")


if __name__ == "__main__":
    main()

