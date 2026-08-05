"""Reconstruct the benchmark corpus from immutable public GitHub commits."""

from __future__ import annotations

import argparse
import shutil
import tarfile
import tempfile
import urllib.request
from pathlib import Path

import yaml


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() and any(args.output.iterdir()):
        parser.error("--output must be absent or empty")
    sources = yaml.safe_load(args.sources.read_text(encoding="utf-8"))["sources"]
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="skilltrust-corpus-") as temporary:
        temp = Path(temporary)
        for source in sources:
            repository = source["repository"]
            commit = source["commit"]
            owner, name = repository.split("/", 1)
            archive = temp / f"{owner}__{name}.tar.gz"
            url = f"https://api.github.com/repos/{repository}/tarball/{commit}"
            print(f"FETCH {repository}@{commit}")
            request = urllib.request.Request(
                url, headers={"User-Agent": "skilltrustops-benchmark/1.0"}
            )
            with urllib.request.urlopen(request, timeout=120) as response:
                archive.write_bytes(response.read())
            extracted = temp / f"{owner}__{name}"
            extracted.mkdir()
            with tarfile.open(archive, "r:gz") as bundle:
                bundle.extractall(extracted, filter="data")
            roots = [path for path in extracted.iterdir() if path.is_dir()]
            if len(roots) != 1:
                raise SystemExit(f"Unexpected archive layout for {repository}")
            destination = args.output / owner / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(roots[0]), destination)


if __name__ == "__main__":
    main()
