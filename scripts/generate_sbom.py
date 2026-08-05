"""Generate a deterministic SPDX 2.3 JSON SBOM from uv.lock."""

from __future__ import annotations

import hashlib
import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "uv.lock"
OUTPUT = ROOT / "artifacts" / "skilltrustops.spdx.json"


def _identifier(value: str) -> str:
    return "".join(
        character if character.isalnum() or character in ".-" else "-"
        for character in value
    )


def main() -> None:
    lock_bytes = LOCK.read_bytes()
    lock = tomllib.loads(lock_bytes.decode())
    packages = []
    relationships = []
    root_id = "SPDXRef-Package-skilltrustops"
    for item in sorted(
        lock["package"], key=lambda value: (value["name"], value["version"])
    ):
        package_id = (
            f"SPDXRef-Package-{_identifier(item['name'])}-"
            f"{_identifier(item['version'])}"
        )
        checksums = []
        if "sdist" in item and "hash" in item["sdist"]:
            algorithm, value = item["sdist"]["hash"].split(":", 1)
            checksums.append(
                {
                    "algorithm": algorithm.upper().replace("SHA256", "SHA256"),
                    "checksumValue": value,
                }
            )
        packages.append(
            {
                "SPDXID": package_id,
                "name": item["name"],
                "versionInfo": item["version"],
                "downloadLocation": item.get("source", {}).get(
                    "registry", "NOASSERTION"
                ),
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                **({"checksums": checksums} if checksums else {}),
            }
        )
        if item["name"] != "skilltrustops":
            relationships.append(
                {
                    "spdxElementId": root_id,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": package_id,
                }
            )
    namespace_hash = hashlib.sha256(lock_bytes).hexdigest()
    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "skilltrustops-uv-lock",
        "documentNamespace": f"https://skilltrustops.dev/spdx/{namespace_hash}",
        "creationInfo": {
            "created": "2026-08-05T00:00:00Z",
            "creators": ["Tool: SkillTrustOps-sbom-generator"],
        },
        "packages": packages,
        "relationships": relationships,
    }
    OUTPUT.parent.mkdir(exist_ok=True)
    OUTPUT.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
