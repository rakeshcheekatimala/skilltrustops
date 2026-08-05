"""Installed-artifact smoke test used by trusted publishing."""

from pathlib import Path
from tempfile import TemporaryDirectory

from skilltrustops import scan


def test_installed_artifact(tmp_path: Path) -> None:
    package = tmp_path / "example"
    package.mkdir()
    skill = package / "SKILL.md"
    skill.write_text(
        "---\nname: example\ndescription: Installed artifact test.\n---\n\nTest.\n",
        encoding="utf-8",
    )
    report = scan(skill)
    assert report.summary.discovered == 1
    assert report.summary.errors == 0


if __name__ == "__main__":
    with TemporaryDirectory(prefix="skilltrustops-smoke-") as directory:
        test_installed_artifact(Path(directory))
