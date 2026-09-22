from pathlib import Path
import tomllib

from bfrs.version import VERSION


ROOT = Path(__file__).resolve().parents[1]


def test_project_metadata_uses_code_version_and_main_cli_entry_point() -> None:
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert metadata["project"]["name"] == "bfrs"
    assert metadata["project"]["dynamic"] == ["version"]
    assert "version" not in metadata["project"]
    assert metadata["tool"]["setuptools"]["dynamic"]["version"] == {
        "attr": "bfrs.version.VERSION"
    }
    assert metadata["project"]["scripts"]["bfrs"] == "bfrs.cli:main"
    assert VERSION == "2.0.1"


def test_package_discovery_is_limited_to_bfrs_under_src() -> None:
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    setuptools = metadata["tool"]["setuptools"]

    assert setuptools["package-dir"] == {"": "src"}
    assert setuptools["packages"]["find"] == {
        "where": ["src"],
        "include": ["bfrs*"],
    }
    assert setuptools["package-data"]["bfrs.recovery.mnemonic"] == [
        "wordlists/*.txt"
    ]


def test_public_docs_and_gpl_license_metadata() -> None:
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")

    assert "pre-1.0" in readme
    assert "licensed under the GNU General Public License v3.0" in readme
    assert metadata["project"]["license"] == "GPL-3.0-only"
    assert metadata["project"]["license-files"] == ["LICENSE"]
    assert (ROOT / "SECURITY.md").is_file()
    assert (ROOT / "CONTRIBUTING.md").is_file()
    assert "GNU GENERAL PUBLIC LICENSE" in license_text
    assert "Version 3, 29 June 2007" in license_text
