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
    assert VERSION == "2.0.0"


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


def test_public_docs_exist_and_do_not_claim_a_license() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "pre-1.0" in readme
    assert "not yet publicly licensed" in readme
    assert (ROOT / "SECURITY.md").is_file()
    assert (ROOT / "CONTRIBUTING.md").is_file()
    assert not (ROOT / "LICENSE").exists()
