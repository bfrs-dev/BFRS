from __future__ import annotations

from functools import lru_cache
import json

import pytest

from bfrs.recovery.mnemonic.electrum_seed_validator import ElectrumSeedValidator
from bfrs.recovery.mnemonic.raw_mnemonic_scanner import RawMnemonicScanner
from bfrs.tools.revalidate_electrum_candidates import (
    FORMAT,
    build_parser,
    main,
    revalidate_report,
)


@lru_cache(maxsize=None)
def electrum_phrase() -> str:
    validator = ElectrumSeedValidator()
    words = sorted(validator.wordlists["english"])
    for number in range(100_000):
        phrase = " ".join([words[0]] * 11 + [words[number % len(words)]])
        if validator.validate(phrase).status == "ELECTRUM_SEED_VALID":
            return phrase
    raise AssertionError("deterministic Electrum fixture not found")


def current_candidate(image: bytes, encoding: str):
    result = RawMnemonicScanner().scan_bytes(image)
    return next(item.candidate for item in result.occurrences
                if item.candidate.mnemonic_standard == "ELECTRUM" and
                item.candidate.encoding == encoding)


def old_candidate(candidate, provenance, *, candidate_id="legacy-electrum"):
    return {
        "candidate_id": candidate_id,
        "fingerprint": candidate.fingerprint,
        "mnemonic_standard": "ELECTRUM",
        "seed_type": candidate.seed_type,
        "word_count": candidate.word_count,
        "duplicate_count": len(provenance),
        "correlated_sources": ["RAW_BYTES"],
        "provenance": provenance,
    }


def raw_occurrence(start, end, encoding="utf-8"):
    return {
        "source_kind": "RAW_BYTES",
        "physical_start": start,
        "physical_end": end,
        "encoding": encoding,
    }


def report(*candidates):
    return {"mnemonic_recovery": {"candidates": list(candidates)}}


def run_fixture(tmp_path, image: bytes, payload, **options):
    path = tmp_path / "fixture.img"
    path.write_bytes(image)
    return revalidate_report(payload, path, context_bytes=options.pop("context_bytes", 32),
                             **options)


def test_real_css_false_positive_is_rejected(tmp_path):
    css = (b'left-color\",\"border-left-style\",\"border-left-width\",'
           b'\"border-image-source\",\"border-image-slice\",\"border')
    legacy = {
        "candidate_id": "374c3d7a3351b4e9f02aa6af",
        "fingerprint": "a" * 64,
        "mnemonic_standard": "ELECTRUM",
        "seed_type": "standard",
        "word_count": 12,
        "duplicate_count": 1,
        "correlated_sources": ["RAW_BYTES"],
        "provenance": [raw_occurrence(0, len(css))],
    }
    result = run_fixture(tmp_path, css, report(legacy))
    candidate = result["candidates"][0]
    assert candidate["status"] == "REJECTED"
    assert candidate["occurrences"][0]["status"] == "REJECTED_NO_CURRENT_MATCH"


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16-le", "utf-16-be"])
def test_valid_candidate_survives_all_encodings_offsets_and_safe_output(tmp_path, encoding):
    phrase = electrum_phrase()
    prefix = b"\x00" * 18
    encoded = phrase.encode(encoding)
    image = prefix + encoded + b"\x00" * 20
    candidate = current_candidate(image, encoding)
    legacy = old_candidate(candidate, [raw_occurrence(
        candidate.physical_start, candidate.physical_end, encoding)])
    result = run_fixture(tmp_path, image, report(legacy))
    output = result["candidates"][0]
    occurrence = output["occurrences"][0]
    assert result["format"] == FORMAT
    assert output["status"] == "SURVIVED"
    assert occurrence["physical_start"] == len(prefix)
    assert occurrence["physical_end"] == len(prefix) + len(encoded)
    assert occurrence["old_encoding"] == encoding
    assert occurrence["new_encoding"] == encoding
    assert phrase not in json.dumps(result)


def test_mixed_occurrences_are_partial_and_duplicate_ranges_checked_once(tmp_path):
    phrase = electrum_phrase()
    good = phrase.encode()
    bad = ",".join(phrase.split()).encode()
    second_start = len(good) + 64
    image = good + b"\x00" * 64 + bad
    candidate = current_candidate(image, "utf-8")
    provenance = [
        raw_occurrence(0, len(good)),
        raw_occurrence(0, len(good)),
        raw_occurrence(second_start, second_start + len(bad)),
    ]
    result = run_fixture(tmp_path, image, report(old_candidate(candidate, provenance)),
                         context_bytes=16)
    output = result["candidates"][0]
    assert output["status"] == "PARTIAL"
    assert output["occurrences_total"] == 3
    assert output["occurrences_unique"] == 2
    assert output["occurrences_deduplicated"] == 1
    assert output["occurrences_checked"] == 2
    assert output["occurrences_survived"] == 1
    assert output["occurrences_rejected"] == 1


def test_neighboring_valid_seed_does_not_rescue_old_occurrence(tmp_path):
    phrase = electrum_phrase()
    bad = ",".join(phrase.split()).encode()
    good = phrase.encode()
    good_start = len(bad) + 32
    image = bad + b"\x00" * 32 + good
    current = current_candidate(image, "utf-8")
    assert current.physical_start == good_start
    legacy = old_candidate(current, [raw_occurrence(0, len(bad))])
    result = run_fixture(tmp_path, image, report(legacy), context_bytes=len(image))
    output = result["candidates"][0]
    assert output["status"] == "REJECTED"
    assert output["occurrences"][0]["status"] == "REJECTED_NO_CURRENT_MATCH"


def test_malformed_ranges_are_controlled_failures(tmp_path):
    image = b"small fixture"
    legacy = {
        "candidate_id": "malformed",
        "fingerprint": "b" * 64,
        "mnemonic_standard": "ELECTRUM",
        "duplicate_count": 2,
        "provenance": [
            raw_occurrence(None, 10),
            raw_occurrence(10, 10_000),
        ],
    }
    result = run_fixture(tmp_path, image, report(legacy))
    output = result["candidates"][0]
    assert output["status"] == "REJECTED"
    assert output["read_failures"] == 2
    assert result["summary"]["read_failures"] == 2
    assert {item["failure_reason"] for item in output["occurrences"]} == {
        "INVALID_PHYSICAL_RANGE"}


def test_bip39_and_electrum_v1_are_ignored(tmp_path):
    ignored = [{
        "candidate_id": standard,
        "fingerprint": standard,
        "mnemonic_standard": standard,
        "provenance": [raw_occurrence(0, 1)],
    } for standard in ("BIP39", "ELECTRUM_V1")]
    selected = {
        "candidate_id": "electrum",
        "fingerprint": "c" * 64,
        "mnemonic_standard": "ELECTRUM",
        "provenance": [raw_occurrence(0, 1)],
    }
    result = run_fixture(tmp_path, b"x", report(*ignored, selected))
    assert result["summary"]["input_candidates"] == 1
    assert [item["candidate_id"] for item in result["candidates"]] == ["electrum"]


def test_nearby_ranges_share_one_bounded_io_window(tmp_path):
    phrase = electrum_phrase().encode()
    second_start = len(phrase) + 40
    image = phrase + b"\x00" * 40 + phrase
    candidate = current_candidate(image, "utf-8")
    provenance = [raw_occurrence(0, len(phrase)),
                  raw_occurrence(second_start, second_start + len(phrase))]
    result = run_fixture(tmp_path, image, report(old_candidate(candidate, provenance)),
                         context_bytes=64)
    assert result["summary"]["io_windows_planned"] == 1
    assert result["summary"]["io_windows_read"] == 1
    assert result["summary"]["image_bytes_read"] == len(image)
    assert result["summary"]["survived_occurrences"] == 2


def test_cli_help_and_secret_free_json_output(tmp_path):
    assert "--context-bytes" in build_parser().format_help()
    phrase = electrum_phrase()
    image = tmp_path / "fixture.img"
    image.write_bytes(phrase.encode())
    candidate = current_candidate(image.read_bytes(), "utf-8")
    payload = report(old_candidate(candidate, [raw_occurrence(
        candidate.physical_start, candidate.physical_end)]))
    old_report = tmp_path / "old.json"
    old_report.write_text(json.dumps(payload), encoding="utf-8")
    output = tmp_path / "revalidated.json"
    assert main(["--report", str(old_report), "--image", str(image),
                 "--output", str(output), "--context-bytes", "16"]) == 0
    encoded = output.read_text(encoding="utf-8")
    assert phrase not in encoded
    assert json.loads(encoded)["summary"]["survived_candidates"] == 1
