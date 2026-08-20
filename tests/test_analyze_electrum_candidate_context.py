from __future__ import annotations

from functools import lru_cache
import io
import json

import pytest

from bfrs.recovery.mnemonic.electrum_seed_validator import ElectrumSeedValidator
from bfrs.tools.analyze_electrum_candidate_context import (
    FORMAT,
    analyze_report,
    build_parser,
    main,
)


@lru_cache(maxsize=None)
def electrum_phrase(word_count: int = 12) -> str:
    validator = ElectrumSeedValidator()
    words = sorted(validator.wordlists["english"])
    for number in range(100_000):
        phrase = " ".join([words[0]] * (word_count - 1) +
                          [words[number % len(words)]])
        if validator.validate(phrase).status == "ELECTRUM_SEED_VALID":
            return phrase
    raise AssertionError("deterministic Electrum fixture not found")


def occurrence(start, end, *, encoding="utf-8", word_count=12,
               status="SURVIVED", validation="ELECTRUM_SEED_VALID"):
    return {
        "physical_start": start,
        "physical_end": end,
        "old_encoding": encoding,
        "new_encoding": encoding,
        "status": status,
        "validation_status": validation,
        "seed_type": "standard",
        "word_count": word_count,
        "reason_codes": ["ELECTRUM_HMAC_SEED_VERSION_VALID"],
    }


def candidate(candidate_id, fingerprint, occurrences, *, priority="HIGH_REVIEW",
              standard="ELECTRUM"):
    return {
        "candidate_id": candidate_id,
        "fingerprint": fingerprint,
        "mnemonic_standard": standard,
        "revalidation_priority": priority,
        "status": "SURVIVED",
        "occurrences": occurrences,
    }


def report(*candidates):
    return {"format": "BFRS_ELECTRUM2_REVALIDATION_V1",
            "candidates": list(candidates)}


def analyze(tmp_path, image, payload, **kwargs):
    path = tmp_path / "fixture.img"
    path.write_bytes(image)
    return analyze_report(payload, path, context_bytes=kwargs.pop("context_bytes", 64),
                          **kwargs)


def wallet_fixture(encoding="utf-8"):
    phrase = electrum_phrase()
    prefix = ('{"wallet_type":"standard","keystore":{"seed_version":"01",'
              '"master_public_key":"xpub-safe","accounts":{"receiving":[]}},'
              '"electrum":true,"seed":"')
    suffix = '"}'
    image = (prefix + phrase + suffix).encode(encoding)
    start = len(prefix.encode(encoding))
    end = start + len(phrase.encode(encoding))
    return image, start, end


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16-le", "utf-16-be"])
def test_wallet_structure_confirms_context_and_all_encodings(tmp_path, encoding):
    image, start, end = wallet_fixture(encoding)
    payload = report(candidate("wallet", "a" * 64,
                               [occurrence(start, end, encoding=encoding)]))
    result = analyze(tmp_path, image, payload, context_bytes=512)
    item = result["candidates"][0]["occurrences"][0]
    assert result["format"] == FORMAT
    assert item["classification"] == "ELECTRUM_WALLET_CONTEXT_CONFIRMED"
    assert item["review_ranking"] == "VERY_HIGH_REVIEW"
    assert {"ELECTRUM_KEYSTORE_SIGNAL", "ELECTRUM_WALLET_TYPE_SIGNAL",
            "ELECTRUM_MASTER_PUBLIC_KEY_SIGNAL",
            "ELECTRUM_SEED_METADATA_SIGNAL"} <= set(item["reason_codes"])
    assert item["encoding"] == encoding


def test_valid_mnemonic_without_context_is_plaintext_candidate(tmp_path):
    phrase = electrum_phrase().encode()
    payload = report(candidate("bare", "b" * 64,
                               [occurrence(0, len(phrase))]))
    result = analyze(tmp_path, phrase, payload, context_bytes=0)
    item = result["candidates"][0]["occurrences"][0]
    assert item["classification"] == "PLAINTEXT_SEED_CANDIDATE"
    assert item["left_boundary_type"] == "BEGINNING_OF_IMAGE"
    assert item["right_boundary_type"] == "END_OF_IMAGE"
    assert item["standalone_phrase"] is True
    assert "STANDALONE_MNEMONIC_PHRASE" in item["reason_codes"]


@pytest.mark.parametrize("word_count", [12, 13])
@pytest.mark.parametrize("encoding", ["utf-8", "utf-16-le", "utf-16-be"])
def test_isolated_plaintext_line_is_candidate_for_12_13_words_and_encodings(
        tmp_path, word_count, encoding):
    phrase = electrum_phrase(word_count)
    prefix = "zzzzzz\r\n"
    suffix = "\r\nyyyyyy"
    image = (prefix + phrase + suffix).encode(encoding)
    start = len(prefix.encode(encoding))
    payload = report(candidate(f"plain-{encoding}-{word_count}", "a1" * 32, [
        occurrence(start, start + len(phrase.encode(encoding)),
                   encoding=encoding, word_count=word_count)]))
    result = analyze(tmp_path, image, payload)
    item = result["candidates"][0]["occurrences"][0]
    assert item["classification"] == "PLAINTEXT_SEED_CANDIDATE"
    assert item["review_ranking"] == "HIGH_REVIEW"
    assert item["left_boundary_type"] == "NEWLINE"
    assert item["right_boundary_type"] == "NEWLINE"
    assert item["line_isolation"] is True
    assert item["total_contiguous_dictionary_run_length"] == word_count


def test_seed_label_is_plaintext_candidate(tmp_path):
    phrase = electrum_phrase()
    prefix = "seed: "
    image = (prefix + phrase + "\n").encode()
    start = len(prefix)
    payload = report(candidate("label", "a2" * 32,
                               [occurrence(start, start + len(phrase.encode()))]))
    item = analyze(tmp_path, image, payload)["candidates"][0]["occurrences"][0]
    assert item["classification"] == "PLAINTEXT_SEED_CANDIDATE"
    assert item["left_boundary_type"] == "DELIMITER"
    assert item["line_isolation"] is True


def test_distant_html_css_javascript_do_not_reject_isolated_seed(tmp_path):
    phrase = electrum_phrase()
    suffix = ("\n" + "x" * (40 * 1024) +
              "<html><script>const page = window.document;</script>"
              "<style>.x { color:red; }</style></html>")
    image = (phrase + suffix).encode()
    payload = report(candidate("distant-code", "a3" * 32,
                               [occurrence(0, len(phrase.encode()))]))
    item = analyze(tmp_path, image, payload, context_bytes=64 * 1024)[
        "candidates"][0]["occurrences"][0]
    assert item["classification"] == "PLAINTEXT_SEED_CANDIDATE"
    assert item["near_html_signal"] is False
    assert item["near_css_signal"] is False
    assert item["near_javascript_signal"] is False
    assert item["signal_distance"]["html"] > 40 * 1024


def test_example_seed_context_is_textual_false_positive(tmp_path):
    phrase = electrum_phrase()
    prefix = "documentation example seed: "
    image = (prefix + phrase + "\n").encode()
    start = len(prefix)
    payload = report(candidate("example", "a4" * 32,
                               [occurrence(start, start + len(phrase.encode()))]))
    item = analyze(tmp_path, image, payload)["candidates"][0]["occurrences"][0]
    assert item["classification"] == "TEXTUAL_FALSE_POSITIVE"
    assert "EXAMPLE_OR_TEST_CONTEXT" in item["reason_codes"]


def test_nearby_css_does_not_reject_seed_on_its_own_line(tmp_path):
    phrase = electrum_phrase()
    prefix = ".page { color:red; border-width:1px; }\n"
    image = (prefix + phrase + "\n").encode()
    start = len(prefix)
    payload = report(candidate("css-note", "a5" * 32,
                               [occurrence(start, start + len(phrase.encode()))]))
    item = analyze(tmp_path, image, payload)["candidates"][0]["occurrences"][0]
    assert item["near_css_signal"] is True
    assert "LOCAL_CSS_CONTEXT" in item["reason_codes"]
    assert item["classification"] == "PLAINTEXT_SEED_CANDIDATE"


@pytest.mark.parametrize("wrapper,reason", [
    (("<script>const test_vector = {example_seed: \"", "\"};</script>"),
     "LOCAL_JAVASCRIPT_CONTEXT"),
    (("<style>.fixture { color:red; content:\"", "\"; }</style>"),
     "LOCAL_CSS_CONTEXT"),
])
def test_locally_embedded_javascript_and_css_are_textual_false_positives(
        tmp_path, wrapper, reason):
    phrase = electrum_phrase()
    text = wrapper[0] + phrase + wrapper[1]
    start = len(wrapper[0].encode())
    payload = report(candidate(reason, reason * 4,
                               [occurrence(start, start + len(phrase.encode()))]))
    result = analyze(tmp_path, text.encode(), payload)
    item = result["candidates"][0]["occurrences"][0]
    assert item["classification"] == "TEXTUAL_FALSE_POSITIVE"
    assert reason in item["reason_codes"]
    assert "MNEMONIC_EMBEDDED_IN_CODE" in item["reason_codes"]


def test_long_mnemonic_wordlist_is_textual_false_positive(tmp_path):
    validator = ElectrumSeedValidator()
    words = sorted(validator.wordlists["english"])
    phrase = electrum_phrase()
    prefix = " ".join(words[:44]) + " "
    suffix = " " + " ".join(words[44:88])
    text = prefix + phrase + suffix
    start = len(prefix.encode())
    payload = report(candidate("wordlist", "c" * 64,
                               [occurrence(start, start + len(phrase.encode()))]))
    result = analyze(tmp_path, text.encode(), payload)
    item = result["candidates"][0]["occurrences"][0]
    assert item["classification"] == "TEXTUAL_FALSE_POSITIVE"
    assert "LONG_WORDLIST_RUN" in item["reason_codes"]
    assert "MNEMONIC_EMBEDDED_IN_WORDLIST" in item["reason_codes"]


def test_dense_overlapping_candidates_are_false_positive(tmp_path):
    words = sorted(ElectrumSeedValidator().wordlists["english"])[:30]
    text = " ".join(words)
    starts = []
    cursor = 0
    for word in words:
        starts.append(cursor)
        cursor += len(word) + 1
    image = text.encode()
    candidates = []
    for number in range(5):
        start = starts[number]
        end = starts[number + 11] + len(words[number + 11])
        candidates.append(candidate(
            f"dense-{number}", f"{number + 1:064x}",
            [occurrence(start, end)]))
    result = analyze(tmp_path, image, report(*candidates))
    for item in result["candidates"]:
        analyzed = item["occurrences"][0]
        assert analyzed["classification"] == "TEXTUAL_FALSE_POSITIVE"
        assert "HIGH_LOCAL_MNEMONIC_DENSITY" in analyzed["reason_codes"]
        assert "SLIDING_WINDOW_PATTERN" in analyzed["reason_codes"]
        assert analyzed["overlapping_candidate_count"] == 4


def test_dense_but_separate_seed_lines_are_not_automatically_rejected(tmp_path):
    phrase = electrum_phrase()
    lines = [phrase for _ in range(5)]
    text = "\n".join(lines)
    candidates = []
    cursor = 0
    for number, line in enumerate(lines):
        candidates.append(candidate(
            f"separate-{number}", f"{number + 20:064x}",
            [occurrence(cursor, cursor + len(line.encode()))]))
        cursor += len(line.encode()) + 1
    result = analyze(tmp_path, text.encode(), report(*candidates))
    for output in result["candidates"]:
        item = output["occurrences"][0]
        assert "HIGH_LOCAL_MNEMONIC_DENSITY" in item["reason_codes"]
        assert item["overlapping_candidate_count"] == 0
        assert item["classification"] == "PLAINTEXT_SEED_CANDIDATE"


def test_selection_is_exactly_high_review_survived_electrum_12_or_13(tmp_path):
    phrase = electrum_phrase().encode()
    valid = occurrence(0, len(phrase))
    inputs = [
        candidate("selected", "d" * 64, [valid]),
        candidate("medium", "e" * 64, [valid], priority="MEDIUM_REVIEW"),
        candidate("low", "f" * 64, [valid], priority="LOW_REVIEW"),
        candidate("bip39", "1" * 64, [valid], standard="BIP39"),
        candidate("v1", "2" * 64, [valid], standard="ELECTRUM_V1"),
        candidate("fourteen", "3" * 64,
                  [occurrence(0, len(phrase), word_count=14)]),
        candidate("rejected", "4" * 64,
                  [occurrence(0, len(phrase), status="REJECTED_NO_CURRENT_MATCH")]),
        candidate("invalid", "5" * 64,
                  [occurrence(0, len(phrase), validation="REJECTED")]),
    ]
    result = analyze(tmp_path, phrase, report(*inputs), context_bytes=0)
    assert result["summary"]["input_candidates"] == len(inputs)
    assert result["summary"]["selected_candidates"] == 1
    assert result["summary"]["selected_occurrences"] == 1
    assert [item["candidate_id"] for item in result["candidates"]] == ["selected"]


def test_context_is_clipped_at_image_start_and_end_and_windows_merge(tmp_path):
    phrase = electrum_phrase().encode()
    gap = b"\x00" * 24
    image = phrase + gap + phrase
    second = len(phrase) + len(gap)
    payload = report(candidate("edges", "6" * 64, [
        occurrence(0, len(phrase)),
        occurrence(second, len(image)),
    ]))
    result = analyze(tmp_path, image, payload, context_bytes=64)
    assert result["summary"]["io_windows_planned"] == 1
    assert result["summary"]["io_windows_read"] == 1
    assert result["summary"]["image_bytes_read"] == len(image)
    contexts = [item["context_bytes_requested"]
                for item in result["candidates"][0]["occurrences"]]
    assert contexts == [min(len(image), len(phrase) + 64)] * 2
    assert {item["classification"] for item in
            result["candidates"][0]["occurrences"]} == {
                "PLAINTEXT_SEED_CANDIDATE"}


def test_read_failure_is_controlled_and_image_is_opened_once(tmp_path):
    phrase = electrum_phrase().encode()
    path = tmp_path / "fixture.img"
    path.write_bytes(phrase)
    payload = report(candidate("failure", "7" * 64,
                               [occurrence(0, len(phrase))]))
    calls = []

    class FailingStream(io.BytesIO):
        def read(self, size=-1):
            raise OSError("controlled failure")

    def factory(selected_path):
        calls.append(selected_path)
        return FailingStream(phrase)

    result = analyze_report(payload, path, context_bytes=0, stream_factory=factory)
    assert len(calls) == 1
    assert result["summary"]["read_failures"] == 1
    item = result["candidates"][0]["occurrences"][0]
    assert item["classification"] == "READ_FAILED"
    assert item["reason_codes"] == ["READ_FAILURE"]


def test_candidate_aggregate_does_not_hide_mixed_physical_contexts(tmp_path):
    phrase = electrum_phrase()
    wallet, first_start, first_end = wallet_fixture()
    html_prefix = b"\x00" * 512 + b"<!DOCTYPE html><html><body>"
    second_start = len(wallet) + len(html_prefix)
    image = wallet + html_prefix + phrase.encode() + b"</body></html>"
    payload = report(candidate("mixed", "8" * 64, [
        occurrence(first_start, first_end),
        occurrence(second_start, second_start + len(phrase.encode())),
    ]))
    result = analyze(tmp_path, image, payload, context_bytes=256)
    output = result["candidates"][0]
    assert output["classification"] == "INCONCLUSIVE"
    assert {item["classification"] for item in output["occurrences"]} == {
        "ELECTRUM_WALLET_CONTEXT_CONFIRMED", "PLAINTEXT_SEED_CANDIDATE"}


def test_report_is_secret_free_deterministic_and_cli_writes_json(tmp_path):
    phrase = electrum_phrase()
    prefix = ('{"wallet_type":"standard","keystore":{},"seed_type":"standard",'
              '"xprv":"xprv-SUPER-SECRET","seed":"')
    image_data = (prefix + phrase + '"}').encode()
    start = len(prefix.encode())
    payload = report(candidate("safe", "9" * 64,
                               [occurrence(start, start + len(phrase.encode()))]))
    image = tmp_path / "fixture.img"
    image.write_bytes(image_data)
    first = analyze_report(payload, image, context_bytes=64)
    second = analyze_report(payload, image, context_bytes=64)
    assert first == second
    encoded = json.dumps(first)
    assert phrase not in encoded
    assert "xprv-SUPER-SECRET" not in encoded

    source_report = tmp_path / "revalidation.json"
    source_report.write_text(json.dumps(payload), encoding="utf-8")
    output = tmp_path / "context.json"
    assert main(["--report", str(source_report), "--image", str(image),
                 "--output", str(output), "--context-bytes", "64"]) == 0
    assert json.loads(output.read_text(encoding="utf-8")) == first
    assert "--context-bytes" in build_parser().format_help()
