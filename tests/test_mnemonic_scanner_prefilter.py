"""Correctness and instrumentation tests for the bytes-level mnemonic prefilter."""

import hashlib

from bfrs.recovery.mnemonic.bip39_validator import BIP39Validator
from bfrs.recovery.mnemonic.raw_mnemonic_scanner import RawMnemonicScanner


def _bip39_phrase(entropy_bytes: int) -> str:
    validator = BIP39Validator()
    entropy = bytes(range(entropy_bytes))
    entropy_bits = "".join(f"{byte:08b}" for byte in entropy)
    checksum_length = len(entropy_bits) // 32
    checksum = "".join(
        f"{byte:08b}" for byte in hashlib.sha256(entropy).digest()
    )[:checksum_length]
    indices = validator.indices["english"]
    words = sorted(indices, key=indices.get)
    bits = entropy_bits + checksum
    return " ".join(words[int(bits[offset:offset + 11], 2)]
                    for offset in range(0, len(bits), 11))


def test_prefilter_rejects_binary_without_candidate_or_expensive_validation():
    data = bytes(range(256)) * 128
    result = RawMnemonicScanner(chunk_size=8192, overlap=4096).scan_bytes(data)

    assert result.occurrences == ()
    assert result.prefilter_windows == 0
    assert result.expensive_validations == 0
    assert result.bip39_validations == 0
    assert result.electrum_validations == 0
    assert result.electrum_v1_validations == 0


def test_prefilter_nominates_small_windows_then_preserves_full_bip39_validation():
    phrase12 = _bip39_phrase(16)
    phrase24 = _bip39_phrase(32)
    payload = b"\x00binary:" + phrase12.encode() + b":gap:" + phrase24.encode() + b":end"

    result = RawMnemonicScanner(chunk_size=8192, overlap=4096).scan_bytes(payload)
    bip39 = [item for item in result.occurrences
             if item.candidate.mnemonic_standard == "BIP39"]

    assert {item.candidate.word_count for item in bip39} == {12, 24}
    assert all(item.candidate.checksum_valid is True for item in bip39)
    assert result.prefilter_windows >= 1
    assert result.bip39_validations >= 2


def test_prefilter_near_matches_do_not_bypass_checksum_or_word_membership():
    phrase = _bip39_phrase(16).split()
    validator = BIP39Validator()
    invalid_checksum = next(
        " ".join(phrase[:-1] + [replacement])
        for replacement in validator.indices["english"]
        if replacement != phrase[-1] and
        validator.validate(" ".join(phrase[:-1] + [replacement])).status ==
        "BIP39_CHECKSUM_INVALID"
    )
    invalid_word = " ".join(phrase[:-1] + ["notaword"])

    scanner = RawMnemonicScanner(chunk_size=8192, overlap=4096)
    results = (scanner.scan_bytes(invalid_checksum.encode()),
               scanner.scan_bytes(invalid_word.encode()))

    assert not [item for result in results for item in result.occurrences
                if item.candidate.mnemonic_standard == "BIP39"]
    assert results[0].bip39_validations >= 1


def test_long_wordlist_run_has_bounded_candidate_only_validation_work():
    payload = (" ".join(["abandon"] * 256)).encode()
    result = RawMnemonicScanner(chunk_size=8192, overlap=4096).scan_bytes(payload)

    assert not result.occurrences
    assert result.prefilter_windows == 1
    assert result.expensive_validations < 5_000
