from __future__ import annotations

from collections.abc import Iterator
import hashlib

import pytest

from bfrs.core.chunk_reader import Chunk, ChunkReader
from bfrs.recovery.mnemonic.electrum_v1_validator import ElectrumV1Validator
from bfrs.scanners.fast_scanner import FastScanner
from bfrs.scanners.target_registry import (
    ARMORY_HEADER,
    MULTIBIT_NETWORK,
    TARGET_ARMORY,
    TARGET_BITCOIN_CORE,
    TARGET_ELECTRUM,
    TARGET_INTERNAL,
    TARGET_MULTIBIT,
    TARGET_SECRETS,
    build_target_selection,
    parse_targets,
)


def _scan(tmp_path, data, targets, *, chunk_size=256, overlap=64):
    path = tmp_path / "targets.img"
    path.write_bytes(data)
    selection = build_target_selection(frozenset(targets), include_mnemonics=False)
    reader = ChunkReader(path, chunk_size=chunk_size, overlap=overlap)
    return list(FastScanner(selection.signatures).scan(reader))


def _multibit_wallet(*, encrypted=False, public=True, private=True):
    result = bytearray((0x0a, len(MULTIBIT_NETWORK)))
    result.extend(MULTIBIT_NETWORK)
    if public:
        result.extend(b"\x12\x21" + b"\x02" + b"P" * 32)
    if private:
        result.extend(b"\x1a\x20" + b"K" * 32)
    if encrypted:
        result.extend(b"Salted__" + b"E" * 32)
    return bytes(result)


def test_multibit_valid_protobuf_wallet_requires_correlated_structure(tmp_path):
    hits = _scan(tmp_path, _multibit_wallet(), {TARGET_MULTIBIT})
    network = next(item for item in hits if item.hit_type == "multibit_network_anchor")
    assert network.structural_status == "STRONG"
    assert network.validation_status == "PROTOBUF_STRUCTURAL_VALID"
    assert network.confidence >= 0.9
    assert {"PROTOBUF_NETWORK_FIELD", "EC_PUBLIC_KEY_FIELD",
            "EC_PRIVATE_KEY_FIELD"} <= set(network.correlated_evidence)


def test_multibit_network_string_without_protobuf_is_not_high(tmp_path):
    hits = _scan(tmp_path, b"ordinary " + MULTIBIT_NETWORK + b" text",
                 {TARGET_MULTIBIT})
    assert len(hits) == 1
    assert hits[0].structural_status == "WEAK"
    assert hits[0].confidence < 0.5


@pytest.mark.parametrize("fixture,reason", [
    (_multibit_wallet(encrypted=True, private=False),
     "MULTIBIT_PROTOBUF_WALLET_CONFIRMED"),
    (_multibit_wallet(public=False), "MULTIBIT_PROTOBUF_KEY_FRAGMENT"),
])
def test_multibit_encrypted_and_unencrypted_key_structures(tmp_path, fixture, reason):
    hits = _scan(tmp_path, fixture, {TARGET_MULTIBIT})
    network = next(item for item in hits if item.hit_type == "multibit_network_anchor")
    assert reason in network.reason_codes
    assert network.structural_status in {"STRONG", "FRAGMENT"}


def test_multibit_malformed_protobuf_anchor_is_weak(tmp_path):
    hits = _scan(tmp_path, b"\x0a\xff" + MULTIBIT_NETWORK,
                 {TARGET_MULTIBIT})
    network = next(item for item in hits if item.hit_type == "multibit_network_anchor")
    assert network.validation_status == "ANCHOR_ONLY"
    assert network.structural_status == "WEAK"


def test_multibit_hd_and_legacy_markers_are_format_specific_fragments(tmp_path):
    hd = _scan(
        tmp_path, b"mbhd.wallet.aes wallet recovery encrypted mbhd",
        {TARGET_MULTIBIT})[0]
    assert hd.artifact_kind == "MULTIBIT_HD"
    assert hd.structural_status == "FRAGMENT"
    assert hd.safe_metadata["mnemonic_standard"] == "UNCONFIRMED"
    legacy = _scan(
        tmp_path, b"\xac\xed\x00\x05 serialized com.google.bitcoin wallet",
        {TARGET_MULTIBIT})[0]
    assert legacy.artifact_kind == "MULTIBIT_CLASSIC_LEGACY"
    assert legacy.validation_status == "JAVA_SERIALIZED_WALLET_FRAGMENT"


def test_multibit_chunk_boundary_and_overlap_ownership(tmp_path):
    prefix = b"X" * 28
    hits = _scan(tmp_path, prefix + MULTIBIT_NETWORK + b"Z" * 40,
                 {TARGET_MULTIBIT}, chunk_size=48,
                 overlap=28)
    network = [item for item in hits if item.hit_type == "multibit_network_anchor"]
    assert len(network) == 1
    assert network[0].start_offset == len(prefix)


def test_armory_full_fragment_signature_only_and_random_text(tmp_path):
    full = ARMORY_HEADER + (1).to_bytes(4, "little") + b"walletID:x rootKey:y"
    fragment = ARMORY_HEADER + (2).to_bytes(4, "little")
    signature_only = ARMORY_HEADER
    random_text = b"ordinary BAWALLET text without binary magic"
    assert _scan(tmp_path, full, {TARGET_ARMORY})[0].structural_status == "STRONG"
    assert _scan(tmp_path, fragment, {TARGET_ARMORY})[0].structural_status == "FRAGMENT"
    assert _scan(tmp_path, signature_only, {TARGET_ARMORY})[0].structural_status == "WEAK"
    assert _scan(tmp_path, random_text, {TARGET_ARMORY}) == []


def test_armory_boundary_duplicate_suppression_and_paper_routing(tmp_path):
    prefix = b"X" * 29
    hits = _scan(tmp_path, prefix + ARMORY_HEADER + b"\x00" * 40,
                 {TARGET_ARMORY}, chunk_size=40,
                 overlap=18)
    wallet = [item for item in hits if item.hit_type == "armory_wallet_header"]
    assert len(wallet) == 1
    assert wallet[0].start_offset == len(prefix)
    paper = _scan(tmp_path, b"Armory Paper Backup", {TARGET_ARMORY})[0]
    assert paper.artifact_kind == "ARMORY_PAPER_BACKUP"
    assert paper.recommended_recovery_action == "DOCUMENT_RECOVERY"


def test_one_shared_chunk_iteration_returns_all_wallet_families(tmp_path):
    class CountingReader(ChunkReader):
        calls = 0

        def iter_chunks(self, start=0, end=None) -> Iterator[Chunk]:
            self.calls += 1
            yield from super().iter_chunks(start=start, end=end)

    parts = (
        b"\x04ckey-invalid-but-owned-anchor",
        _multibit_wallet(),
        ARMORY_HEADER + (1).to_bytes(4, "little") + b"walletID:x rootKey:y",
        b"BIE1",
    )
    gaps = (b"A" * 17, b"B" * 19, b"C" * 23)
    data = parts[0] + gaps[0] + parts[1] + gaps[1] + parts[2] + gaps[2] + parts[3]
    path = tmp_path / "integrated.img"
    path.write_bytes(data)
    targets = parse_targets("bitcoin-core,multibit,armory,electrum")
    selection = build_target_selection(targets, include_mnemonics=False)
    reader = CountingReader(path, chunk_size=96, overlap=64)
    hits = list(FastScanner(selection.signatures).scan(reader))
    assert reader.calls == 1
    assert {item.target for item in hits} >= {
        TARGET_BITCOIN_CORE, TARGET_MULTIBIT, TARGET_ARMORY, TARGET_ELECTRUM}
    for pattern in (b"\x04ckey", MULTIBIT_NETWORK, ARMORY_HEADER, b"BIE1"):
        expected = data.index(pattern)
        assert any(item.start_offset == expected for item in hits)


def test_target_finding_safe_dict_has_no_payload(tmp_path):
    secret = b"K" * 32
    hits = _scan(tmp_path, _multibit_wallet(), {TARGET_MULTIBIT})
    payload = hits[0].safe_dict()
    encoded = repr(payload)
    assert secret.decode() not in encoded
    assert "raw" not in payload
    assert {"target", "wallet_family", "artifact_kind", "physical_start",
            "physical_end", "structural_status", "validation_status",
            "confidence", "reason_codes", "safe_metadata",
            "recommended_recovery_action"} <= set(payload)


def test_individual_target_selection_does_not_enable_other_wallet_families():
    bitcoin = build_target_selection(
        frozenset({TARGET_BITCOIN_CORE}), include_mnemonics=False)
    assert {item.target for item in bitcoin.signatures} == {
        TARGET_BITCOIN_CORE, "internal"}
    armory = build_target_selection(
        frozenset({TARGET_ARMORY}), include_mnemonics=False)
    assert {item.target for item in armory.signatures} == {TARGET_ARMORY}


def _base58check(payload):
    alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    raw = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    number = int.from_bytes(raw, "big")
    encoded = bytearray()
    while number:
        number, remainder = divmod(number, 58)
        encoded.append(alphabet[remainder])
    return bytes(alphabet[:1] * (len(raw) - len(raw.lstrip(b"\x00"))) +
                 bytes(reversed(encoded)))


def test_validated_wif_detector_uses_shared_chunk_and_reports_only_fingerprint(tmp_path):
    private = bytes.fromhex("11" * 32)
    wif = _base58check(b"\x80" + private + b"\x01")
    path = tmp_path / "wif.img"
    path.write_bytes(b"prefix " + wif + b" suffix")
    selection = build_target_selection(
        frozenset({TARGET_SECRETS}), include_mnemonics=False)
    hits = list(FastScanner(
        selection.signatures, chunk_detectors=selection.chunk_detectors).scan(
            ChunkReader(path, chunk_size=128, overlap=64)))
    validated = [item for item in hits if item.hit_type == "validated_wif"]
    assert len(validated) == 1
    assert validated[0].validation_status == "BASE58CHECK_AND_SECP256K1_VALID"
    encoded = repr(validated[0].safe_dict())
    assert wif.decode() not in encoded
    assert private.hex() not in encoded


def test_existing_strict_mnemonic_validator_runs_as_shared_chunk_detector(tmp_path):
    phrase = " ".join(ElectrumV1Validator().mn_encode(
        "000102030405060708090a0b0c0d0e0f"))
    path = tmp_path / "mnemonic.img"
    path.write_bytes(("header\n" + phrase + "\nfooter").encode())
    selection = build_target_selection(
        frozenset({TARGET_ELECTRUM}), include_mnemonics=True)
    hits = list(FastScanner(
        selection.signatures, chunk_detectors=selection.chunk_detectors).scan(
            ChunkReader(path, chunk_size=8192, overlap=4096)))
    mnemonic = [item for item in hits if item.artifact_kind == "mnemonic"]
    assert len(mnemonic) == 1
    assert mnemonic[0].validation_status == "ELECTRUM_V1_STRICT_VALID"
    assert mnemonic[0].start_offset == len("header\n".encode())
    assert phrase not in repr(mnemonic[0].safe_dict())


def test_filesystem_anchors_are_internal_but_remain_streamed_downstream(tmp_path):
    path = tmp_path / "filesystem.img"
    path.write_bytes(b"FILE--INDX--\x04ckey")
    selection = build_target_selection(
        parse_targets("bitcoin-core,electrum"), include_mnemonics=False)
    updates = []

    hits = list(FastScanner(selection.signatures).scan(
        ChunkReader(path, chunk_size=64, overlap=16),
        progress=updates.append,
    ))

    filesystem = [item for item in hits if item.artifact_kind.startswith("filesystem")]
    assert {item.hit_type for item in filesystem} == {
        "ntfs_file_record_anchor", "ntfs_indx_record_anchor"}
    assert {item.target for item in filesystem} == {TARGET_INTERNAL}
    assert updates[-1].anchors_total == 2
    assert updates[-1].findings_total == 1
    assert updates[-1].findings_by_target == {TARGET_BITCOIN_CORE: 1}


def test_shared_boot_anchor_owner_is_stable_across_target_combinations():
    selections = (
        build_target_selection(frozenset({TARGET_BITCOIN_CORE}),
                               include_mnemonics=False),
        build_target_selection(frozenset({TARGET_ELECTRUM}),
                               include_mnemonics=False),
        build_target_selection(frozenset({TARGET_ELECTRUM, TARGET_BITCOIN_CORE}),
                               include_mnemonics=False),
    )

    for selection in selections:
        boot = [item for item in selection.signatures
                if item.name == "ntfs_boot_sector_oem_anchor"]
        assert len(boot) == 1
        assert boot[0].target == TARGET_INTERNAL


def test_wallet_signatures_keep_wallet_target_ownership(tmp_path):
    hits = _scan(
        tmp_path,
        b"\x04ckey--BIE1",
        {TARGET_BITCOIN_CORE, TARGET_ELECTRUM},
    )

    assert next(item for item in hits if item.hit_type == "bitcoin_ckey").target == (
        TARGET_BITCOIN_CORE)
    assert next(item for item in hits if item.hit_type ==
                "electrum_bie1_raw_anchor").target == TARGET_ELECTRUM
