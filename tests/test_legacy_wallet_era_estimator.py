from bfrs.core.models import ValidationStatus
from bfrs.recovery.berkeley_records import BerkeleyLeafPair, BerkeleyRecord, BerkeleyRecordExtraction
from bfrs.recovery.legacy_wallet_era_estimator import (
    EraConfidence, LegacyBitcoinWalletEraEstimatorV1, LegacyWalletEra,
)
from bfrs.recovery.logical_berkeley_reader import LogicalBerkeleyDatabaseIdentity
from bfrs.recovery.logical_btree_membership import LogicalBerkeleySubdatabaseIdentity
from bfrs.recovery.logical_wallet_record_decoder import LogicalBitcoinWalletRecordDecoderV1, LogicalWalletRecordState
from bfrs.validators.logical_encrypted_wallet_evidence import LogicalBerkeleyRecordPageContext


SOURCE = r"E:\images\wallet.dat"
SIZE = 512
PUB = bytes.fromhex("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")


def vec(value: bytes) -> bytes:
    return bytes((len(value),)) + value


def raw(payload: bytes, page_offset: int, local: int, slot: int) -> BerkeleyRecord:
    return BerkeleyRecord(slot, local, page_offset + local, len(payload), 1, False, payload)


def decoded(specs: list[tuple[str, bytes, bytes]], *, fragment=False):
    page_offset = 20000
    pairs = []
    for index, (name, suffix, value) in enumerate(specs):
        key = bytes((len(name),)) + name.encode() + suffix
        pairs.append(BerkeleyLeafPair(index, raw(key, page_offset, 20 + index * 40, index * 2),
                                      raw(value, page_offset, 260 + index * 40, index * 2 + 1)))
    status = ValidationStatus.FRAGMENT if fragment else ValidationStatus.STRUCTURAL
    extraction = BerkeleyRecordExtraction(4, status,
        tuple(record for pair in pairs for record in (pair.key, pair.value)),
        tuple(pairs), len(pairs) * 2, 0, 0, ())
    database = LogicalBerkeleyDatabaseIdentity(SOURCE, SIZE, "little", "mft-9")
    identity = LogicalBerkeleySubdatabaseIdentity(database, 0, 1, SIZE, "little")
    context = LogicalBerkeleyRecordPageContext(identity, SOURCE, 4, page_offset, SIZE, status, extraction)
    return LogicalBitcoinWalletRecordDecoderV1().decode_context(context)


def estimate(specs, *, fragment=False):
    return LegacyBitcoinWalletEraEstimatorV1().estimate(decoded(specs, fragment=fragment))


def key_spec():
    return ("key", vec(PUB), vec(b"opaque-private-serialization"))


def test_early_unencrypted_legacy_record_set_is_conservative():
    result = estimate([key_spec(), ("keymeta", vec(PUB), (1).to_bytes(4, "little") + (1).to_bytes(8, "little")),
                       ("defaultkey", b"", vec(PUB))])
    assert result.estimated_era is LegacyWalletEra.EARLY_2009_2010
    assert result.confidence is EraConfidence.MEDIUM
    assert "encryption_state_not_proven_by_absence" in result.missing_evidence


def test_encrypted_legacy_record_set():
    mkey = vec(bytes(48)) + vec(b"12345678") + (0).to_bytes(4, "little") + (25000).to_bytes(4, "little") + vec(b"")
    result = estimate([("ckey", vec(PUB), vec(bytes(48))), ("mkey", (1).to_bytes(4, "little"), mkey)])
    assert result.estimated_era is LegacyWalletEra.LEGACY_ENCRYPTED_2011_PLUS
    assert result.confidence is EraConfidence.HIGH


def test_defaultkey_is_evidence_but_not_an_exact_release():
    result = estimate([key_spec(), ("defaultkey", b"", vec(PUB))])
    assert result.estimated_era is LegacyWalletEra.EARLY_2009_2010
    assert not result.exact_version_determinable


def test_explicit_version_record_is_decoded_and_bounds_estimate():
    records = decoded([("version", b"", (32000).to_bytes(4, "little")), key_spec()])
    assert records[0].state is LogicalWalletRecordState.VALID
    assert records[0].wallet_version == 32000
    result = LegacyBitcoinWalletEraEstimatorV1().estimate(records)
    assert result.estimated_era is LegacyWalletEra.LEGACY_2010_2011
    assert result.maximum_plausible_version == 32000
    assert not result.exact_version_determinable


def test_explicit_minversion_record_sets_minimum():
    result = estimate([("minversion", b"", (40000).to_bytes(4, "little")), key_spec()])
    assert result.minimum_compatible_version == 40000
    assert result.maximum_plausible_version is None


def test_conflicting_version_evidence_lowers_confidence():
    result = estimate([("version", b"", (32000).to_bytes(4, "little")),
                       ("version", b"", (35000).to_bytes(4, "little")), key_spec()])
    assert result.confidence is EraConfidence.MEDIUM
    assert {item.finding for item in result.conflicting_evidence} == {"conflicting_version_value"}


def test_fragmentary_record_set_has_low_confidence():
    result = estimate([key_spec(), ("defaultkey", b"", vec(PUB))], fragment=True)
    assert result.confidence is EraConfidence.LOW
    assert "complete_database_evidence_missing" in result.missing_evidence


def test_unsupported_extended_keymeta_is_not_interpreted():
    result = LegacyBitcoinWalletEraEstimatorV1().estimate(decoded([
        ("keymeta", vec(PUB), (1).to_bytes(4, "little") + (1).to_bytes(8, "little") + b"extended")
    ]))
    assert result.estimated_era is LegacyWalletEra.UNKNOWN
    assert [item.finding for item in result.conflicting_evidence] == ["extended_keymeta_not_interpreted"]


def test_deterministic_hd_keymeta_layout_is_recognized():
    value = ((10).to_bytes(4, "little") + (1).to_bytes(8, "little")
             + vec(b"m/0'/1'") + b"\x01" * 20)
    records = decoded([("keymeta", vec(PUB), value)])
    assert records[0].state is LogicalWalletRecordState.VALID
    assert records[0].keymeta_hd_path == "m/0'/1'"
    result = LegacyBitcoinWalletEraEstimatorV1().estimate(records)
    assert result.estimated_era is LegacyWalletEra.HD_CAPABLE_LEGACY
    assert "deterministic_hd_keymeta" in {item.finding for item in result.positive_evidence}


def test_no_usable_version_evidence_reports_missing_fields():
    result = estimate([key_spec()])
    assert result.estimated_era is LegacyWalletEra.PRE_HD_LEGACY
    assert result.minimum_compatible_version is result.maximum_plausible_version is None
    assert result.missing_evidence[:2] == ("version_record_missing", "minversion_record_missing")


def test_every_positive_and_conflicting_item_preserves_provenance():
    result = estimate([("version", b"", (10000).to_bytes(4, "little")),
                       ("version", b"", (20000).to_bytes(4, "little"))])
    evidence = result.positive_evidence + result.conflicting_evidence
    assert evidence
    assert all(item.provenance.source == SOURCE.lower() for item in evidence)
    assert all(item.provenance.logical_page_identity[1] == 4 for item in evidence)
