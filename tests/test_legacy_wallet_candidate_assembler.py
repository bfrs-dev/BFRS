from bfrs.core.models import ValidationStatus
from bfrs.recovery.berkeley_records import BerkeleyLeafPair, BerkeleyRecord, BerkeleyRecordExtraction
from bfrs.recovery.legacy_wallet_candidate_assembler import (
    EncryptionEvidenceState, LegacyBitcoinWalletCandidateAssemblerV1, RecoveryPriority,
)
from bfrs.recovery.logical_berkeley_reader import LogicalBerkeleyDatabaseIdentity
from bfrs.recovery.logical_btree_membership import LogicalBerkeleySubdatabaseIdentity
from bfrs.recovery.logical_wallet_record_decoder import LogicalBitcoinWalletRecordDecoderV1
from bfrs.validators.logical_encrypted_wallet_evidence import LogicalBerkeleyRecordPageContext


SOURCE = r"E:\images\wallet.img"
PAGE_SIZE = 1024
PUB1 = bytes.fromhex("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
PUB2 = bytes.fromhex("02C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5")


def vec(value: bytes) -> bytes:
    assert len(value) < 253
    return bytes((len(value),)) + value


def specs_key(pub=PUB1): return ("key", vec(pub), vec(b"private-serialization"))
def specs_meta(pub=PUB1): return ("keymeta", vec(pub), (1).to_bytes(4, "little") + (10).to_bytes(8, "little"))
def specs_default(pub=PUB1): return ("defaultkey", b"", vec(pub))
def specs_ckey(pub=PUB1): return ("ckey", vec(pub), vec(bytes(48)))
def specs_mkey():
    value = vec(bytes(48)) + vec(b"12345678") + (0).to_bytes(4, "little") + (25000).to_bytes(4, "little") + vec(b"")
    return ("mkey", (1).to_bytes(4, "little"), value)


def decode(specs, *, file_id="file-a", page=4, physical=10000, fragment=False):
    pairs = []
    for index, (name, suffix, value) in enumerate(specs):
        key = bytes((len(name),)) + name.encode() + suffix
        def record(payload, local, slot):
            return BerkeleyRecord(slot, local, physical + local, len(payload), 1, False, payload)
        pairs.append(BerkeleyLeafPair(index, record(key, 20 + index * 60, index * 2),
                                      record(value, 500 + index * 60, index * 2 + 1)))
    status = ValidationStatus.FRAGMENT if fragment else ValidationStatus.STRUCTURAL
    extraction = BerkeleyRecordExtraction(page, status,
        tuple(record for pair in pairs for record in (pair.key, pair.value)), tuple(pairs),
        len(pairs) * 2, 0, 0, ())
    database = LogicalBerkeleyDatabaseIdentity(SOURCE, PAGE_SIZE, "little", file_id)
    identity = LogicalBerkeleySubdatabaseIdentity(database, 0, 1, PAGE_SIZE, "little")
    context = LogicalBerkeleyRecordPageContext(identity, SOURCE, page, physical, PAGE_SIZE, status, extraction)
    return LogicalBitcoinWalletRecordDecoderV1().decode_context(context)


def assemble(*groups):
    return LegacyBitcoinWalletCandidateAssemblerV1().assemble(item for group in groups for item in group)


def test_coherent_early_unencrypted_wallet():
    candidate = assemble(decode([specs_key(), specs_meta(), specs_default()]))[0]
    assert candidate.record_counts == (("key", 1), ("ckey", 0), ("mkey", 0), ("keymeta", 1), ("defaultkey", 1), ("version", 0), ("minversion", 0))
    assert candidate.encryption_evidence is EncryptionEvidenceState.NO_ENCRYPTION_EVIDENCE


def test_multiple_key_records_and_private_payload_count():
    candidate = assemble(decode([specs_key(PUB1), specs_key(PUB2)]))[0]
    assert candidate.plain_key_records == candidate.structurally_recoverable_private_key_payloads == 2


def test_key_matches_keymeta_only_by_public_key():
    candidate = assemble(decode([specs_key(), specs_meta()]))[0]
    assert [item.relationship for item in candidate.matched_relationships] == ["key_keymeta"]
    assert candidate.matched_key_metadata == 1


def test_unrelated_keymeta_remains_unmatched():
    candidate = assemble(decode([specs_key(PUB1), specs_meta(PUB2)]))[0]
    assert candidate.unmatched_key_metadata == 1
    assert {item.record_type for item in candidate.unmatched_records} == {"key", "keymeta"}


def test_defaultkey_matches_plain_key():
    candidate = assemble(decode([specs_key(), specs_default()]))[0]
    assert [item.relationship for item in candidate.matched_relationships] == ["defaultkey_key"]


def test_coherent_encrypted_wallet_has_master_key_relationship():
    candidate = assemble(decode([specs_ckey(), specs_mkey()]))[0]
    assert candidate.encryption_evidence is EncryptionEvidenceState.ENCRYPTED_COMPLETE_EVIDENCE
    assert candidate.recovery_priority is RecoveryPriority.HIGH


def test_ckey_without_mkey():
    candidate = assemble(decode([specs_ckey()]))[0]
    assert candidate.encryption_evidence is EncryptionEvidenceState.ENCRYPTED_KEYS_WITHOUT_MASTER_KEY


def test_mkey_without_ckey():
    candidate = assemble(decode([specs_mkey()]))[0]
    assert candidate.encryption_evidence is EncryptionEvidenceState.MASTER_KEY_WITHOUT_CKEY


def test_version_and_minversion_propagate_to_estimator():
    candidate = assemble(decode([("version", b"", (60000).to_bytes(4, "little")),
                                 ("minversion", b"", (40000).to_bytes(4, "little"))]))[0]
    assert candidate.era_estimate.maximum_plausible_version == 60000
    assert candidate.era_estimate.minimum_compatible_version == 40000
    assert {item.relationship for item in candidate.matched_relationships} == {
        "version_database_context", "minversion_database_context"
    }
    assert candidate.unmatched_records == ()


def test_conflicting_database_identities_create_separate_candidates():
    candidates = assemble(decode([specs_key()], file_id="a"), decode([specs_meta()], file_id="b", physical=10100))
    assert len(candidates) == 2


def test_physically_close_different_databases_are_never_merged():
    candidates = assemble(decode([specs_ckey()], file_id="a", physical=20000),
                          decode([specs_mkey()], file_id="b", physical=20001))
    assert len(candidates) == 2
    assert {item.encryption_evidence for item in candidates} == {
        EncryptionEvidenceState.ENCRYPTED_KEYS_WITHOUT_MASTER_KEY,
        EncryptionEvidenceState.MASTER_KEY_WITHOUT_CKEY,
    }


def test_fragmentary_candidate_lowers_priority():
    candidate = assemble(decode([specs_key()], fragment=True))[0]
    assert candidate.fragmentary
    assert candidate.recovery_priority is RecoveryPriority.HIGH
    assert "complete_database_evidence_missing" in candidate.era_estimate.missing_evidence


def test_critical_requires_private_key_and_strong_structure():
    critical = assemble(decode([specs_key()]))[0]
    metadata = assemble(decode([specs_meta(), specs_default()]))[0]
    assert critical.recovery_priority is RecoveryPriority.CRITICAL
    assert metadata.recovery_priority is RecoveryPriority.LOW


def test_rejected_records_create_no_candidate():
    rejected = decode([("unknown", b"", b"")])
    assert LegacyBitcoinWalletCandidateAssemblerV1().assemble(rejected) == ()


def test_provenance_is_preserved_in_records_ranges_and_relationships():
    original = decode([specs_key(), specs_meta()])
    candidate = assemble(original)[0]
    assert candidate.records == original
    assert original[0].provenance.physical_key_range in candidate.physical_ranges
    assert candidate.matched_relationships[0].left.provenance == original[0].provenance


def test_output_order_is_deterministic_for_reversed_input():
    first = decode([specs_key()], file_id="z", physical=30000)
    second = decode([specs_ckey()], file_id="a", physical=10000)
    forward = assemble(first, second)
    reverse = assemble(tuple(reversed(second)), tuple(reversed(first)))
    assert forward == reverse
    assert tuple(item.candidate_id for item in forward) == tuple(sorted(item.candidate_id for item in forward))
