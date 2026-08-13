from dataclasses import replace
import json

from bfrs.core.models import ValidationStatus
from bfrs.recovery.legacy_plaintext_key_crypto_validator import PlaintextKeyCryptoState
from bfrs.recovery.legacy_wallet_candidate_assembler import (
    EncryptionEvidenceState,
    LegacyBitcoinWalletCandidateAssemblerV1,
    RecoveryPriority,
)

from tests.test_legacy_plaintext_key_crypto_validator import decoded_key
from tests.test_legacy_wallet_candidate_assembler import (
    decode,
    specs_ckey,
    specs_default,
    specs_key,
    specs_meta,
    specs_mkey,
)


def assemble(*records):
    return LegacyBitcoinWalletCandidateAssemblerV1().assemble(records)[0]


def test_one_crypto_valid_key_makes_candidate_critical():
    candidate = assemble(decoded_key(1))
    assert candidate.priority is RecoveryPriority.CRITICAL
    assert candidate.crypto_valid_plain_keys == 1
    assert candidate.unique_crypto_valid_plain_keys == 1


def test_structural_key_without_crypto_confirmation_is_not_critical():
    candidate = assemble(*decode([specs_key()]))
    assert candidate.priority is not RecoveryPriority.CRITICAL
    assert candidate.crypto_valid_plain_keys == 0


def test_invalid_scalar_is_not_recovered():
    record = decoded_key(1, private_bytes=bytes(32))
    candidate = assemble(record)
    assert candidate.crypto_validation_results[0].state is PlaintextKeyCryptoState.PRIVATE_SCALAR_INVALID
    assert candidate.crypto_valid_plain_keys == 0
    assert candidate.crypto_invalid_plain_records == 1


def test_public_key_mismatch_is_not_recovered():
    candidate = assemble(decoded_key(1, key_scalar=2))
    assert candidate.crypto_validation_results[0].state is PlaintextKeyCryptoState.PUBLIC_KEY_MISMATCH
    assert candidate.crypto_valid_plain_keys == 0


def test_valid_k2_checksum_key_is_integrated():
    candidate = assemble(decoded_key(3, checksum=True))
    result = candidate.crypto_validation_results[0]
    assert result.state is PlaintextKeyCryptoState.CRYPTO_VALID
    assert result.serialization_layout == "K2_DER_CHECKSUM"
    assert candidate.priority is RecoveryPriority.CRITICAL


def test_invalid_k2_checksum_is_not_recovered():
    candidate = assemble(decoded_key(3, checksum=True, checksum_valid=False))
    assert candidate.crypto_validation_results[0].state is PlaintextKeyCryptoState.CHECKSUM_INVALID
    assert candidate.crypto_valid_plain_keys == 0


def test_two_unique_crypto_valid_keys_are_counted():
    candidate = assemble(decoded_key(4, page=4), decoded_key(5, page=5, physical=20000))
    assert candidate.crypto_valid_plain_keys == 2
    assert candidate.unique_crypto_valid_plain_keys == 2
    assert candidate.crypto_duplicate_occurrences == 0


def test_duplicate_crypto_valid_occurrences_keep_both_provenances():
    first = decoded_key(6, page=4)
    second = decoded_key(6, page=5, physical=20000)
    candidate = assemble(first, second)
    assert candidate.crypto_valid_plain_keys == 2
    assert candidate.unique_crypto_valid_plain_keys == 1
    assert candidate.crypto_duplicate_occurrences == 1
    assert tuple(result.provenance for result in candidate.crypto_validation_results) == (
        first.provenance,
        second.provenance,
    )


def test_conflicting_private_payloads_for_same_public_key_are_retained():
    valid = decoded_key(7, page=4)
    conflicting = replace(decoded_key(7, page=5, physical=20000), private_key_payload=b"\x01\x00")
    candidate = assemble(valid, conflicting)
    assert [item.finding for item in candidate.conflicts] == [
        "conflicting_plain_private_payloads_for_public_key"
    ]
    assert len(candidate.conflicts[0].records) == 2
    assert candidate.priority is RecoveryPriority.MEDIUM


def test_valid_and_invalid_payload_for_same_public_key_are_both_reported():
    valid = decoded_key(8, page=4)
    invalid = replace(decoded_key(8, page=5, physical=20000), private_key_payload=b"\x01\x00")
    candidate = assemble(valid, invalid)
    assert tuple(result.state for result in candidate.crypto_validation_results) == (
        PlaintextKeyCryptoState.CRYPTO_VALID,
        PlaintextKeyCryptoState.SERIALIZATION_UNSUPPORTED,
    )
    assert candidate.crypto_valid_plain_keys == 1
    assert candidate.crypto_invalid_plain_records == 1


def test_encrypted_ckey_and_mkey_remains_high():
    candidate = assemble(*decode([specs_ckey(), specs_mkey()]))
    assert candidate.encryption_state is EncryptionEvidenceState.ENCRYPTED_COMPLETE_EVIDENCE
    assert candidate.priority is RecoveryPriority.HIGH


def test_metadata_only_remains_low():
    candidate = assemble(*decode([specs_meta(), specs_default()]))
    assert candidate.priority is RecoveryPriority.LOW


def test_fragmentary_plaintext_candidate_is_high_but_not_recovered():
    candidate = assemble(*decode([specs_key()], fragment=True))
    assert candidate.fragmentary
    assert candidate.priority is RecoveryPriority.HIGH
    assert candidate.crypto_valid_plain_keys == 0


def test_crypto_integration_preserves_record_and_validation_provenance():
    record = decoded_key(9)
    candidate = assemble(record)
    assert candidate.records == (record,)
    assert candidate.provenance == (record.provenance,)
    assert candidate.crypto_validation_results[0].provenance == record.provenance


def test_integrated_output_order_is_deterministic():
    first = decoded_key(10, page=5, physical=20000)
    second = decoded_key(11, page=4, physical=10000)
    forward = assemble(first, second)
    reverse = assemble(second, first)
    assert forward == reverse
    assert tuple(result.provenance.logical_page_identity[1] for result in forward.crypto_validation_results) == (4, 5)
    forward_json = json.dumps(forward.to_report_dict(), sort_keys=True)
    reverse_json = json.dumps(reverse.to_report_dict(), sort_keys=True)
    assert forward_json == reverse_json
    assert "WIF" not in forward_json
    assert "address" not in forward_json
