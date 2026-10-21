import json

import pytest

from bfrs.recovery.rtf_text import extract_rtf, RTFError
from bfrs.recovery import rtf_text
from bfrs.recovery.document_scan import scan_document
from bfrs.recovery.mnemonic.document_seed_recovery import DocumentSeedRecovery
from bfrs.recovery.mnemonic.raw_mnemonic_scanner import RawMnemonicScanner
from bfrs.cli import main
from tests.test_cli import basic_arguments, valid_wif
from tests.test_mnemonic_recovery_v1 import bip39_phrase


def test_wordpad_formatting_preserves_contiguous_key(tmp_path):
    key = valid_wif().decode()
    data = ('{\\rtf1\\ansi\\ansicpg1250\\deff0'
            '{\\fonttbl{\\f0\\fnil\\fcharset238 Calibri;}}'
            '\\viewkind4\\uc1\\pard\\f0\\fs22 ' + key[:10] +
            '{\\b ' + key[10:30] + '}\\i ' + key[30:] + '\\par}').encode()
    path = tmp_path / 'backup.rtf'
    path.write_bytes(data)
    hits, coverage = scan_document(path, targets={'secrets'}, mnemonic_standards=())
    assert coverage['status'] == 'SCANNED'
    assert len(hits) == 1
    assert hits[0].safe_dict()['physical_start'] is None
    assert key not in json.dumps(hits[0].safe_dict())
    assert key.encode() in extract_rtf(data)


def test_cp1250_hex_font_charset_and_unicode():
    text = extract_rtf(br"{\rtf1\ansi\ansicpg1250 za\'bf\'f3\'b3\'e6\par\u261?}")
    assert text.decode() == 'zażółć\ną'
    text = extract_rtf(br"{\rtf1\ansi\ansicpg1252\deff0{\fonttbl{\f0\fcharset238 Arial;}}\f0 \'b9}")
    assert text.decode().strip() == 'ą'


def test_unicode_fallback_scopes_and_surrogate_pair():
    data = br"{\rtf1\uc1 \u97?{\uc2\u98??}\u99?\uc0\u-10179\u-8704}"
    assert extract_rtf(data).decode() == 'abc😀'
    assert extract_rtf(br"{\rtf1\uc1\u97a\u98\'3f}") == b'ab'


def test_escaped_symbols_paragraphs_tabs_and_source_newlines():
    assert extract_rtf(b'{\\rtf1 ab\r\ncd\\tab \\{x\\}\\\\\\par end}') == b'abcd\t{x}\\\nend'


def test_skipped_destinations_and_binary_do_not_leak_secret(tmp_path):
    key = valid_wif()
    data = (br'{\rtf1 safe{\*\unknown ' + key + br'}{\pict ' + key +
            br'}{\object{\objdata ' + key + br'}}{\info{\author ' + key +
            br'}}{\pict\bin5 ' + b'{\\}xx' + br'} end}')
    # Five binary bytes include braces/backslashes and must not alter nesting.
    assert len(b'{\\}xx') == 5
    text = extract_rtf(data)
    assert key not in text
    assert b'end' in text


def test_hyperlink_field_returns_display_text_only():
    data = br'{\rtf1 {\field{\*\fldinst HYPERLINK "https://example.test"}{\fldrslt visible}}}'
    assert extract_rtf(data).strip() == b'visible'


@pytest.mark.parametrize('data,reason', [
    (b'{\\rtf1 unclosed', 'RTF_UNBALANCED_GROUP'),
    (b'plain text', 'RTF_FORMAT_UNCONFIRMED'),
    (br"{\rtf1 \'zz}", 'RTF_INVALID_HEX'),
    (br'{\rtf1\bin99 x}', 'RTF_INVALID_BINARY_LENGTH'),
    (br'{\rtf1\uc-1 x}', 'RTF_INVALID_UNICODE_FALLBACK'),
    (br'{\rtf1\u-10179?}', 'RTF_INVALID_UNICODE'),
    (br'{\rtf1\ansicpg99999 x}', 'RTF_ENCODING_UNSUPPORTED_OR_INVALID'),
    (br'{\rtf1\upr x}', 'RTF_ALTERNATE_UNICODE_UNSUPPORTED'),
    (br'{\rtf1 x}junk', 'RTF_TRAILING_DATA'),
])
def test_malformed_or_unsupported_is_explicit(data, reason):
    with pytest.raises(RTFError, match=reason):
        extract_rtf(data)


def test_limits(monkeypatch):
    monkeypatch.setattr(rtf_text, 'MAX_RTF_DEPTH', 2)
    with pytest.raises(RTFError, match='DEPTH_LIMIT'):
        extract_rtf(br'{\rtf1 {{x}}}')
    monkeypatch.setattr(rtf_text, 'MAX_RTF_TEXT_BYTES', 3)
    with pytest.raises(RTFError, match='TEXT_LIMIT'):
        extract_rtf(br'{\rtf1 abcd}')
    monkeypatch.setattr(rtf_text, 'MAX_RTF_BYTES', 5)
    with pytest.raises(RTFError, match='FILE_LIMIT'):
        extract_rtf(br'{\rtf1 x}')


def test_seed_from_formatted_wordpad_text_in_both_paths(tmp_path):
    phrase = bip39_phrase('english')
    # Split inside each word: raw-byte mnemonic scanning cannot see the phrase.
    text = ' '.join(w[:2] + '{\\b ' + w[2:] + '}' for w in phrase.split())
    path = tmp_path / 'seed.rtf'
    path.write_bytes(('{\\rtf1\\ansi ' + text + '}').encode())
    hits, coverage = scan_document(path, targets={'secrets'}, mnemonic_standards={'BIP39'})
    assert coverage['status'] == 'SCANNED'
    assert any(h.artifact_kind == 'mnemonic' for h in hits)
    seed_result = DocumentSeedRecovery(RawMnemonicScanner()).scan_path(path)
    assert not seed_result.failures
    assert any(o.candidate.mnemonic_standard == 'BIP39' for o in seed_result.occurrences)
    assert all(o.candidate.safe_metadata['extractor'] == 'bounded_rtf_v1' for o in seed_result.occurrences)


def test_folder_rtf_report_and_malformed_coverage(tmp_path):
    root = tmp_path / 'source'
    root.mkdir()
    key = valid_wif()
    (root / 'key.rtf').write_bytes(br'{\rtf1 ' + key[:20] + br'{\b ' + key[20:] + b'}}')
    (root / 'broken.rtf').write_bytes(br'{\rtf1 broken')
    report = tmp_path / 'report.json'
    assert main(basic_arguments(root, report) + ['--targets', 'secrets', '--skip-mnemonic']) == 0
    payload = json.loads(report.read_text())
    assert any(row['safe_metadata'].get('document_format') == 'RTF'
               for row in payload['target_findings'])
    broken = next(row for row in payload['files'] if row['relative_path'] == 'broken.rtf')
    assert broken['report']['document_scan']['reason'] == 'RTF_UNBALANCED_GROUP'


def test_seed_only_rejects_large_rtf_before_reading(tmp_path, monkeypatch):
    path = tmp_path / 'large.rtf'
    with path.open('wb') as stream:
        stream.truncate(rtf_text.MAX_RTF_BYTES + 1)
    def forbidden(*args, **kwargs):
        raise AssertionError('oversized RTF must not be read')
    monkeypatch.setattr(type(path), 'read_bytes', forbidden)
    result = DocumentSeedRecovery(RawMnemonicScanner()).scan_path(path)
    assert result.failures == ('RTF_FILE_LIMIT',)
