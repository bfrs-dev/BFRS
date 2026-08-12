import csv
import hashlib
import json

from bfrs.core.secp256k1 import GENERATOR, encode_sec_public_key
from bfrs.tools.export_legacy_plaintext_keys import (
    _address,
    _base58check,
    _structural_rows,
    _wif,
    main,
)

from tests.test_berkeley_database_pipeline import (
    database,
    leaf,
    plain_pair,
    private_der,
    string,
    vector,
)


def wallet(tmp_path, payload):
    path = tmp_path / "wallet.dat"
    path.write_bytes(payload)
    return path


def compressed_pair(scalar=1):
    public = encode_sec_public_key(GENERATOR, compressed=True)
    return string("key") + vector(public), vector(private_der(scalar))


def base58_decode(value):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    number = 0
    for character in value:
        number = number * 58 + alphabet.index(character)
    encoded = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(value) - len(value.lstrip("1"))) + encoded


def test_explicit_flag_is_required(tmp_path, capsys):
    source = wallet(tmp_path, database(leaf(1, plain_pair())))
    output = tmp_path / "keys.csv"
    assert main(["--input", str(source), "--output", str(output)]) == 2
    assert not output.exists()
    assert "required" in capsys.readouterr().err


def test_structural_export_encodings_dedup_manifest_stdout_and_source(tmp_path, capsys):
    uncompressed = plain_pair()
    compressed = compressed_pair()
    source = wallet(
        tmp_path,
        database(
            leaf(1, uncompressed),
            leaf(2, compressed),
            leaf(3, uncompressed),
        ),
    )
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    output = tmp_path / "private_keys.csv"
    assert main([
        "--input", str(source), "--output", str(output),
        "--allow-private-key-export",
    ]) == 0
    after = hashlib.sha256(source.read_bytes()).hexdigest()
    assert before == after
    with output.open(encoding="utf-8", newline="") as data:
        rows = list(csv.DictReader(data))
    assert len(rows) == 1
    assert rows[0]["pubkey_encoding"] == "uncompressed"
    manifest = json.loads((tmp_path / "private_keys_manifest.json").read_text())
    assert manifest["structural_key_record_count"] == 3
    assert manifest["unique_private_key_count"] == 1
    assert manifest["duplicate_record_count"] == 2
    assert set(manifest) == {
        "source_wallet", "source_wallet_size", "source_wallet_sha256",
        "structural_key_record_count", "unique_private_key_count",
        "duplicate_record_count", "compressed_count", "uncompressed_count",
        "csv_filename", "csv_sha256",
    }
    stdout = capsys.readouterr().out
    assert all(
        line.startswith((
            "input path:", "input SHA-256:", "wallet size:",
            "structural records:", "unique key count:", "duplicate count:",
            "compressed count:", "uncompressed count:", "output path:",
            "output SHA-256:",
        ))
        for line in stdout.splitlines()
    )
    for private_value in (
        rows[0]["private_key_hex"], rows[0]["wif"], rows[0]["bitcoin_address"]
    ):
        assert private_value not in stdout


def test_compressed_and_uncompressed_wif_and_address_are_encoding_correct(tmp_path):
    compressed_source = wallet(tmp_path, database(leaf(1, compressed_pair())))
    count, compressed_rows = _structural_rows(compressed_source)
    assert count == 1 and compressed_rows[0].compressed
    row = compressed_rows[0]
    decoded_wif = base58_decode(_wif(row))
    assert decoded_wif[:-4] == b"\x80" + row.private_bytes + b"\x01"
    assert _address(row) == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"

    uncompressed_source = tmp_path / "uncompressed.dat"
    uncompressed_source.write_bytes(database(leaf(1, plain_pair())))
    _, uncompressed_rows = _structural_rows(uncompressed_source)
    row = uncompressed_rows[0]
    decoded_wif = base58_decode(_wif(row))
    assert decoded_wif[:-4] == b"\x80" + row.private_bytes
    assert _address(row) == "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm"


def test_invalid_mismatch_and_fragment_only_do_not_export(tmp_path):
    cases = (
        database(leaf(1, (string("key") + vector(encode_sec_public_key(GENERATOR, compressed=False)), vector(b"bad der")))),
        database(leaf(1, plain_pair(key_scalar=2))),
        database(leaf(1, plain_pair(), fragment=True)),
    )
    for index, payload in enumerate(cases):
        source = tmp_path / f"invalid-{index}.dat"
        output = tmp_path / f"invalid-{index}.csv"
        source.write_bytes(payload)
        assert main([
            "--input", str(source), "--output", str(output),
            "--allow-private-key-export",
        ]) == 3
        assert not output.exists()


def test_existing_output_or_manifest_refuses_without_overwrite(tmp_path):
    source = wallet(tmp_path, database(leaf(1, plain_pair())))
    output = tmp_path / "private_keys.csv"
    output.write_text("existing", encoding="utf-8")
    assert main([
        "--input", str(source), "--output", str(output),
        "--allow-private-key-export",
    ]) == 3
    assert output.read_text(encoding="utf-8") == "existing"


def test_private_row_repr_is_redacted(tmp_path):
    source = wallet(tmp_path, database(leaf(1, plain_pair())))
    _, rows = _structural_rows(source)
    rendered = repr(rows[0])
    assert rendered == "_PrivateRow(<redacted>)"
    assert rows[0].private_bytes.hex() not in rendered
