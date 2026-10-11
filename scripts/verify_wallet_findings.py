"""Stream a directory report and check only reported Core/Electrum locations."""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from analyze_large_report import _project
from verify_der_findings import VerificationError, _source_path
from bfrs.recovery.electrum_raw_recovery import (
    ELECTRUM_SIGNATURE_PATTERNS, ElectrumCandidateAssembler,
    MAX_BACKWARD_CONTEXT, MAX_SCANNER_CANDIDATE_WINDOW,
)
from bfrs.validators.base import ValidationContext
from bfrs.validators.berkeley_metadata import (
    BTREE_MAGIC, MAGIC_OFFSET, MAX_PAGE_SIZE, BerkeleyMetadataValidator,
)
from bfrs.validators.bitcoin_record_key import (
    BitcoinRecordKeyValidator, MAX_RAW_KEY_SIDE_BYTES, RawBitcoinRecordKeySideValidator,
)
from bfrs.validators.bitcoin_record_type import BitcoinRecordTypeDecoder, decode_compact_size

KINDS = {"berkeley_metadata", "wallet_record", "electrum_wallet_anchor"}
SCALARS = {"string", "number", "boolean", "null"}
INTERESTING = {"BDB_METADATA_STRUCTURAL", "BDB_METADATA_FRAGMENT",
               "VALID_PUBLIC_KEY_SIDE", "ELECTRUM_COMPLETE_STRUCTURE", "ELECTRUM_FRAGMENT_STRUCTURE"}


def _queue_report(report: Path, database, progress=None) -> Counter:
    import ijson
    counts = Counter()
    row = None
    canonical_seen = False
    size = report.stat().st_size
    last_progress = time.monotonic()
    with report.open("rb") as stream:
        if stream.read(3) != b"\xef\xbb\xbf":
            stream.seek(0)
        for index, (prefix, event, value) in enumerate(ijson.parse(stream, use_float=True)):
            if progress and index % 16384 == 0 and time.monotonic() - last_progress >= 0.5:
                progress("report", stream.tell(), size)
                last_progress = time.monotonic()
            if prefix == "target_findings" and event == "start_array":
                canonical_seen = True
            elif prefix == "target_findings.item" and event == "start_map":
                row = {}
            elif prefix == "target_findings.item" and event == "end_map":
                if row.get("artifact_kind") in KINDS:
                    counts["input_wallet_rows"] += 1
                    relative, offset = row.get("relative_path"), row.get("file_offset_start")
                    if not isinstance(relative, str) or not isinstance(offset, int) or isinstance(offset, bool):
                        raise VerificationError("Trafienie nie zawiera relative_path i file_offset_start; wymagany raport skanowania folderu")
                    inserted = database.execute(
                        "INSERT OR IGNORE INTO positions VALUES (?, ?, ?, ?)",
                        (relative, offset, row["artifact_kind"], json.dumps(row, ensure_ascii=False)),
                    ).rowcount
                    counts["queued_locations" if inserted else "duplicate_locations_skipped"] += 1
                row = None
            elif row is not None and prefix.startswith("target_findings.item.") and event in SCALARS:
                _project(row, prefix[len("target_findings.item."):], value)
    if not canonical_seen:
        raise VerificationError("Brak kanonicznej listy target_findings; wybierz pelny raport BFRS JSON")
    database.commit()
    if progress:
        progress("report", size, size)
    return counts


def _record(data: bytes) -> dict:
    raw = RawBitcoinRecordKeySideValidator().validate_detected(data)
    if raw is not None:
        return {"status": "VALID_PUBLIC_KEY_SIDE" if raw.valid else "RECORD_KEY_SIDE_REJECTED",
                "record_type": raw.record_type, "reason_codes": list(raw.reason_codes),
                **{key: value for key, value in raw.evidence.items() if key in {
                    "pubkey_length", "safe_pubkey_fingerprint", "compressed",
                    "available_record_key_bytes", "required_record_key_bytes"}}}
    decoded = BitcoinRecordTypeDecoder().decode(data)
    if decoded is None:
        return {"status": "ANCHOR_MISMATCH"}
    # mkey's arbitrary four-byte ID and defaultkey's name alone cannot prove a wallet.
    if decoded.name in {"mkey", "defaultkey"}:
        return {"status": "RECORD_NAME_ONLY", "record_type": decoded.name,
                "reason_codes": ["RECORD_VALUE_AND_DATABASE_NOT_EVALUATED"]}
    if decoded.name == "keymeta":
        length = decode_compact_size(decoded.remaining_key)
        if length is None or not length.canonical or length.value not in {33, 65}:
            return {"status": "RECORD_KEY_SIDE_REJECTED", "record_type": decoded.name,
                    "reason_codes": ["INVALID_PUBLIC_KEY_VECTOR"]}
        end = decoded.prefix_length + length.encoded_length + length.value
        exact = BitcoinRecordTypeDecoder().decode(data[:end])
        result = BitcoinRecordKeyValidator().validate(exact)
        return {"status": "VALID_PUBLIC_KEY_SIDE" if result.valid else "RECORD_KEY_SIDE_REJECTED",
                "record_type": result.record_type, "reason_codes": list(result.reasons),
                "pubkey_length": length.value}
    return {"status": "RECORD_TYPE_NOT_SUPPORTED", "record_type": decoded.name}


def verify_one(source: Path, kind: str, offset: int) -> dict:
    with source.open("rb", buffering=0) as stream:
        before = os.fstat(stream.fileno())
        size = before.st_size
        if offset < 0 or offset >= size:
            return {"status": "OFFSET_OUT_OF_RANGE", "source_size": size, "bytes_read": 0}
        if kind == "berkeley_metadata":
            if offset < MAGIC_OFFSET:
                return {"status": "METADATA_PREFIX_UNAVAILABLE", "source_size": size, "bytes_read": 0}
            start, maximum = offset - MAGIC_OFFSET, MAX_PAGE_SIZE
        elif kind == "wallet_record":
            start, maximum = offset, MAX_RAW_KEY_SIDE_BYTES
        elif kind == "electrum_wallet_anchor":
            start, maximum = max(0, offset - MAX_BACKWARD_CONTEXT), MAX_SCANNER_CANDIDATE_WINDOW
        else:
            raise VerificationError("Nieobslugiwany rodzaj trafienia")
        length = min(size - start, maximum)
        stream.seek(start)
        data = stream.read(length)
        after = os.fstat(stream.fileno())
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        return {"status": "SOURCE_CHANGED_DURING_READ", "bytes_read": len(data)}
    if len(data) != length:
        return {"status": "SHORT_READ", "bytes_read": len(data)}
    public = {"source_size": size, "bytes_read": len(data), "window_start": start,
              "window_end": start + len(data), "window_sha256": hashlib.sha256(data).hexdigest()}
    if kind == "wallet_record":
        return {**public, **_record(data)}
    if kind == "berkeley_metadata":
        magic = data[MAGIC_OFFSET:MAGIC_OFFSET + 4]
        order = next((order for order in ("little", "big") if magic == BTREE_MAGIC.to_bytes(4, order)), None)
        if order is None:
            return {**public, "status": "ANCHOR_MISMATCH"}
        # Inspect this exact page, never another magic somewhere in the read window.
        result = BerkeleyMetadataValidator()._inspect_candidate(ValidationContext(str(source), start, data), 0, order)
        return {**public, "status": "BDB_METADATA_" + result.status.value.upper(),
                "metadata": asdict(result.info), "reason_codes": list(result.reasons),
                "anchor_matches_report": True}
    local = offset - start
    anchors = [name for name, pattern in ELECTRUM_SIGNATURE_PATTERNS if data.startswith(pattern, local)]
    if not anchors:
        return {**public, "status": "ANCHOR_MISMATCH"}
    candidates = ElectrumCandidateAssembler().analyze_bytes(
        data, source=str(source), physical_start=start, required_anchor_offset=local, anchor_types=anchors)
    details = [{"candidate_id": item.candidate_id, "serialization_type": item.serialization_type,
                "completeness": item.completeness, "encryption_state": item.encryption_state,
                "confidence": item.confidence, "structural_status": item.structural_status,
                "file_offset_start": item.physical_start, "file_offset_end": item.physical_end,
                "reason_codes": list(item.reason_codes), "legacy_format": item.legacy_format,
                "format_generation": item.format_generation} for item in candidates]
    status = ("ELECTRUM_COMPLETE_STRUCTURE" if any(item.structural_status == "STRONG" for item in candidates)
              else "ELECTRUM_FRAGMENT_STRUCTURE" if candidates else "ELECTRUM_NOT_CONFIRMED")
    return {**public, "status": status, "anchor_matches_report": True, "anchor_types": anchors,
            "candidates": details, "bounded_context": True}


def verify_report(report: Path, source_root: Path, output_dir: Path, *, progress=None) -> dict:
    report, source_root, output_dir = report.resolve(strict=True), source_root.resolve(strict=True), output_dir.resolve()
    if not report.is_file() or not source_root.is_dir():
        raise VerificationError("Wymagany plik raportu i folder z odzyskanymi plikami")
    if output_dir.is_relative_to(source_root) or output_dir.exists():
        raise VerificationError("Folder wyniku musi byc nowy i znajdowac sie poza folderem zrodlowym")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".wallet-verification-", dir=output_dir.parent))
    database = None
    try:
        database = sqlite3.connect(staging / "queue.sqlite")
        database.execute("CREATE TABLE positions (relative TEXT, offset INTEGER, kind TEXT, row TEXT, PRIMARY KEY(relative, offset, kind))")
        database.execute("CREATE TABLE windows (kind TEXT, digest TEXT, PRIMARY KEY(kind, digest))")
        counts = _queue_report(report, database, progress)
        statuses, reasons, samples = Counter(), Counter(), []
        with (staging / "weryfikacja_portfeli.jsonl").open("w", encoding="utf-8") as output:
            for relative, offset, kind, original in database.execute("SELECT relative, offset, kind, row FROM positions ORDER BY relative, offset, kind"):
                row = {"relative_path": relative, "file_offset_start": offset, "artifact_kind": kind,
                       "original_report": json.loads(original)}
                try:
                    source = _source_path(source_root, relative)
                    row["file_path"] = str(source)
                    row.update(verify_one(source, kind, offset))
                except FileNotFoundError:
                    row["status"] = "SOURCE_FILE_MISSING"
                except PermissionError:
                    row["status"] = "SOURCE_ACCESS_DENIED"
                except OSError:
                    row["status"] = "SOURCE_READ_ERROR"
                except VerificationError:
                    row["status"] = "UNSAFE_SOURCE_PATH"
                counts["processed_locations"] += 1
                counts["bytes_read"] += row.get("bytes_read", 0)
                statuses[kind + ":" + row["status"]] += 1
                if row.get("window_sha256"):
                    counts["unique_read_windows"] += database.execute("INSERT OR IGNORE INTO windows VALUES (?, ?)", (kind, row["window_sha256"])).rowcount
                for reason in row.get("reason_codes", ()):
                    reasons[kind + ":" + reason] += 1
                if len(samples) < 10 or row["status"] in INTERESTING and len(samples) < 30:
                    samples.append(row)
                output.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
                if progress:
                    progress("verify", counts["processed_locations"], counts["queued_locations"])
        database.close()
        database = None
        (staging / "queue.sqlite").unlink()
        summary = {"schema": "BFRS_TARGETED_WALLET_VERIFICATION_V1", "report": str(report),
                   "source_root": str(source_root), "counts": dict(counts), "status_counts": dict(statuses),
                   "reason_counts": dict(reasons), "samples": samples,
                   "notes": [
                       "Sprawdzono tylko kanoniczne lokalizacje Core/Electrum z raportu folderu; seedy i DER pominieto.",
                       "Odczyt na lokalizacje: BDB do 64 KiB, rekord do 79 bajtow, Electrum do 2 MiB (do 1 MiB przed znacznikiem).",
                       "Metadane BDB potwierdzaja format bazy, nie jej zwiazek z portfelem Bitcoin.",
                       "VALID_PUBLIC_KEY_SIDE potwierdza klucz publiczny w ramce rekordu, nie jego wartosc ani klucz prywatny.",
                       "RECORD_NAME_ONLY to slaby znacznik wymagajacy kontekstu strony i wartosci rekordu.",
                       "Struktura Electrum wymaga dalszej oceny pochodzenia; fragment i brak potwierdzenia nie wykluczaja danych poza oknem.",
                       "Rozne znaczniki moga nalezec do jednego obiektu; liczba lokalizacji nie jest liczba portfeli.",
                       "Wynik zawiera statusy, offsety i skroty, bez zawartosci plikow, seedow i kluczy prywatnych. Nie sprawdzano sald.",
                   ]}
        (staging / "podsumowanie_portfeli.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.rename(staging, output_dir)
        return summary
    except BaseException:
        if database is not None:
            database.close()
        shutil.rmtree(staging, ignore_errors=True)
        raise


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args(argv)
    try:
        report, source = args.report, args.source_root
        if report is None or source is None:
            import tkinter
            from tkinter import filedialog
            root = tkinter.Tk()
            root.withdraw()
            try:
                if report is None:
                    name = filedialog.askopenfilename(title="Wybierz pelny raport Disk_Drill_Hp.bfrs.json", filetypes=[("Raport BFRS", "*.json")])
                    report = Path(name) if name else None
                if report is not None and source is None:
                    name = filedialog.askdirectory(title="Wybierz folder Disk_Drill_Hp z odzyskanymi plikami")
                    source = Path(name) if name else None
            finally:
                root.destroy()
        if report is None or source is None:
            print("Anulowano.")
            return 0
        output = args.output_dir or report.with_name("weryfikacja-portfeli-" + time.strftime("%Y%m%d-%H%M%S"))
        last_progress = 0.0

        def progress(phase, done, total):
            nonlocal last_progress
            now = time.monotonic()
            if now - last_progress < 0.5 and done != total:
                return
            last_progress = now
            message = (f"Odczyt raportu: {done / max(total, 1):.1%}" if phase == "report"
                       else f"Sprawdzone lokalizacje: {done}/{total}")
            print("\r" + message + " " * 10, end="", flush=True)

        summary = verify_report(report, source, output, progress=progress)
        print(f"\nGotowe: {output.resolve()}")
        print(json.dumps({"counts": summary["counts"], "status_counts": summary["status_counts"]}, ensure_ascii=False, indent=2))
        return 0
    except Exception as error:
        print(f"\nWeryfikacja nie powiodla sie: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
