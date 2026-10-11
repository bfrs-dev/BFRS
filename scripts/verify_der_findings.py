"""Verify existing DER findings offline using bounded reads of source files."""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import shutil
import sqlite3
import sys
import tempfile
import time

# Run the checked-out validators even when the GUI installation is older.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from bfrs.core.models import RawHit
from bfrs.recovery.orphan_private_key_der import (
    HISTORICAL_EC_PRIVATE_KEY_DER_ANCHOR as ANCHOR,
    HISTORICAL_EC_PRIVATE_KEY_DER_SIGNATURE as SIGNATURE,
    OrphanHistoricalECPrivateKeyRecoveryPipeline,
)
from bfrs.recovery.orphan_private_key_fragment import (
    OrphanHistoricalECPrivateKeyFragmentRecoveryPipeline,
)


class VerificationError(ValueError):
    pass


class WindowReader:
    def __init__(self, start: int, data: bytes):
        self.start = start
        self.data = data

    def read_at(self, offset: int, length: int) -> bytes:
        local = offset - self.start
        if local < 0 or local + length > len(self.data):
            raise VerificationError("Validator requested data outside its bounded window")
        return self.data[local:local + length]


def _source_path(root: Path, relative: str) -> Path:
    path = PureWindowsPath(relative)
    if not path.parts or path.drive or path.root or ".." in path.parts or any(":" in part for part in path.parts):
        raise VerificationError("Nieprawidlowa sciezka wzgledna w liscie trafien")
    target = root
    for part in path.parts:
        target = target / part
        if target.is_symlink() or getattr(target, "is_junction", lambda: False)():
            raise VerificationError("Pominieto dowiazanie lub junction")
        if target.exists() and getattr(target.stat(), "st_file_attributes", 0) & 0x400:
            raise VerificationError("Pominieto punkt ponownej analizy Windows")
    resolved = target.resolve()
    if not resolved.is_relative_to(root):
        raise VerificationError("Sciezka wychodzi poza wybrany folder")
    return resolved


def verify_one(source: Path, offset: int) -> dict:
    with source.open("rb", buffering=0) as stream:
        before = os.fstat(stream.fileno())
        size = before.st_size
        if offset < 0 or offset + len(ANCHOR) > size:
            return {"status": "OFFSET_OUT_OF_RANGE", "source_size": size, "bytes_read": 0}
        start = max(0, offset - 4)
        length = min(size, offset + 1024) - start
        stream.seek(start)
        data = stream.read(length)
        after = os.fstat(stream.fileno())
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        return {"status": "SOURCE_CHANGED_DURING_READ", "bytes_read": len(data)}
    if len(data) != length:
        return {"status": "SHORT_READ", "bytes_read": len(data)}
    public = {"source_size": size, "bytes_read": len(data), "window_start": start,
              "window_sha256": hashlib.sha256(data).hexdigest()}
    if data[offset - start:offset - start + len(ANCHOR)] != ANCHOR:
        return {**public, "status": "ANCHOR_MISMATCH"}
    public["anchor_matches_report"] = True
    hit = RawHit(offset, offset + len(ANCHOR), SIGNATURE, 0.0, str(source),
                 target="secrets", artifact_kind="ec_private_key_der")
    arguments = {"source": str(source), "range_start": 0, "range_end": size,
                 "range_reader": WindowReader(start, data)}
    complete = OrphanHistoricalECPrivateKeyRecoveryPipeline([hit], **arguments).run()
    fragment = OrphanHistoricalECPrivateKeyFragmentRecoveryPipeline([hit], **arguments).run()
    status = ("VALID_COMPLETE_DER" if complete.valid_secp256k1_der_count
              else "VALID_INNER_FRAGMENT" if fragment.valid_inner_fragment_count
              else "NOT_CONFIRMED")
    public.update(
        status=status, outer_der_candidates=complete.candidate_der_count,
        inner_fragment_candidates=fragment.candidate_inner_fragment_count,
        complete_locations=[asdict(item) for item in complete.locations],
        fragment_locations=[asdict(item) for item in fragment.locations],
        complete_rejection_counts=dict(complete.evidence.get("rejection_counts", ())),
        fragment_rejection_counts=dict(fragment.evidence.get("rejection_counts", ())),
        complete_reasons=list(complete.reasons), fragment_reasons=list(fragment.reasons),
    )
    if not complete.candidate_der_count:
        public["outer_header_status"] = "NO_MATCHING_OUTER_DER_HEADER"
    return public


def verify_findings(findings: Path, source_root: Path, output_dir: Path, *, progress=None) -> dict:
    findings = findings.resolve(strict=True)
    source_root = source_root.resolve(strict=True)
    output_dir = output_dir.resolve()
    if not source_root.is_dir():
        raise VerificationError("Wybierz folder z odzyskanymi plikami")
    if output_dir.exists():
        raise VerificationError("Folder wynikowy juz istnieje")
    if output_dir.is_relative_to(source_root) or source_root.is_relative_to(output_dir):
        raise VerificationError("Wybierz folder wynikowy poza folderem zrodlowym")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".bfrs-der-", dir=output_dir.parent))
    counts, reasons = Counter(), Counter()
    samples = []
    database = staging / "dedup.sqlite"
    try:
        with sqlite3.connect(database) as dedup:
            dedup.execute("PRAGMA journal_mode=OFF")
            dedup.execute("CREATE TABLE positions (path TEXT, offset INTEGER, PRIMARY KEY(path, offset))")
            dedup.execute("CREATE TABLE windows (digest TEXT PRIMARY KEY)")
            with findings.open(encoding="utf-8-sig") as inputs, (staging / "weryfikacja_der.jsonl").open("x", encoding="utf-8") as output:
                while True:
                    line = inputs.readline(65537)
                    if not line:
                        break
                    if len(line) > 65536:
                        raise VerificationError("Wybierz sygnatury_kluczy.jsonl, a nie pelny raport")
                    if not line.strip():
                        continue
                    original = json.loads(line)
                    if not isinstance(original, dict):
                        raise VerificationError("Nieprawidlowy wpis listy trafien")
                    if str(original.get("artifact_kind", "")).lower() != "ec_private_key_der":
                        continue
                    counts["input_der_rows"] += 1
                    relative = original.get("relative_path")
                    offset = original.get("file_offset_start")
                    if not isinstance(relative, str) or not isinstance(offset, int) or isinstance(offset, bool):
                        raise VerificationError("Wpis DER nie zawiera sciezki wzglednej i offsetu")
                    row = {"relative_path": relative, "file_offset_start": offset}
                    try:
                        source = _source_path(source_root, relative)
                        inserted = dedup.execute("INSERT OR IGNORE INTO positions VALUES (?, ?)", (str(source), offset)).rowcount
                        if not inserted:
                            counts["duplicate_locations_skipped"] += 1
                            continue
                        row["file_path"] = str(source)
                        row.update(verify_one(source, offset))
                    except FileNotFoundError:
                        row["status"] = "SOURCE_FILE_MISSING"
                    except PermissionError:
                        row["status"] = "SOURCE_ACCESS_DENIED"
                    except OSError:
                        row["status"] = "SOURCE_READ_ERROR"
                    except VerificationError:
                        row["status"] = "UNSAFE_SOURCE_PATH"
                    counts["processed_locations"] += 1
                    counts[row["status"]] += 1
                    counts["bytes_read"] += row.get("bytes_read", 0)
                    digest = row.get("window_sha256")
                    if digest:
                        counts["unique_read_windows"] += dedup.execute("INSERT OR IGNORE INTO windows VALUES (?)", (digest,)).rowcount
                    for field in ("complete_rejection_counts", "fragment_rejection_counts"):
                        for reason, count in row.get(field, {}).items():
                            reasons[field + ":" + reason] += count
                    output.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
                    if len(samples) < 10 or (row["status"].startswith("VALID_") and len(samples) < 20):
                        samples.append(row)
                    if progress:
                        progress(counts["processed_locations"], counts["VALID_COMPLETE_DER"] + counts["VALID_INNER_FRAGMENT"])
        # Close the SQLite handle explicitly before unlinking on Windows.
        dedup.close()
        database.unlink()
        if not counts["input_der_rows"]:
            raise VerificationError("Nie znaleziono wpisow DER; wybierz sygnatury_kluczy.jsonl")
        summary = {
            "schema": "BFRS_TARGETED_DER_VERIFICATION_V1", "findings": str(findings),
            "source_root": str(source_root), "counts": dict(counts),
            "rejection_counts": dict(reasons), "samples": samples,
            "validation_profile": "historical_secp256k1_with_matching_embedded_public_key",
            "notes": [
                "Sprawdzono tylko wskazane lokalizacje, odczytujac do 1028 bajtow na trafienie.",
                "Pelny DER i fragment wewnetrzny sa sprawdzane niezaleznie; nie sumuj ich lokalizacji.",
                "Raport zawiera statusy, offsety i skroty okien, bez bajtow plikow i kluczy prywatnych.",
                "NOT_CONFIRMED dotyczy tego profilu walidacji; nie wyklucza innych formatow lub uszkodzonych kluczy.",
                "Nie sprawdzano adresow, historii transakcji ani sald.",
            ],
        }
        (staging / "podsumowanie_der.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.rename(staging, output_dir)
        return summary
    except BaseException:
        # sqlite3's context manager commits but does not close the connection.
        if "dedup" in locals():
            dedup.close()
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _choose_paths(findings, source_root):
    import tkinter
    from tkinter import filedialog
    root = tkinter.Tk()
    root.withdraw()
    try:
        if findings is None:
            selected = filedialog.askopenfilename(title="Wybierz sygnatury_kluczy.jsonl", filetypes=[("Lista trafien kluczy", "*.jsonl")])
            findings = Path(selected) if selected else None
        if findings is not None and source_root is None:
            selected = filedialog.askdirectory(title="Wybierz folder Disk_Drill_Hp z odzyskanymi plikami")
            source_root = Path(selected) if selected else None
        return findings, source_root
    finally:
        root.destroy()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", type=Path)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args(argv)
    try:
        findings, source_root = args.findings, args.source_root
        if findings is None or source_root is None:
            findings, source_root = _choose_paths(findings, source_root)
        if findings is None or source_root is None:
            print("Anulowano.")
            return 0
        output = args.output_dir or findings.with_name("weryfikacja-der-" + time.strftime("%Y%m%d-%H%M%S"))

        def progress(done, valid):
            print(f"\rSprawdzone lokalizacje: {done} | potwierdzone: {valid}", end="", flush=True)

        result = verify_findings(findings, source_root, output, progress=progress)
        print(f"\nGotowe: {output.resolve()}")
        print(json.dumps(result["counts"], ensure_ascii=False, indent=2))
        return 0
    except Exception as error:
        print(f"\nWeryfikacja nie powiodla sie: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
