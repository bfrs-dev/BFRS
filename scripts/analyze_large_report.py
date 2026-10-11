"""Offline, streaming triage of BFRS reports; also runnable outside the repo.

Requires only Python 3.11+ and ijson. Never opens scanned source files, exports
secrets, checks balances, or materializes the report/files array in memory.
"""

from __future__ import annotations

import argparse
from collections import Counter
from contextlib import ExitStack
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import time


SCALARS = {"string", "number", "boolean", "null"}
SECRET_KINDS = {"mnemonic", "wif_private_key", "ec_private_key_der", "private_key"}
VALID_STATUSES = {
    "CRYPTO_VALID", "BASE58CHECK_AND_SECP256K1_VALID", "SECP256K1_VALID",
    "CHECKSUM_VALID", "BIP39_VALID", "ELECTRUM_SEED_VALID",
    "ELECTRUM_V1_STRICT_VALID", "ELECTRUM_V1_COMPAT_VALID",
}
COUNT_FIELDS = {
    "files_processed", "retained_findings", "retained_valid_secret_occurrences",
    "retained_valid_secrets_without_fingerprint", "likely_false_positive_rows",
    "exported_review_rows", "mnemonic_candidate_rows", "mnemonic_candidate_valid_rows",
    "mnemonic_candidate_likely_noise_rows",
}
STATE_FIELDS = {"discovery_state", "structural_state", "crypto_state", "recovery_relevance"}
ROW_FIELDS = {
    "target", "artifact_kind", "hit_type", "validation_status", "structural_status",
    "file_path", "relative_path", "source", "file_offset_start", "file_offset_end",
    "physical_start", "physical_end", "safe_fingerprint", "fingerprint",
    "mnemonic_standard", "word_count", "language", "encoding", "recovery_relevance",
    "candidate_id", "duplicate_count", "completeness",
}
METADATA_FIELDS = {
    "mnemonic_standard", "word_count", "language", "encoding", "recovery_relevance",
}
ROOT_FIELDS = {
    "source", "source_root", "source_type", "report_schema_version", "file_count",
    "files_discovered", "files_scanned", "files_failed", "files_skipped",
    "bytes_discovered", "bytes_scanned", "findings_count", "raw_hit_count",
    "elapsed_seconds",
}
SUMMARY_COUNTS = {
    "rejected", "review_candidates", "accepted_candidates", "structurally_complete",
    "crypto_valid_occurrences", "crypto_valid_secret_occurrences",
    "crypto_valid_secrets_without_fingerprint",
}
FILE_FIELDS = {"file_path", "relative_path", "status", "reason", "size", "finding_count"}
DETAIL_FIELDS = {
    "finding_summary": SUMMARY_COUNTS,
    "intact_wallet": {"detected", "wallet_family", "format"},
    "electrum_raw_recovery": {"complete_candidates", "fragment_candidates", "encrypted_candidates"},
    "orphan_private_key_recovery": {"valid_secp256k1_der_count"},
    "orphan_private_key_fragment_recovery": {"valid_inner_fragment_count"},
    "legacy_wallet_recovery.summary": {
        "critical_candidates", "high_candidates", "crypto_valid_key_occurrences",
        "encrypted_complete_candidates",
    },
    "mnemonic_recovery": {
        "crypto_valid_occurrences", "independent_candidate_occurrences",
        "likely_wordlist_occurrences", "review_required_unique_fingerprints",
    },
}


class ReportAnalysisError(ValueError):
    pass


def _write_row(stream, row: dict) -> None:
    stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _project(row: dict, key: str, value) -> None:
    """Keep a fixed vocabulary of public fields; discard arbitrary evidence."""
    if key in ROW_FIELDS:
        row[key] = value
    elif key.startswith("normalized_state.") and key.split(".", 1)[1] in STATE_FIELDS:
        row.setdefault("normalized_state", {})[key.split(".", 1)[1]] = value
    elif key.startswith("safe_metadata.") and key.split(".", 1)[1] in METADATA_FIELDS:
        row.setdefault("safe_metadata", {})[key.split(".", 1)[1]] = value


def _state(row: dict) -> dict:
    normalized = row.get("normalized_state")
    if isinstance(normalized, dict) and STATE_FIELDS <= normalized.keys():
        return {key: str(normalized[key]).upper() for key in STATE_FIELDS}
    # Old/noncanonical vocabulary remains reviewable, never silently accepted.
    status = str(row.get("validation_status", "UNVALIDATED")).upper()
    structure = str(row.get("structural_status", "NONE")).upper()
    relevance = row.get("recovery_relevance", row.get("safe_metadata", {}).get(
        "recovery_relevance", "CONTEXT_REVIEW"))
    return {
        "discovery_state": ("REJECTED" if status == "REJECTED" or structure == "REJECTED"
                            else "ACCEPTED" if status in VALID_STATUSES else "UNCLASSIFIED"),
        "crypto_state": "VALID" if status in VALID_STATUSES else "UNCHECKED",
        "structural_state": ("COMPLETE" if structure in {"COMPLETE", "STRONG"}
                             else "FRAGMENT" if structure in {"FRAGMENT", "TRUNCATED"} else "NONE"),
        "recovery_relevance": {
            "INDEPENDENT_CANDIDATE": "INDEPENDENT",
            "LIKELY_WORDLIST_FALSE_POSITIVE": "LIKELY_FALSE_POSITIVE",
        }.get(relevance, relevance),
    }


def _file_detail(destination: dict, key: str, value) -> None:
    for section, fields in DETAIL_FIELDS.items():
        prefix = section + "."
        if key.startswith(prefix) and key[len(prefix):] in fields:
            destination.setdefault(section, {})[key[len(prefix):]] = value
            return


def _file_priority(details: dict) -> str | None:
    summary = details.get("finding_summary", {})
    seeds = details.get("mnemonic_recovery", {})
    legacy = details.get("legacy_wallet_recovery.summary", {})
    noise = seeds.get("likely_wordlist_occurrences", 0)
    if (summary.get("crypto_valid_secret_occurrences", 0) > noise
            or seeds.get("crypto_valid_occurrences", 0) > noise
            or seeds.get("independent_candidate_occurrences", 0)
            or seeds.get("review_required_unique_fingerprints", 0)
            or legacy.get("crypto_valid_key_occurrences", 0)
            or details.get("orphan_private_key_recovery", {}).get("valid_secp256k1_der_count", 0)):
        return "SECRET_REVIEW"
    if (details.get("intact_wallet", {}).get("detected")
            or details.get("electrum_raw_recovery", {}).get("complete_candidates", 0)
            or legacy.get("encrypted_complete_candidates", 0)):
        return "WALLET_STRUCTURE"
    if (summary.get("accepted_candidates", 0) > noise or summary.get("review_candidates", 0)
            or details.get("electrum_raw_recovery", {}).get("fragment_candidates", 0)
            or details.get("orphan_private_key_fragment_recovery", {}).get("valid_inner_fragment_count", 0)):
        return "OTHER_REVIEW"
    if noise:
        return "SEED_NOISE"
    return None


def analyze_report(source: Path, output_dir: Path, *, progress=None) -> dict:
    try:
        import ijson
    except ImportError as error:
        raise ReportAnalysisError("Zainstaluj parser: py -m pip install \"ijson>=3.3,<4\"") from error
    source = source.resolve(strict=True)
    output_dir = output_dir.resolve(strict=False)
    if output_dir.exists():
        raise ReportAnalysisError("Folder wynikowy juz istnieje; wybierz nowy folder.")
    if source == output_dir or output_dir in source.parents:
        raise ReportAnalysisError("Folder wynikowy koliduje z raportem zrodlowym.")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".bfrs-analysis-", dir=output_dir.parent))
    metadata = {}
    reported_counts = Counter()
    counters = Counter({key: 0 for key in COUNT_FIELDS})
    categories = Counter()
    priorities = Counter()
    sample_findings = []
    sample_files = []
    sample_file_buckets = {key: [] for key in ("SECRET_REVIEW", "WALLET_STRUCTURE", "OTHER_REVIEW", "SEED_NOISE")}
    current_file = None
    current_details = {}
    row = None
    row_prefix = None
    seen_views = set()
    total_bytes = source.stat().st_size
    database = staging / "unique.sqlite"
    try:
        with ExitStack() as resources:
            connection = sqlite3.connect(database)
            resources.callback(connection.close)
            connection.execute("PRAGMA journal_mode=OFF")
            connection.execute("PRAGMA synchronous=OFF")
            connection.execute("CREATE TABLE fingerprints (value TEXT PRIMARY KEY, actionable INTEGER NOT NULL)")
            connection.execute("CREATE TABLE candidate_fingerprints (value TEXT PRIMARY KEY, actionable INTEGER NOT NULL)")
            findings_stream = resources.enter_context((staging / "wyniki_do_sprawdzenia.jsonl").open("x", encoding="utf-8"))
            noise_stream = resources.enter_context((staging / "seedy_prawdopodobnie_przypadkowe.jsonl").open("x", encoding="utf-8"))
            candidate_stream = resources.enter_context((staging / "kandydaci_seedow.jsonl").open("x", encoding="utf-8"))
            files_stream = resources.enter_context((staging / "najwazniejsze_pliki.jsonl").open("x", encoding="utf-8"))

            def finish_row(item, view):
                state = _state(item)
                item["normalized_state"] = state
                item["source_view"] = view
                counters["retained_findings"] += 1
                categories[f"{item.get('target', 'unknown')} / {item.get('artifact_kind', 'unknown')}"] += 1
                for field, value in state.items():
                    counters[f"{field}:{value}"] += 1
                valid_secret = (str(item.get("artifact_kind", "")).lower() in SECRET_KINDS
                                and state["crypto_state"] == "VALID"
                                and state["discovery_state"] != "REJECTED")
                actionable = state["recovery_relevance"] != "LIKELY_FALSE_POSITIVE"
                if valid_secret:
                    counters["retained_valid_secret_occurrences"] += 1
                    fingerprint = item.get("safe_fingerprint", item.get("fingerprint"))
                    if isinstance(fingerprint, str) and fingerprint:
                        connection.execute(
                            "INSERT INTO fingerprints VALUES (?, ?) ON CONFLICT(value) DO UPDATE SET actionable=MAX(actionable,excluded.actionable)",
                            (fingerprint, int(actionable)),
                        )
                    else:
                        counters["retained_valid_secrets_without_fingerprint"] += 1
                if not actionable:
                    counters["likely_false_positive_rows"] += 1
                    _write_row(noise_stream, item)
                elif state["discovery_state"] != "REJECTED" and (
                        valid_secret or state["discovery_state"] in {"ACCEPTED", "CANDIDATE", "UNCLASSIFIED"}
                        or state["structural_state"] in {"COMPLETE", "FRAGMENT"}):
                    counters["exported_review_rows"] += 1
                    _write_row(findings_stream, item)
                    if len(sample_findings) < 20:
                        sample_findings.append(item)

            with source.open("rb") as stream:
                if stream.read(3) != b"\xef\xbb\xbf":
                    stream.seek(0)
                last_progress = time.monotonic()
                for index, (prefix, event, value) in enumerate(ijson.parse(stream, use_float=True)):
                    if index % 16384 == 0 and progress is not None:
                        now = time.monotonic()
                        if now - last_progress >= 0.5:
                            progress(stream.tell(), total_bytes, counters["files_processed"], counters["retained_findings"])
                            last_progress = now
                    if prefix == "files.item" and event == "start_map":
                        current_file, current_details = {}, {}
                    elif prefix == "files.item" and event == "end_map":
                        counters["files_processed"] += 1
                        for key, count in current_details.get("finding_summary", {}).items():
                            if isinstance(count, int) and not isinstance(count, bool):
                                reported_counts[key] += count
                        priority = _file_priority(current_details)
                        if priority is not None:
                            current_file.update(priority=priority, evidence=current_details)
                            priorities[priority] += 1
                            _write_row(files_stream, current_file)
                            bucket = sample_file_buckets[priority]
                            if len(bucket) < 5:
                                bucket.append(current_file)
                        current_file = None
                    elif prefix in {"target_findings", "mnemonic_recovery.candidates"} and event == "start_array":
                        seen_views.add(prefix)
                    # Only the canonical top-level finding list is counted. The
                    # copies in files[*].report.target_findings are discarded.
                    elif prefix == "target_findings.item" and event == "start_map":
                        row, row_prefix = {}, prefix
                    elif (prefix.endswith("mnemonic_recovery.candidates.item")
                          and prefix in {"mnemonic_recovery.candidates.item", "files.item.report.mnemonic_recovery.candidates.item"}
                          and event == "start_map"):
                        row, row_prefix = {"artifact_kind": "mnemonic", "target": "secrets"}, prefix
                    elif row_prefix is not None and prefix == row_prefix and event == "end_map":
                        if row_prefix == "target_findings.item":
                            finish_row(row, "target_findings")
                        else:
                            # Mnemonic candidate views are separate, non-additive
                            # evidence. Summaries report their counts separately.
                            counters["mnemonic_candidate_rows"] += 1
                            row["source_view"] = "mnemonic_candidates"
                            row["normalized_state"] = _state(row)
                            candidate_state = row["normalized_state"]
                            actionable = candidate_state["recovery_relevance"] != "LIKELY_FALSE_POSITIVE"
                            if not actionable:
                                counters["mnemonic_candidate_likely_noise_rows"] += 1
                            if candidate_state["crypto_state"] == "VALID" and candidate_state["discovery_state"] != "REJECTED":
                                counters["mnemonic_candidate_valid_rows"] += 1
                                fingerprint = row.get("safe_fingerprint", row.get("fingerprint"))
                                if isinstance(fingerprint, str) and fingerprint:
                                    connection.execute(
                                        "INSERT INTO candidate_fingerprints VALUES (?, ?) ON CONFLICT(value) DO UPDATE SET actionable=MAX(actionable,excluded.actionable)",
                                        (fingerprint, int(actionable)),
                                    )
                            _write_row(candidate_stream if actionable else noise_stream, row)
                        row, row_prefix = None, None
                    elif event in SCALARS:
                        if row_prefix is not None and prefix.startswith(row_prefix + "."):
                            _project(row, prefix[len(row_prefix) + 1:], value)
                        elif prefix in ROOT_FIELDS:
                            metadata[prefix] = value
                        elif current_file is not None and prefix.startswith("files.item."):
                            key = prefix[len("files.item."):]
                            if key in FILE_FIELDS:
                                current_file[key] = value
                            elif key.startswith("report."):
                                _file_detail(current_details, key[len("report."):], value)
                            else:
                                _file_detail(current_details, key, value)
                        elif prefix.startswith("finding_summary.") and prefix.split(".", 1)[1] in SUMMARY_COUNTS:
                            reported_counts[prefix.split(".", 1)[1]] = value
                if progress is not None:
                    progress(total_bytes, total_bytes, counters["files_processed"], counters["retained_findings"])
            if metadata.get("source_type") not in {"FOLDER", "FILE", "IMAGE"} and not seen_views:
                raise ReportAnalysisError("Nie rozpoznano raportu BFRS.")
            unique, actionable = connection.execute(
                "SELECT COUNT(*), COALESCE(SUM(actionable),0) FROM fingerprints"
            ).fetchone()
            counters["retained_unique_valid_secret_fingerprints"] = unique
            counters["retained_unique_valid_secret_fingerprints_excluding_likely_noise"] = actionable
            candidate_unique, candidate_actionable = connection.execute(
                "SELECT COUNT(*), COALESCE(SUM(actionable),0) FROM candidate_fingerprints"
            ).fetchone()
            counters["mnemonic_candidate_unique_valid_fingerprints"] = candidate_unique
            counters["mnemonic_candidate_unique_valid_fingerprints_excluding_likely_noise"] = candidate_actionable
        database.unlink()
        sample_files = [item for bucket in sample_file_buckets.values() for item in bucket]
        summary = {
            "analysis_schema_version": 1,
            "input_report": str(source), "input_report_bytes": total_bytes,
            "report_metadata": metadata, "reported_finding_counts": dict(reported_counts),
            "retained_finding_counts": dict(counters), "by_target_and_kind": dict(categories),
            "file_priority_counts": dict(priorities),
            "sample_files": sample_files, "sample_findings": sample_findings,
            "notes": [
                "Statusy walidacji pochodza z raportu; nie wykonano nowego skanu ani sprawdzania salda.",
                "Kopie target_findings w raportach poszczegolnych plikow nie sa liczone ponownie.",
                "Pelne liczniki raportu moga obejmowac zagregowane odrzucenia i seedy przypominajace slowniki.",
                "Widoki mnemonic_candidates i diagnostyka kluczy/portfeli nakladaja sie na target_findings; nie nalezy ich sumowac.",
                "SECRET_REVIEW oznacza plik do analizy; sama walidacja seeda nie dowodzi, ze byl uzywanym portfelem.",
                "Unikalnosc opiera sie na dostepnych fingerprintach; wspolna tozsamosc roznych formatow nie jest wnioskowana.",
            ],
        }
        (staging / "podsumowanie.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        lines = [
            "BFRS - analiza duzego raportu", f"Raport: {source}",
            f"Rozmiar raportu: {total_bytes / 2**30:.2f} GiB",
            f"Pliki w raporcie: {counters['files_processed']}",
            f"Pliki z wynikami do sprawdzenia: {sum(priorities.values())}",
            f"  SECRET_REVIEW: {priorities['SECRET_REVIEW']}",
            f"  WALLET_STRUCTURE: {priorities['WALLET_STRUCTURE']}",
            f"  OTHER_REVIEW: {priorities['OTHER_REVIEW']}", "",
            f"  SEED_NOISE (prawdopodobny szum): {priorities['SEED_NOISE']}", "",
            "Zachowane wpisy target_findings (bez podwojnego liczenia):",
            f"  Wszystkie: {counters['retained_findings']}",
            f"  Poprawne klucze/seedy - wystapienia: {counters['retained_valid_secret_occurrences']}",
            f"  Unikalne fingerprinty kluczy/seedow: {unique}",
            f"  Unikalne fingerprinty po odlozeniu prawdopodobnego szumu: {actionable}",
            f"  Wpisy prawdopodobnie przypadkowe: {counters['likely_false_positive_rows']}",
            f"  Osobny widok kandydatow mnemonic: {counters['mnemonic_candidate_rows']}", "",
            f"  Unikalne poprawne fingerprinty w widoku mnemonic: {candidate_unique}",
            f"  Po odlozeniu prawdopodobnego szumu: {candidate_actionable}", "",
            "Pelne liczniki z raportu (moga obejmowac zagregowany szum):",
            *[f"  {key}: {value}" for key, value in sorted(reported_counts.items())], "",
            "Pliki wynikowe:", "  podsumowanie.json - liczniki i niewielka probka lokalizacji",
            "  najwazniejsze_pliki.jsonl - pliki z wynikami do sprawdzenia",
            "  wyniki_do_sprawdzenia.jsonl - wybrane publiczne dane znalezisk",
            "  kandydaci_seedow.jsonl - osobny, nakladajacy sie widok seedow",
            "  seedy_prawdopodobnie_przypadkowe.jsonl - prawdopodobny szum", "",
            *summary["notes"],
        ]
        (staging / "podsumowanie.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
        os.rename(staging, output_dir)
        return summary
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _choose_report() -> Path | None:
    import tkinter
    from tkinter import filedialog
    root = tkinter.Tk()
    root.withdraw()
    try:
        selected = filedialog.askopenfilename(title="Wybierz raport BFRS", filetypes=[("Raport JSON", "*.json"), ("Wszystkie pliki", "*.*")])
    finally:
        root.destroy()
    return Path(selected) if selected else None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Analiza duzego raportu BFRS bez wczytywania go w calosci.")
    parser.add_argument("--input", type=Path, help="Raport JSON; bez parametru otworzy sie wybor pliku.")
    parser.add_argument("--output-dir", type=Path, help="Nowy folder wynikow; domyslnie obok raportu.")
    args = parser.parse_args(argv)
    try:
        source = args.input or _choose_report()
        if source is None:
            print("Anulowano.")
            return 0
        destination = args.output_dir or source.with_name(source.stem + "-analiza-" + time.strftime("%Y%m%d-%H%M%S"))

        def progress(done, total, files, findings):
            print(f"\rOdczyt: {done * 100 / max(total, 1):5.1f}% | {done / 2**30:.2f}/{total / 2**30:.2f} GiB | pliki={files} | wpisy={findings}", end="", flush=True)

        analyze_report(source, destination, progress=progress)
        print(f"\nGotowe. Podsumowanie: {destination.resolve() / 'podsumowanie.txt'}")
        return 0
    except Exception as error:
        print(f"\nAnaliza nie powiodla sie: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
