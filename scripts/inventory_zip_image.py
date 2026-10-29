"""Scan all bytes of a raw image for ZIP metadata; preserve restart progress."""
import argparse
import json
from pathlib import Path
import sqlite3
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from bfrs.recovery.raw_zip_inventory import scan_image, CHUNK_BYTES, DEFAULT_MAX_CANDIDATES


def main(argv=None):
    parser = argparse.ArgumentParser(description='Szukaj nagłówków ZIP w obrazie dysku, bez odszyfrowywania.')
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--resume', action='store_true')
    parser.add_argument('--chunk-mib', type=int, default=CHUNK_BYTES // 1048576)
    parser.add_argument('--max-candidates', type=int, default=DEFAULT_MAX_CANDIDATES)
    args = parser.parse_args(argv)
    last = 0

    def progress(row):
        nonlocal last
        now = time.monotonic()
        if now - last >= 2:
            print(f"Przeskanowano: {row['scanned_bytes'] / 1048576:.1f} / "
                  f"{row['total_bytes'] / 1048576:.1f} MiB | sygnatury: {row['signatures_seen']} | "
                  f"odrzucone: {row['rejected_signatures']}", flush=True)
            last = now

    try:
        result = scan_image(args.source, args.output, resume=args.resume,
                            chunk_size=args.chunk_mib * 1048576,
                            max_candidates=args.max_candidates, progress=progress)
    except (OSError, ValueError, sqlite3.Error, KeyError, TypeError) as error:
        print(f'Nie udało się uruchomić skanu: {error}', file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print(f"Trafienia do sprawdzenia: {args.output / 'zip_priority.jsonl'}")
    if result['scan_complete']:
        return 0
    if result['stop_reason'] in ('INTERRUPTED', 'STOP_REQUESTED'):
        return 130
    return 3 if result['stop_reason'] == 'CANDIDATE_LIMIT' else 2


if __name__ == '__main__':
    raise SystemExit(main())
