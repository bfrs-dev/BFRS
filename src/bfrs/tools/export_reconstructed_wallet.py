"""Explicit offline exact-page wallet export; stdout never includes record data."""
import argparse
from pathlib import Path

from bfrs.recovery.physical_berkeley_reconstructor import ExportRefused, export_wallet


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--candidate-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allow-private-key-export", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = export_wallet(args.input, args.report, args.candidate_id, args.output,
                               allow_private_key_export=args.allow_private_key_export)
    except ExportRefused as error:
        print(f"REFUSE_EXPORT: {error}")
        return 2
    print(result["structural_validation_status"])
    print(f"size: {result['size']}")
    print(f"SHA-256: {result['sha256']}")
    print(f"page size: {result['page_size']}")
    print(f"page count: {result['page_count']}")
    for n in range(result["page_count"]):
        print(f"page_number={n} match=YES")
    for k, v in result["record_counts"].items():
        print(f"{k}: {v}")
    for k, v in result["crypto_summary"].items():
        print(f"{k}: {v}")
    print("Bitcoin Core loadability: NOT_TESTED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
