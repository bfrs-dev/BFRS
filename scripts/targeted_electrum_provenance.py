"""Run bounded Electrum provenance triage without a raw-image rescan."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from bfrs.recovery.electrum_provenance_triage import (
    ElectrumProvenanceTriage,
    TargetRange,
)


def _target(value: str) -> TargetRange:
    try:
        name, start, end = value.split(":", 2)
        result = TargetRange(name, int(start, 0), int(end, 0))
    except (TypeError, ValueError) as error:
        raise argparse.ArgumentTypeError("expected NAME:START:END") from error
    if not name or result.physical_start < 0 or result.physical_end <= result.physical_start:
        raise argparse.ArgumentTypeError("invalid targeted range")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--candidate", required=True, action="append", type=_target)
    arguments = parser.parse_args()
    result = ElectrumProvenanceTriage(arguments.input).run(arguments.candidate)
    payload = {
        "schema": "electrum_raw_candidate_provenance_triage_v1",
        "source": str(arguments.input.resolve()),
        "targeted_only": True,
        "candidates": [item.safe_dict() for item in result],
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"targeted candidates: {len(result)}")
    print(f"report path: {arguments.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
