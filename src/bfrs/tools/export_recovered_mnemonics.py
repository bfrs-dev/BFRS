"""Explicit, offline export of validated mnemonic phrases."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence

from bfrs.recovery.mnemonic.mnemonic_recovery_pipeline import MnemonicRecoveryPipeline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m bfrs.tools.export_recovered_mnemonics",
        description="Explicit export of validated BIP39/Electrum mnemonic secrets",
    )
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--allow-seed-export", action="store_true")
    parser.add_argument("--chunk-mib", type=int, default=64)
    parser.add_argument("--overlap-kib", type=int, default=64)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    if not arguments.allow_seed_export:
        print("refusing seed export: pass --allow-seed-export explicitly", file=sys.stderr)
        return 2
    if arguments.output.exists():
        print("refusing to overwrite secret output", file=sys.stderr)
        return 4
    manifest = arguments.manifest or arguments.output.with_suffix(
        arguments.output.suffix + ".manifest.json")
    if manifest.exists():
        print("refusing to overwrite manifest", file=sys.stderr)
        return 4
    try:
        result = MnemonicRecoveryPipeline(
            chunk_size=arguments.chunk_mib * 1024 * 1024,
            overlap=arguments.overlap_kib * 1024,
        ).scan(arguments.input)
        unique = {}
        for item in result.occurrences:
            key = (item.candidate.mnemonic_standard, item.candidate.fingerprint)
            unique.setdefault(key, item)
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        with arguments.output.open("x", encoding="utf-8", newline="\n") as target:
            for item in unique.values():
                target.write(item.secret.reveal() + "\n")
        safe_manifest = {
            "warning": "Secret phrases were written only to the separately named output.",
            "source": result.source,
            "exported_count": len(unique),
            "entries": [{
                "mnemonic_standard": item.candidate.mnemonic_standard,
                "fingerprint": item.candidate.fingerprint,
                "word_count": item.candidate.word_count,
                "validation_status": item.candidate.validation_status,
            } for item in unique.values()],
        }
        manifest.parent.mkdir(parents=True, exist_ok=True)
        with manifest.open("x", encoding="utf-8") as target:
            json.dump(safe_manifest, target, indent=2, sort_keys=True)
    except (OSError, ValueError) as error:
        print(f"export error: {error}", file=sys.stderr)
        return 4
    print(f"exported validated seed phrases: {len(unique)}")
    print(f"secret output: {arguments.output.resolve()}")
    print(f"safe manifest: {manifest.resolve()}")
    return 0
