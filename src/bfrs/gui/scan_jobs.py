"""Durable scan-request journal. Never contains findings, keys or passwords."""
from __future__ import annotations
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import uuid

from bfrs.application.scan_config import ScanConfig
from bfrs.core.source_types import SourceType
from bfrs.reporting.atomic_output import write_json
from bfrs.scanners.target_registry import AVAILABLE_TARGETS

_PATHS = ("input_path", "output_path", "recovery_dir", "revalidate_wallet_records", "checkpoint", "resume_checkpoint")
_BOOLS = ("recover_wallets", "electrum_only", "seed_scan_only", "include_mnemonic", "include_bitcoin_context", "skip_mnemonic", "protect_existing_report")
_INTS = ("start", "chunk_mib", "overlap_kib", "workers", "file_workers", "cluster_mib", "padding_mib", "minimum_hits", "minimum_distinct_types")
_STATES = {"running", "stopped", "failed", "completed", "superseded"}


class ScanJobError(ValueError):
    pass


def encode_config(config: ScanConfig) -> dict:
    # Explicit allowlist: future secret-bearing fields must never be persisted.
    result = {name: (str(getattr(config, name).absolute()) if getattr(config, name) is not None else None) for name in _PATHS}
    result.update({name: getattr(config, name) for name in (*_BOOLS, *_INTS)})
    result.update(end=config.end, source_type=config.source_type.value if config.source_type else None,
                  targets=sorted(config.targets) if config.targets is not None else None)
    return result


def decode_config(value: dict) -> ScanConfig:
    allowed = set((*_PATHS, *_BOOLS, *_INTS, "end", "source_type", "targets"))
    if not isinstance(value, dict) or set(value) != allowed:
        raise ScanJobError("unsupported or incomplete saved scan configuration")
    values = dict(value)
    for name in _PATHS:
        item = values[name]
        if item is not None and (not isinstance(item, str) or not item.strip()):
            raise ScanJobError(f"invalid saved path: {name}")
        if name in ("input_path", "output_path") and item is None:
            raise ScanJobError(f"missing saved path: {name}")
        values[name] = Path(item) if item is not None else None
        if values[name] is not None and not values[name].is_absolute():
            raise ScanJobError(f"saved path must be absolute: {name}")
    for name in _BOOLS:
        if type(values[name]) is not bool:
            raise ScanJobError(f"invalid saved flag: {name}")
    for name in _INTS:
        if type(values[name]) is not int:
            raise ScanJobError(f"invalid saved number: {name}")
    if values["end"] is not None and type(values["end"]) is not int:
        raise ScanJobError("invalid saved end offset")
    targets = values["targets"]
    if targets is not None and (not isinstance(targets, list) or
            any(not isinstance(t, str) or t not in AVAILABLE_TARGETS for t in targets)):
        raise ScanJobError("invalid saved detector selection")
    values["targets"] = frozenset(targets) if targets is not None else None
    values["source_type"] = SourceType(values["source_type"]) if values["source_type"] else None
    return ScanConfig(**values)


@dataclass(frozen=True)
class ScanJob:
    job_id: str
    state: str
    config: ScanConfig
    updated: str

    def for_resume(self) -> ScanConfig:
        checkpoint = self.config.checkpoint_path
        if checkpoint is None:
            raise ScanJobError("This task has no checkpoint; its progress cannot be resumed.")
        return replace(self.config, checkpoint=None, resume_checkpoint=checkpoint,
                       protect_existing_report=True)


class ScanJobStore:
    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self.load_errors: list[str] = []

    def _path(self, job_id: str) -> Path:
        if not re.fullmatch(r"[0-9a-f]{32}", job_id):
            raise ScanJobError("invalid scan task ID")
        return self.directory / f"{job_id}.json"

    def begin(self, config: ScanConfig) -> ScanJob:
        # Every attempt has its own record. A failed incompatible resume never
        # replaces the last known working configuration of the earlier attempt.
        job = ScanJob(uuid.uuid4().hex, "running", config, datetime.now(timezone.utc).isoformat())
        self._save(job, overwrite=False)
        return job

    def _save(self, job: ScanJob, *, overwrite=True):
        write_json(self._path(job.job_id), {"version": 1, "job_id": job.job_id,
            "state": job.state, "updated": job.updated, "config": encode_config(job.config)}, overwrite=overwrite)

    def load(self, job_id: str) -> ScanJob:
        path = self._path(job_id)
        if path.stat().st_size > 1024**2:
            raise ScanJobError("oversized scan task record")
        value = json.loads(path.read_text(encoding="utf-8-sig"))
        if (not isinstance(value, dict) or type(value.get("version")) is not int or value.get("version") != 1 or value.get("job_id") != job_id
                or value.get("state") not in _STATES or not isinstance(value.get("updated"), str)):
            raise ScanJobError("unsupported or damaged scan task record")
        return ScanJob(job_id, value["state"], decode_config(value["config"]), value["updated"])

    def incomplete(self) -> list[ScanJob]:
        self.load_errors = []
        jobs = []
        if not self.directory.exists():
            return jobs
        for path in self.directory.glob("*.json"):
            try:
                job = self.load(path.stem)
                if job.state not in {"completed", "superseded"}:
                    jobs.append(job)
            except (OSError, ValueError, TypeError, KeyError) as error:
                # Show the record filename, never echo arbitrary JSON contents.
                self.load_errors.append(f"{path.name}: {type(error).__name__}")
        return sorted(jobs, key=lambda job: job.updated, reverse=True)

    def set_state(self, job_id: str, state: str) -> None:
        if state not in _STATES:
            raise ScanJobError("invalid task state")
        job = self.load(job_id)
        self._save(replace(job, state=state, updated=datetime.now(timezone.utc).isoformat()))

    def complete_checkpoint(self, job_id: str) -> None:
        current = self.load(job_id)
        checkpoint = current.config.checkpoint_path
        self.set_state(job_id, "completed")
        if checkpoint is not None:
            for job in self.incomplete():
                if job.config.checkpoint_path == checkpoint:
                    # The older attempt may have failed to publish its report.
                    # Do not claim that its old destination was completed.
                    self.set_state(job.job_id, "superseded")
