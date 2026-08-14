"""Classify and aggregate wallet-related USN history."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from enum import Enum

from bfrs.recovery.ntfs_bitcoin_artifacts import NTFSStaleRecoveryContext
from bfrs.recovery.usn_journal import UsnRecord

USN_REASON_FILE_DELETE = 0x00000200


class WalletArtifactState(str, Enum):
    ACTIVE_CURRENT = "ACTIVE_CURRENT"
    HISTORICAL = "HISTORICAL"
    DELETED = "DELETED"
    UNKNOWN_REFERENCE = "UNKNOWN_REFERENCE"


@dataclass(frozen=True, slots=True)
class HistoricalWalletArtifact:
    family: str
    name: str
    state: str
    source: str
    first_seen: str
    last_seen: str
    event_count: int
    file_reference: int
    parent_reference: int
    path_if_reconstructable: str | None
    confidence: str
    reason_codes: tuple[str, ...]
    provenance: tuple[dict[str, Any], ...]
    volume_start: int
    volume_end: int | None
    volume_provenance: str


class NtfsWalletHistoryAnalyzer:
    def analyze(self, records: tuple[UsnRecord, ...],
                context: NTFSStaleRecoveryContext | None = None) -> tuple[HistoricalWalletArtifact, ...]:
        names: dict[int, tuple[str, int]] = {}
        for event in records:
            names[self._record_number(event.file_reference)] = (event.filename, self._record_number(event.parent_reference))
        grouped: dict[tuple[int, str, int], list[UsnRecord]] = {}
        for event in records:
            path = self._path(event, names)
            family, codes, confidence = self._candidate(event.filename, path, event.parent_reference, names)
            if family is None:
                continue
            key = (event.file_reference, event.filename.casefold(), event.parent_reference)
            grouped.setdefault(key, []).append(event)
        output = []
        for (_, _, _), events in grouped.items():
            ordered = sorted(events, key=lambda e: e.timestamp)
            event = ordered[-1]
            path = self._path(event, names)
            family, codes, confidence = self._candidate(event.filename, path, event.parent_reference, names)
            active = self._active_match(event.file_reference, event.filename, event.parent_reference, context)
            deleted = any(item.reason & USN_REASON_FILE_DELETE for item in events)
            parent_known = self._record_number(event.parent_reference) in names
            if active:
                state, extra = WalletArtifactState.ACTIVE_CURRENT, "CURRENT_MFT_REFERENCE_MATCH"
            elif deleted:
                state, extra = WalletArtifactState.DELETED, "USN_FILE_DELETE_EVENT"
            elif parent_known:
                state, extra = WalletArtifactState.HISTORICAL, "HISTORICAL_PARENT_CHAIN"
            else:
                state, extra = WalletArtifactState.UNKNOWN_REFERENCE, "PARENT_REFERENCE_UNRESOLVED"
            output.append(HistoricalWalletArtifact(
                family or "unknown", event.filename, state.value, event.source_image,
                ordered[0].timestamp, ordered[-1].timestamp, len(events), event.file_reference,
                event.parent_reference, path, confidence, tuple((*codes, extra)),
                tuple({"source_image": e.source_image, "physical_offset": e.physical_offset,
                       "logical_j_offset": e.logical_j_offset,
                       "physical_source_segments": list(e.physical_segments)} for e in ordered),
                getattr(getattr(context, "boot", None), "volume_offset", 0),
                getattr(getattr(context, "boot", None), "volume_end", None),
                getattr(context, "provenance", "unknown"),
            ))
        return tuple(sorted(output, key=lambda a: (a.family, a.name.casefold(), a.file_reference)))

    @staticmethod
    def _record_number(reference: int) -> int:
        return reference & ((1 << 48) - 1)

    def _path(self, event: UsnRecord, names: dict[int, tuple[str, int]]) -> str | None:
        parts, current, seen = [event.filename], self._record_number(event.parent_reference), set()
        while current in names and current not in seen and len(parts) < 64:
            seen.add(current)
            name, current = names[current]
            parts.append(name)
            if current in (0, 5):
                return "\\" + "\\".join(reversed(parts))
        return "\\".join(reversed(parts)) if len(parts) > 1 else None

    def _candidate(self, name: str, path: str | None, parent_ref: int,
                   names: dict[int, tuple[str, int]]):
        low, folded = name.casefold(), (path or "").replace("/", "\\").casefold()
        parent_name = names.get(self._record_number(parent_ref), ("", 0))[0].casefold()
        if low in ("wallet.dat", "wallet.dat-journal"):
            return "bitcoin_core", ("BITCOIN_CANONICAL_WALLET_NAME",), "HIGH"
        if low in ("electrum.dat", "default_wallet"):
            return "electrum", ("ELECTRUM_KNOWN_WALLET_NAME",), "HIGH"
        if parent_name == "wallets" and "electrum" in folded:
            return "electrum", ("DIRECT_CHILD_OF_ELECTRUM_WALLETS",), "HIGH"
        if low in ("bitcoin", "wallets") and (low == "bitcoin" or "bitcoin" in folded):
            return "bitcoin_core", ("BITCOIN_DIRECTORY_REFERENCE",), "MEDIUM"
        if low == "electrum" or (low == "wallets" and "electrum" in folded):
            return "electrum", ("ELECTRUM_DIRECTORY_REFERENCE",), "MEDIUM"
        return None, (), "LOW"

    def _active_match(self, reference: int, name: str, parent: int,
                      context: NTFSStaleRecoveryContext | None) -> bool:
        if context is None:
            return False
        number, sequence = self._record_number(reference), (reference >> 48) & 0xFFFF
        record = context.current_records_by_number.get(number)
        if record is None or not record.allocated or record.sequence != sequence:
            return False
        parent_number = self._record_number(parent)
        return any(a.filename.casefold() == name.casefold() and a.parent_mft_record_number == parent_number for a in record.aliases)
