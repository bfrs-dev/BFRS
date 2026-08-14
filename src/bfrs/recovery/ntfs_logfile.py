"""Conservative streaming analysis of NTFS `$LogFile` LFS metadata."""

from __future__ import annotations

from dataclasses import dataclass, replace
import re
from typing import Any, Iterable

from bfrs.recovery.ntfs_bitcoin_artifacts import NTFSStaleRecoveryContext
from bfrs.recovery.ntfs_system_files import NtfsResolvedStream, NtfsStreamChunk


MIN_PAGE_SIZE = 512
MAX_PAGE_SIZE = 64 * 1024
LFS_RECORD_HEADER_SIZE = 48


class LfsStructureError(ValueError):
    """Controlled malformed LFS structure."""


@dataclass(frozen=True, slots=True)
class LfsRestartInfo:
    system_page_size: int
    log_page_size: int
    restart_offset: int
    record_header_length: int
    log_page_data_offset: int


@dataclass(frozen=True, slots=True)
class LfsPage:
    kind: str
    logical_offset: int
    size: int
    fixed_data: bytes
    physical_segments: tuple[dict[str, int], ...]
    restart: LfsRestartInfo | None = None
    next_record_offset: int | None = None


@dataclass(frozen=True, slots=True)
class LfsLogRecord:
    lsn: int
    previous_lsn: int
    undo_next_lsn: int
    client_id: int
    transaction_id: int
    record_type: int | None
    flags: int
    client_data_length: int
    logical_offset: int
    physical_segments: tuple[dict[str, int], ...]
    client_data: bytes


@dataclass(frozen=True, slots=True)
class LogFileWalletEvidence:
    family: str
    name: str
    state: str
    confidence: str
    reason_codes: tuple[str, ...]
    source: str
    volume_start: int
    logical_logfile_offset: int
    physical_provenance: tuple[dict[str, int], ...]
    lsn_if_available: int | None
    transaction_id_if_available: int | None
    path_if_reconstructable: str | None
    correlated_sources: tuple[str, ...]
    event_count: int = 1


@dataclass(frozen=True, slots=True)
class LogFileRecoverySummary:
    files_found: int
    physical_bytes_examined: int
    restart_pages_valid: int
    record_pages_valid: int
    lfs_records_valid: int
    malformed_pages: int
    malformed_records: int
    wallet_evidence_count: int
    ignored_application_references: int
    evidences: tuple[LogFileWalletEvidence, ...]
    failures: tuple[str, ...]


class LfsPageParser:
    """Validate one complete LFS restart or record page."""

    def parse(self, data: bytes, *, logical_offset: int,
              bytes_per_sector: int,
              physical_segments: tuple[dict[str, int], ...] = (),
              expected_log_page_size: int | None = None,
              log_page_data_offset: int | None = None) -> LfsPage:
        if len(data) < 30:
            raise LfsStructureError("lfs_page_truncated")
        signature = data[:4]
        if signature not in (b"RSTR", b"RCRD"):
            raise LfsStructureError("lfs_page_signature_invalid")
        if (len(data) < MIN_PAGE_SIZE or len(data) > MAX_PAGE_SIZE or
                len(data) % bytes_per_sector):
            raise LfsStructureError("lfs_page_size_invalid")
        fixed = self._apply_fixup(data, bytes_per_sector)
        if signature == b"RSTR":
            system_size = self._u32(fixed, 16)
            log_size = self._u32(fixed, 20)
            restart_offset = self._u16(fixed, 24)
            if not self._page_size(system_size) or not self._page_size(log_size):
                raise LfsStructureError("restart_page_geometry_invalid")
            if system_size != len(data):
                raise LfsStructureError("restart_system_page_size_mismatch")
            if restart_offset < 30 or restart_offset + 42 > len(fixed):
                raise LfsStructureError("restart_area_bounds_invalid")
            restart_length = self._u16(fixed, restart_offset + 20)
            record_header = self._u16(fixed, restart_offset + 36)
            data_offset = self._u16(fixed, restart_offset + 38)
            if (restart_length < 42 or restart_offset + restart_length > len(fixed)
                    or record_header < LFS_RECORD_HEADER_SIZE
                    or record_header > 256 or record_header % 8
                    or data_offset < 40 or data_offset >= log_size
                    or data_offset % 8):
                raise LfsStructureError("restart_area_fields_invalid")
            restart = LfsRestartInfo(system_size, log_size, restart_offset,
                                     record_header, data_offset)
            return LfsPage("RSTR", logical_offset, len(data), fixed,
                           physical_segments, restart=restart)
        if expected_log_page_size is None or len(data) != expected_log_page_size:
            raise LfsStructureError("record_page_size_mismatch")
        if log_page_data_offset is None:
            raise LfsStructureError("record_page_data_offset_unknown")
        next_offset = self._u16(fixed, 24)
        if (log_page_data_offset < 40 or log_page_data_offset >= len(fixed)
                or log_page_data_offset % 8
                or next_offset and
                (next_offset < log_page_data_offset or next_offset > len(fixed)
                 or next_offset % 8)):
            raise LfsStructureError("record_page_offsets_invalid")
        return LfsPage("RCRD", logical_offset, len(data), fixed,
                       physical_segments, next_record_offset=next_offset)

    @staticmethod
    def _page_size(value: int) -> bool:
        return (MIN_PAGE_SIZE <= value <= MAX_PAGE_SIZE and
                value & (value - 1) == 0)

    @staticmethod
    def _apply_fixup(data: bytes, sector_size: int) -> bytes:
        usa_offset = int.from_bytes(data[4:6], "little")
        usa_count = int.from_bytes(data[6:8], "little")
        sectors = len(data) // sector_size
        if (usa_count != sectors + 1 or usa_offset < 8 or
                usa_offset + usa_count * 2 > len(data)):
            raise LfsStructureError("lfs_usa_bounds_invalid")
        usn = data[usa_offset:usa_offset + 2]
        if len(usn) != 2:
            raise LfsStructureError("lfs_usa_bounds_invalid")
        fixed = bytearray(data)
        for index in range(1, usa_count):
            trailer = index * sector_size - 2
            if data[trailer:trailer + 2] != usn:
                raise LfsStructureError("lfs_usa_mismatch")
            replacement = usa_offset + index * 2
            fixed[trailer:trailer + 2] = data[replacement:replacement + 2]
        return bytes(fixed)

    @staticmethod
    def _u16(data: bytes, offset: int) -> int:
        return int.from_bytes(data[offset:offset + 2], "little")

    @staticmethod
    def _u32(data: bytes, offset: int) -> int:
        return int.from_bytes(data[offset:offset + 4], "little")


class LfsRecordExtractor:
    def extract(self, page: LfsPage, *, data_offset: int,
                record_header_length: int) -> tuple[tuple[LfsLogRecord, ...], tuple[str, ...]]:
        if page.kind != "RCRD":
            return (), ()
        end = page.next_record_offset or data_offset
        if end == data_offset:
            return (), ()
        records: list[LfsLogRecord] = []
        failures: list[str] = []
        cursor = data_offset
        while cursor < end:
            if end - cursor < record_header_length:
                failures.append("lfs_record_truncated")
                break
            header = page.fixed_data[cursor:cursor + record_header_length]
            if not any(header):
                break
            lsn = int.from_bytes(header[0:8], "little")
            previous = int.from_bytes(header[8:16], "little")
            undo = int.from_bytes(header[16:24], "little")
            client_length = int.from_bytes(header[24:28], "little")
            client_id = int.from_bytes(header[28:32], "little")
            record_type_raw = int.from_bytes(header[32:36], "little")
            transaction = int.from_bytes(header[36:40], "little")
            flags = int.from_bytes(header[40:42], "little")
            total = (record_header_length + client_length + 7) & ~7
            if not lsn:
                failures.append("lfs_record_lsn_invalid")
                break
            if record_type_raw not in (1, 2):
                failures.append("lfs_record_type_unknown")
                break
            if client_length > end - cursor - record_header_length or cursor + total > end:
                failures.append("lfs_client_data_bounds_invalid")
                break
            logical = page.logical_offset + cursor
            segments = self._subsegments(page.physical_segments, cursor, total)
            payload_start = cursor + record_header_length
            payload = page.fixed_data[payload_start:payload_start + client_length]
            records.append(LfsLogRecord(
                lsn, previous, undo, client_id, transaction, record_type_raw,
                flags, client_length, logical, segments, payload,
            ))
            cursor += total
        return tuple(records), tuple(failures)

    @staticmethod
    def _subsegments(segments, relative: int, length: int):
        result = []
        record_start, record_end = relative, relative + length
        page_base = segments[0].get("page_logical_start", 0) if segments else 0
        for segment in segments:
            seg_rel = segment["logical_start"] - page_base
            left, right = max(record_start, seg_rel), min(record_end,
                                                          seg_rel + segment["length"])
            if left < right:
                result.append({
                    "logical_start": page_base + left,
                    "physical_start": segment["physical_start"] + left - seg_rel,
                    "length": right - left,
                })
        return tuple(result)


class NtfsLogFileAnalyzer:
    """Stream LFS pages, extract records, and aggregate safe name evidence."""

    def analyze(self, chunks: Iterable[NtfsStreamChunk], *, context,
                logical_size: int,
                usn_artifacts: Iterable[Any] = ()) -> LogFileRecoverySummary:
        parser = LfsPageParser()
        extractor = LfsRecordExtractor()
        pending = bytearray()
        pending_start: int | None = None
        segments: list[tuple[int, int, int]] = []
        system_size = log_size = data_offset = header_length = None
        page_records: list[LfsLogRecord] = []
        failures: list[str] = []
        bytes_examined = restart_valid = record_valid = malformed_pages = malformed_records = 0

        def page_segments(start: int, end: int):
            output = []
            for left, right, physical in segments:
                overlap_left, overlap_right = max(start, left), min(end, right)
                if overlap_left < overlap_right:
                    output.append({
                        "logical_start": overlap_left,
                        "physical_start": physical + overlap_left - left,
                        "length": overlap_right - overlap_left,
                        "page_logical_start": start,
                    })
            return tuple(output)

        def consume(final=False, gap=False):
            nonlocal pending, pending_start, segments, system_size, log_size
            nonlocal data_offset, header_length, restart_valid, record_valid
            nonlocal malformed_pages, malformed_records
            if pending_start is None:
                return
            used = 0
            while len(pending) - used >= 4:
                signature = bytes(pending[used:used + 4])
                logical = pending_start + used
                if signature == b"RSTR":
                    if len(pending) - used < 24:
                        break
                    size = int.from_bytes(pending[used + 16:used + 20], "little")
                    if not parser._page_size(size):
                        failures.append("restart_page_declared_size_invalid")
                        malformed_pages += 1
                        used += MIN_PAGE_SIZE
                        continue
                elif signature == b"RCRD" and log_size is not None:
                    size = log_size
                else:
                    if len(pending) - used < MIN_PAGE_SIZE:
                        break
                    if any(pending[used:used + MIN_PAGE_SIZE]):
                        failures.append("lfs_page_signature_invalid")
                        malformed_pages += 1
                    used += MIN_PAGE_SIZE
                    continue
                if len(pending) - used < size:
                    break
                raw = bytes(pending[used:used + size])
                provenance = page_segments(logical, logical + size)
                try:
                    page = parser.parse(
                        raw, logical_offset=logical,
                        bytes_per_sector=context.boot.bytes_per_sector,
                        physical_segments=provenance,
                        expected_log_page_size=log_size,
                        log_page_data_offset=data_offset,
                    )
                except (ValueError, LfsStructureError) as exc:
                    failures.append(str(exc))
                    malformed_pages += 1
                else:
                    if page.kind == "RSTR":
                        restart_valid += 1
                        system_size = page.restart.system_page_size
                        log_size = page.restart.log_page_size
                        data_offset = page.restart.log_page_data_offset
                        header_length = page.restart.record_header_length
                    else:
                        record_valid += 1
                        records, rejected = extractor.extract(
                            page, data_offset=data_offset,
                            record_header_length=header_length,
                        )
                        page_records.extend(records)
                        malformed_records += len(rejected)
                        failures.extend(rejected)
                used += size
            if final and len(pending) > used and any(pending[used:]):
                failures.append("lfs_page_truncated_at_gap" if gap
                                else "lfs_page_truncated_at_stream_end")
                malformed_pages += 1
                used = len(pending)
            if used:
                pending = pending[used:]
                pending_start += used
                segments = [item for item in segments if item[1] > pending_start]
            if final:
                pending.clear()
                pending_start = None
                segments.clear()

        for chunk in chunks:
            bytes_examined += len(chunk.data)
            discontinuous = (pending_start is not None and
                             chunk.logical_start != pending_start + len(pending))
            if chunk.gap_before or discontinuous or not chunk.data:
                consume(True, gap=True)
            if not chunk.data:
                continue
            if pending_start is None:
                pending_start = chunk.logical_start
            pending.extend(chunk.data)
            if chunk.physical_start is not None:
                segments.append((chunk.logical_start,
                                 chunk.logical_start + len(chunk.data),
                                 chunk.physical_start))
            consume(False)
        consume(True)
        evidences, ignored = self._wallet_evidence(
            page_records, context=context, usn_artifacts=tuple(usn_artifacts)
        )
        return LogFileRecoverySummary(
            1, bytes_examined, restart_valid, record_valid, len(page_records),
            malformed_pages, malformed_records, len(evidences), ignored,
            evidences, tuple(dict.fromkeys(failures)),
        )

    def _wallet_evidence(self, records, *, context, usn_artifacts):
        events: dict[tuple[str, str, int], list[tuple[LfsLogRecord, str, str, tuple[str, ...]]]] = {}
        ignored = 0
        for record in records:
            for text in self._utf16_strings(record.client_data):
                candidate = self._classify(text)
                if candidate == "IGNORED":
                    ignored += 1
                    continue
                if candidate is None:
                    continue
                family, name, confidence, reasons = candidate
                key = (family, name.casefold(), context.boot.volume_offset)
                events.setdefault(key, []).append((record, text, confidence, reasons))
        output = []
        for (family, _, volume), items in events.items():
            record, path, confidence, reasons = items[0]
            name = path.replace("/", "\\").rstrip("\\").split("\\")[-1]
            sources = ["LOGFILE"]
            state = "HISTORICAL" if confidence in ("HIGH", "MEDIUM") else "UNKNOWN_REFERENCE"
            for current in context.current_records_by_number.values():
                if any(alias.filename.casefold() == name.casefold()
                       for alias in current.aliases):
                    sources.append("MFT")
                    if current.allocated:
                        state = "ACTIVE_CURRENT"
                    break
            for artifact in usn_artifacts:
                if (getattr(artifact, "volume_start", volume) == volume and
                        artifact.name.casefold() == name.casefold()):
                    sources.append("USN_JOURNAL")
                    if artifact.state == "ACTIVE_CURRENT":
                        state = "ACTIVE_CURRENT"
                    elif artifact.state == "DELETED" and state != "ACTIVE_CURRENT":
                        state = "DELETED"
            output.append(LogFileWalletEvidence(
                family, name, state, confidence,
                tuple((*reasons, "LOGFILE_VALIDATED_PAYLOAD_UTF16_EVIDENCE")),
                "LOGFILE", volume, record.logical_offset,
                record.physical_segments, record.lsn, record.transaction_id,
                path if "\\" in path or "/" in path else None,
                tuple(dict.fromkeys(sources)), len(items),
            ))
        return tuple(sorted(output, key=lambda item: (item.volume_start,
                            item.family, item.name.casefold()))), ignored

    @staticmethod
    def _utf16_strings(payload: bytes):
        found = set()
        for parity in (0, 1):
            current: list[str] = []
            aligned = payload[parity:]
            for offset in range(0, len(aligned) - 1, 2):
                codepoint = int.from_bytes(aligned[offset:offset + 2], "little")
                character = chr(codepoint)
                if (codepoint >= 0x20 and not 0xD800 <= codepoint <= 0xDFFF
                        and character.isprintable()):
                    current.append(character)
                    if len(current) > 1024:
                        current = []
                else:
                    if len(current) >= 4:
                        found.add("".join(current).strip())
                    current = []
            if len(current) >= 4:
                found.add("".join(current).strip())
        maximal = {
            text for text in found
            if not any(text != other and text in other for other in found)
        }
        return tuple(sorted(maximal))

    @staticmethod
    def _classify(text: str):
        normalized = text.replace("/", "\\").strip(" \x00")
        low = normalized.casefold()
        basename = low.rstrip("\\").split("\\")[-1]
        if (re.search(r"electrum[^\\]*\.exe-[^\\]*\.pf$", low) or
                basename.endswith((".dll", ".exe", ".pf", ".ico", ".cache"))):
            return "IGNORED"
        if basename in ("wallet.dat", "wallet.dat-journal"):
            return "bitcoin_core", normalized, "HIGH", ("BITCOIN_CANONICAL_WALLET_NAME",)
        if basename in ("electrum.dat", "default_wallet"):
            return "electrum", normalized, "HIGH", ("ELECTRUM_KNOWN_WALLET_NAME",)
        if re.search(r"(?:^|\\)electrum\\wallets\\[^\\]+$", low):
            return "electrum", normalized, "HIGH", ("DIRECT_CHILD_OF_ELECTRUM_WALLETS",)
        if re.search(r"(?:^|\\)bitcoin\\wallets\\[^\\]+$", low):
            return "bitcoin_core", normalized, "HIGH", ("DIRECT_CHILD_OF_BITCOIN_WALLETS",)
        if low.endswith("\\electrum") or low.endswith("\\electrum\\wallets"):
            return "electrum", normalized, "MEDIUM", ("ELECTRUM_DIRECTORY_REFERENCE",)
        if low.endswith("\\bitcoin") or low.endswith("\\bitcoin\\wallets"):
            return "bitcoin_core", normalized, "MEDIUM", ("BITCOIN_DIRECTORY_REFERENCE",)
        if "wallet" in basename and ("backup" in basename or "recovery" in basename):
            if basename.endswith((".txt", ".md", ".html", ".py", ".js")):
                return None
            return "unknown", normalized, "LOW", ("GENERIC_WALLET_BACKUP_OR_RECOVERY_NAME",)
        return None
