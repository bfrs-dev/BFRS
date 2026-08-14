"""Strict, secret-free NTFS USN_RECORD V2/V3 parsing."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone

WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True, slots=True)
class UsnRecord:
    file_reference: int
    parent_reference: int
    timestamp: str
    reason: int
    file_attributes: int
    filename: str
    major_version: int
    minor_version: int
    source_image: str
    physical_offset: int
    logical_j_offset: int | None
    physical_segments: tuple[dict[str, int], ...] = ()


@dataclass(frozen=True, slots=True)
class UsnParseResult:
    records: tuple[UsnRecord, ...]
    failures: tuple[str, ...]


class UsnJournalReader:
    """Parse allocated `$J` run bytes; malformed candidates never escape."""

    def parse_buffer(self, data: bytes, *, source_image: str,
                     physical_offset: int = 0, logical_j_offset: int | None = None) -> UsnParseResult:
        if not isinstance(data, bytes):
            raise ValueError("data must be bytes")
        records, failures, pos = [], [], 0
        while pos + 8 <= len(data):
            length = int.from_bytes(data[pos:pos + 4], "little")
            major = int.from_bytes(data[pos + 4:pos + 6], "little")
            minor = int.from_bytes(data[pos + 6:pos + 8], "little")
            if length == 0:
                pos += 8
                continue
            minimum = 60 if major == 2 else 76 if major == 3 else 0
            if (not minimum or minor != 0 or length < minimum or length > 1024 * 1024
                    or length % 8 or pos + length > len(data)):
                failures.append("usn_record_invalid_length_or_version")
                pos += 8
                continue
            if major == 2:
                file_ref = int.from_bytes(data[pos + 8:pos + 16], "little")
                parent_ref = int.from_bytes(data[pos + 16:pos + 24], "little")
                ts_off, reason_off, attr_off, nlen_off, noff_off = 32, 40, 52, 56, 58
            else:
                file_ref = int.from_bytes(data[pos + 8:pos + 24], "little")
                parent_ref = int.from_bytes(data[pos + 24:pos + 40], "little")
                ts_off, reason_off, attr_off, nlen_off, noff_off = 48, 56, 68, 72, 74
            name_len = int.from_bytes(data[pos + nlen_off:pos + nlen_off + 2], "little")
            name_off = int.from_bytes(data[pos + noff_off:pos + noff_off + 2], "little")
            if name_len == 0 or name_len % 2 or name_off < minimum or name_off % 2 or name_off + name_len > length:
                failures.append("usn_filename_bounds_invalid")
                pos += 8
                continue
            try:
                filename = data[pos + name_off:pos + name_off + name_len].decode("utf-16le")
                if (not file_ref or not parent_ref or
                        any(ord(ch) < 32 or ch in "\\/" for ch in filename)):
                    raise UnicodeError
                ticks = int.from_bytes(data[pos + ts_off:pos + ts_off + 8], "little", signed=True)
                if ticks <= 0:
                    raise ValueError
                timestamp = (WINDOWS_EPOCH + timedelta(microseconds=ticks // 10)).isoformat()
            except (UnicodeError, OverflowError, ValueError):
                failures.append("usn_record_encoding_or_timestamp_invalid")
                pos += 8
                continue
            records.append(UsnRecord(
                file_ref, parent_ref, timestamp,
                int.from_bytes(data[pos + reason_off:pos + reason_off + 4], "little"),
                int.from_bytes(data[pos + attr_off:pos + attr_off + 4], "little"),
                filename, major, minor, source_image, physical_offset + pos,
                None if logical_j_offset is None else logical_j_offset + pos,
            ))
            pos += length
        return UsnParseResult(tuple(records), tuple(failures))

    def parse_stream(self, chunks, *, source_image: str) -> UsnParseResult:
        """Parse ordered logical chunks while retaining incomplete record tails."""
        records: list[UsnRecord] = []
        failures: list[str] = []
        pending = bytearray()
        pending_start: int | None = None
        segments: list[tuple[int, int, int]] = []

        def physical_for(logical: int) -> int:
            for start, end, physical in segments:
                if start <= logical < end:
                    return physical + logical - start
            return 0

        def record_segments(start: int, end: int) -> tuple[dict[str, int], ...]:
            result = []
            for logical_start, logical_end, physical in segments:
                left, right = max(start, logical_start), min(end, logical_end)
                if left < right:
                    result.append({
                        "logical_start": left,
                        "physical_start": physical + left - logical_start,
                        "length": right - left,
                    })
            return tuple(result)

        def consume(final: bool, gap: bool = False) -> None:
            nonlocal pending, pending_start, segments
            if pending_start is None:
                return
            pos = 0
            while pos + 8 <= len(pending):
                length = int.from_bytes(pending[pos:pos + 4], "little")
                major = int.from_bytes(pending[pos + 4:pos + 6], "little")
                minor = int.from_bytes(pending[pos + 6:pos + 8], "little")
                if length == 0:
                    pos += 8
                    continue
                minimum = 60 if major == 2 else 76 if major == 3 else 0
                plausible = bool(minimum and minor == 0 and minimum <= length <= 1024 * 1024
                                 and length % 8 == 0)
                if plausible and pos + length > len(pending):
                    if not final:
                        break
                    failures.append("usn_record_truncated_at_logical_gap" if gap
                                    else "usn_record_truncated_at_stream_end")
                    pos = len(pending)
                    break
                if not plausible:
                    failures.append("usn_record_invalid_length_or_version")
                    pos += 8
                    continue
                logical = pending_start + pos
                parsed = self.parse_buffer(
                    bytes(pending[pos:pos + length]), source_image=source_image,
                    physical_offset=physical_for(logical), logical_j_offset=logical,
                )
                if parsed.records:
                    item = parsed.records[0]
                    records.append(replace(
                        item,
                        physical_segments=record_segments(logical, logical + length),
                    ))
                else:
                    failures.append(parsed.failures[0] if parsed.failures
                                    else "usn_record_rejected")
                pos += length
            if final and pos < len(pending) and any(pending[pos:]):
                failures.append("usn_record_truncated_at_logical_gap" if gap
                                else "usn_record_truncated_at_stream_end")
                pos = len(pending)
            if pos:
                pending = pending[pos:]
                pending_start += pos
                segments = [item for item in segments if item[1] > pending_start]
            if final:
                pending.clear()
                pending_start = None
                segments.clear()

        for chunk in chunks:
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
        return UsnParseResult(tuple(records), tuple(dict.fromkeys(failures)))
