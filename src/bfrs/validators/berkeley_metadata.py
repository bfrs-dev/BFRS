"""Conservative validation of Berkeley DB B-tree metadata pages."""

from dataclasses import asdict, dataclass

from bfrs.core.models import ValidationResult, ValidationStatus
from bfrs.validators.base import ValidationContext


# Oracle DBMETA uses this B-tree magic at bytes 12..15.
BTREE_MAGIC = 0x00053162
# V1 intentionally supports only Bitcoin-compatible BDB B-tree version 9.
BTREE_VERSION = 9
# P_BTREEMETA is the on-disk page type stored at byte 25.
BTREE_METADATA_PAGE_TYPE = 9
# DBMETA/BTMETA occupies at least one 512-byte metadata page.
MIN_METADATA_SIZE = 512
# DB->set_pagesize permits powers of two from 512 through 64 KiB.
MIN_PAGE_SIZE = 512
MAX_PAGE_SIZE = 65536
# DBMETA_ALLFLAGS: checksum, partition range/callback, and sliced flags.
METADATA_FLAG_MASK = 0x0F
# Bitcoin Core's legacy BDB reader supports only the BTM_SUBDB flag.
BITCOIN_BTREE_FLAGS = 0x20

MAGIC_OFFSET = 12
MIN_PREFIX_SIZE = 28
STRUCTURAL_FIELDS_SIZE = 92


@dataclass(frozen=True, slots=True)
class BerkeleyMetaInfo:
    local_offset: int
    absolute_offset: int
    byte_order: str
    magic: int
    version: int | None
    page_size: int | None
    page_type: int | None
    page_number: int | None
    metadata_flags: int | None
    free_page: int | None = None
    last_page_number: int | None = None
    root_page: int | None = None
    btree_flags: int | None = None


@dataclass(frozen=True, slots=True)
class _Candidate:
    status: ValidationStatus
    info: BerkeleyMetaInfo
    reasons: tuple[str, ...]
    end_offset: int


class BerkeleyMetadataValidator:
    name = "berkeley_metadata"

    def validate(self, context: ValidationContext) -> ValidationResult:
        candidates = self._find_candidates(context)
        if not candidates:
            return ValidationResult(
                start_offset=context.start_offset,
                end_offset=context.end_offset,
                validator=self.name,
                status=ValidationStatus.REJECTED,
                source=context.source,
                evidence={
                    "candidate_count": 0,
                    "structural_candidates": 0,
                    "fragment_candidates": 0,
                    "rejected_candidates": 0,
                    "reasons": ("metadata_magic_not_found",),
                },
            )

        priority = {
            ValidationStatus.STRUCTURAL: 0,
            ValidationStatus.FRAGMENT: 1,
            ValidationStatus.REJECTED: 2,
        }
        selected = min(
            candidates,
            key=lambda item: (priority[item.status], item.info.absolute_offset),
        )
        counts = {
            status: sum(item.status is status for item in candidates)
            for status in ValidationStatus
        }
        evidence = asdict(selected.info)
        evidence.update(
            {
                "magic_valid": True,
                "base_metadata": selected.info.page_number == 0,
                "last_page_consistent_with_root": (
                    selected.info.last_page_number is not None
                    and selected.info.root_page is not None
                    and selected.info.last_page_number >= selected.info.root_page
                ),
                "free_page_within_last_page": (
                    selected.info.free_page is not None
                    and selected.info.last_page_number is not None
                    and (
                        selected.info.free_page == 0
                        or selected.info.free_page <= selected.info.last_page_number
                    )
                ),
                "candidate_count": len(candidates),
                "structural_candidates": counts[ValidationStatus.STRUCTURAL],
                "fragment_candidates": counts[ValidationStatus.FRAGMENT],
                "rejected_candidates": counts[ValidationStatus.REJECTED],
                "reasons": selected.reasons,
            }
        )
        return ValidationResult(
            start_offset=selected.info.absolute_offset,
            end_offset=selected.end_offset,
            validator=self.name,
            status=selected.status,
            source=context.source,
            evidence=evidence,
        )

    def _find_candidates(self, context: ValidationContext) -> list[_Candidate]:
        patterns = (
            (BTREE_MAGIC.to_bytes(4, "little"), "little"),
            (BTREE_MAGIC.to_bytes(4, "big"), "big"),
        )
        found: list[tuple[int, str]] = []
        for pattern, byte_order in patterns:
            position = context.data.find(pattern)
            while position != -1:
                local_offset = position - MAGIC_OFFSET
                if local_offset >= 0:
                    found.append((local_offset, byte_order))
                position = context.data.find(pattern, position + 1)

        return [
            self._inspect_candidate(context, local_offset, byte_order)
            for local_offset, byte_order in sorted(set(found))
        ]

    def _inspect_candidate(
        self,
        context: ValidationContext,
        local_offset: int,
        byte_order: str,
    ) -> _Candidate:
        available = len(context.data) - local_offset
        prefix = context.data[local_offset:]
        absolute_offset = context.start_offset + local_offset

        if available < MIN_PREFIX_SIZE:
            info = BerkeleyMetaInfo(
                local_offset=local_offset,
                absolute_offset=absolute_offset,
                byte_order=byte_order,
                magic=BTREE_MAGIC,
                version=None,
                page_size=None,
                page_type=None,
                page_number=None,
                metadata_flags=None,
                free_page=None,
            )
            return _Candidate(
                ValidationStatus.REJECTED,
                info,
                ("metadata_prefix_too_short",),
                context.end_offset,
            )

        decode = lambda start, end: int.from_bytes(prefix[start:end], byte_order)
        page_number = decode(8, 12)
        magic = decode(12, 16)
        version = decode(16, 20)
        page_size = decode(20, 24)
        page_type = prefix[25]
        metadata_flags = prefix[26]
        reasons: list[str] = []

        if magic != BTREE_MAGIC:
            reasons.append("metadata_magic_invalid")
        if version != BTREE_VERSION:
            reasons.append("metadata_version_unsupported")
        if not self._valid_page_size(page_size):
            reasons.append("metadata_page_size_invalid")
        if page_type != BTREE_METADATA_PAGE_TYPE:
            reasons.append("metadata_page_type_invalid")
        if metadata_flags & ~METADATA_FLAG_MASK:
            reasons.append("metadata_flags_invalid")

        last_page_number = None
        free_page = None
        root_page = None
        btree_flags = None
        if available >= STRUCTURAL_FIELDS_SIZE:
            free_page = decode(28, 32)
            last_page_number = decode(32, 36)
            btree_flags = decode(48, 52)
            root_page = decode(88, 92)
            if root_page == 0:
                reasons.append("metadata_root_page_invalid")
            if btree_flags != BITCOIN_BTREE_FLAGS:
                reasons.append("metadata_btree_flags_invalid")

        info = BerkeleyMetaInfo(
            local_offset=local_offset,
            absolute_offset=absolute_offset,
            byte_order=byte_order,
            magic=magic,
            version=version,
            page_size=page_size,
            page_type=page_type,
            page_number=page_number,
            metadata_flags=metadata_flags,
            free_page=free_page,
            last_page_number=last_page_number,
            root_page=root_page,
            btree_flags=btree_flags,
        )

        if reasons:
            status = ValidationStatus.REJECTED
        elif available < STRUCTURAL_FIELDS_SIZE:
            status = ValidationStatus.FRAGMENT
            reasons.append("metadata_structural_fields_truncated")
        elif available < page_size:
            status = ValidationStatus.FRAGMENT
            reasons.append("metadata_page_truncated")
        else:
            status = ValidationStatus.STRUCTURAL

        candidate_end = absolute_offset + min(available, max(page_size, 0))
        return _Candidate(status, info, tuple(reasons), candidate_end)

    @staticmethod
    def _valid_page_size(page_size: int) -> bool:
        return (
            MIN_PAGE_SIZE <= page_size <= MAX_PAGE_SIZE
            and page_size & (page_size - 1) == 0
        )
