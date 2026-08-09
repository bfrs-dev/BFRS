"""Aggregate encrypted-wallet evidence by logical Berkeley database."""

from collections.abc import Iterable
from dataclasses import dataclass
import ntpath

from bfrs.core.models import ValidationStatus
from bfrs.validators.berkeley_page_locator import BerkeleyAnchor
from bfrs.validators.encrypted_wallet_evidence import (
    BerkeleyRecordPageContext,
    EncryptedWalletEvidence,
    EncryptedWalletEvidenceCorrelator,
)


@dataclass(frozen=True, slots=True)
class EncryptedWalletEvidenceGroup:
    source: str
    anchor: BerkeleyAnchor
    context_count: int
    page_count: int
    evidence: EncryptedWalletEvidence


@dataclass(frozen=True, slots=True)
class EncryptedWalletAggregation:
    groups: tuple[EncryptedWalletEvidenceGroup, ...]
    database_count: int
    structural_database_count: int
    fragment_database_count: int
    rejected_database_count: int
    context_count: int


_DatabaseIdentity = tuple[str, BerkeleyAnchor]
_ContextIdentity = tuple[str, BerkeleyAnchor, int]


class EncryptedWalletEvidenceAggregator:
    """Group page contexts by database and delegate evidence correlation."""

    def aggregate(
        self,
        contexts: Iterable[BerkeleyRecordPageContext],
    ) -> EncryptedWalletAggregation:
        unique_contexts: dict[_ContextIdentity, BerkeleyRecordPageContext] = {}

        for context in contexts:
            normalized = self._normalize_context(context)
            identity = self._context_identity(normalized)
            existing = unique_contexts.get(identity)
            if existing is None:
                unique_contexts[identity] = normalized
            elif existing.extraction != normalized.extraction:
                raise ValueError(
                    "conflicting duplicate context for source, anchor, "
                    "and page_number"
                )

        contexts_by_database: dict[
            _DatabaseIdentity, list[BerkeleyRecordPageContext]
        ] = {}
        for context in unique_contexts.values():
            identity = self._database_identity(context)
            contexts_by_database.setdefault(identity, []).append(context)

        groups: list[EncryptedWalletEvidenceGroup] = []
        for identity in sorted(contexts_by_database, key=self._database_sort_key):
            source, anchor = identity
            group_contexts = tuple(
                sorted(
                    contexts_by_database[identity],
                    key=lambda item: item.extraction.page_number,
                )
            )
            evidence = EncryptedWalletEvidenceCorrelator().correlate(
                group_contexts
            )
            groups.append(
                EncryptedWalletEvidenceGroup(
                    source=source,
                    anchor=anchor,
                    context_count=len(group_contexts),
                    page_count=len(
                        {
                            context.extraction.page_number
                            for context in group_contexts
                        }
                    ),
                    evidence=evidence,
                )
            )

        group_tuple = tuple(groups)
        return EncryptedWalletAggregation(
            groups=group_tuple,
            database_count=len(group_tuple),
            structural_database_count=self._status_count(
                group_tuple, ValidationStatus.STRUCTURAL
            ),
            fragment_database_count=self._status_count(
                group_tuple, ValidationStatus.FRAGMENT
            ),
            rejected_database_count=self._status_count(
                group_tuple, ValidationStatus.REJECTED
            ),
            context_count=len(unique_contexts),
        )

    @staticmethod
    def _normalize_context(
        context: BerkeleyRecordPageContext,
    ) -> BerkeleyRecordPageContext:
        normalized_source = ntpath.normcase(ntpath.normpath(context.source))
        if normalized_source == context.source:
            return context
        return BerkeleyRecordPageContext(
            source=normalized_source,
            anchor=context.anchor,
            extraction=context.extraction,
        )

    @staticmethod
    def _database_identity(
        context: BerkeleyRecordPageContext,
    ) -> _DatabaseIdentity:
        return (context.source, context.anchor)

    @staticmethod
    def _context_identity(
        context: BerkeleyRecordPageContext,
    ) -> _ContextIdentity:
        return (
            context.source,
            context.anchor,
            context.extraction.page_number,
        )

    @staticmethod
    def _database_sort_key(
        identity: _DatabaseIdentity,
    ) -> tuple[str, int, int, int, int, str]:
        source, anchor = identity
        return (
            source,
            anchor.database_base_offset,
            anchor.metadata_absolute_offset,
            anchor.metadata_page_number,
            anchor.page_size,
            anchor.byte_order,
        )

    @staticmethod
    def _status_count(
        groups: tuple[EncryptedWalletEvidenceGroup, ...],
        status: ValidationStatus,
    ) -> int:
        return sum(group.evidence.status is status for group in groups)
