"""Presentation-neutral loading and filtering of public BFRS JSON reports."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from bfrs.reporting.finding_state import normalize_finding


class ResultServiceError(ValueError):
    """A report cannot be safely presented by the result browser."""


@dataclass(frozen=True, slots=True)
class ResultSummary:
    """Safe counts used by the result browser."""

    displayed_findings: int
    accepted: int
    review: int
    rejected: int
    crypto_valid: int


@dataclass(frozen=True, slots=True)
class FindingView:
    target: str
    artifact_kind: str
    discovery_state: str
    structural_state: str
    crypto_state: str
    recovery_relevance: str
    validation_status: str
    structural_status: str
    confidence: float | None
    start_offset: int | None
    end_offset: int | None
    file_path: str | None
    relative_path: str | None
    reason_codes: tuple[str, ...]
    correlated_evidence: tuple[str, ...]
    recommended_recovery_action: str | None
    safe_metadata: Mapping[str, Any]

    @property
    def review_priority(self) -> int:
        """Presentation-only triage rank; lower values are shown first."""
        if self.crypto_state == "VALID":
            return 0
        if (
            self.discovery_state == "ACCEPTED"
            and self.recovery_relevance != "CONTEXT_REVIEW"
        ):
            return 1
        if (
            self.discovery_state == "CANDIDATE"
            or (
                self.discovery_state == "ACCEPTED"
                and self.recovery_relevance == "CONTEXT_REVIEW"
            )
        ):
            return 2
        if self.discovery_state == "REJECTED":
            return 4
        return 3

    @property
    def review_priority_label(self) -> str:
        return (
            "CRYPTO_VALID",
            "ACCEPTED",
            "REVIEW",
            "OTHER",
            "REJECTED",
        )[self.review_priority]

    @property
    def location_kind(self) -> str:
        return "file_offset" if self.file_path else "physical_offset"

    @property
    def display_location(self) -> str:
        if self.file_path:
            if self.start_offset is None:
                return self.file_path
            return f"{self.file_path} @ {self.start_offset}"
        if self.start_offset is None:
            return ""
        if self.end_offset is None:
            return str(self.start_offset)
        return f"{self.start_offset}..{self.end_offset}"


@dataclass(frozen=True, slots=True)
class ResultReport:
    path: Path
    schema_version: int | None
    application_name: str | None
    application_version: str | None
    source_type: str
    source: str
    status: str | None
    findings: tuple[FindingView, ...]
    finding_summary: Mapping[str, Any]

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def targets(self) -> tuple[str, ...]:
        return tuple(sorted({item.target for item in self.findings if item.target}))


class ResultService:
    """Load current public reports without depending on Qt."""

    def load(self, path: str | Path) -> ResultReport:
        report_path = Path(path)
        try:
            payload = json.loads(report_path.read_text(encoding="utf-8-sig"))
        except OSError as error:
            raise ResultServiceError(f"unable to read report: {error}") from error
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ResultServiceError("report is not valid UTF-8 JSON") from error

        if not isinstance(payload, dict):
            raise ResultServiceError("report root must be a JSON object")

        raw_findings = payload.get("target_findings", ())
        if not isinstance(raw_findings, list):
            raise ResultServiceError("report target_findings must be a list")

        findings = tuple(self._finding(row) for row in raw_findings)

        application = payload.get("application")
        if not isinstance(application, dict):
            application = {}
        summary = payload.get("finding_summary")
        if not isinstance(summary, dict):
            summary = {}

        source_type = str(payload.get("source_type") or "UNKNOWN")
        source = str(
            payload.get("source")
            or payload.get("source_root")
            or ""
        )

        schema = payload.get("report_schema_version")
        schema_version = schema if isinstance(schema, int) else None
        status = payload.get("status")
        status_text = str(status) if isinstance(status, str) else None

        return ResultReport(
            path=report_path,
            schema_version=schema_version,
            application_name=(
                str(application["name"]) if "name" in application else None
            ),
            application_version=(
                str(application["version"]) if "version" in application else None
            ),
            source_type=source_type,
            source=source,
            status=status_text,
            findings=findings,
            finding_summary=summary,
        )

    def summary(self, report: ResultReport) -> ResultSummary:
        """Return report-wide safe counts, preferring canonical report summary."""
        computed = self._computed_summary(report.findings)
        raw = report.finding_summary
        return ResultSummary(
            displayed_findings=report.finding_count,
            accepted=self._summary_int(
                raw, "accepted_candidates", computed.accepted
            ),
            review=self._summary_int(
                raw, "review_candidates", computed.review
            ),
            rejected=self._summary_int(raw, "rejected", computed.rejected),
            crypto_valid=self._summary_int(
                raw, "crypto_valid_occurrences", computed.crypto_valid
            ),
        )

    def filter(
        self,
        report: ResultReport,
        *,
        targets: Iterable[str] | None = None,
        discovery_states: Iterable[str] | None = None,
        crypto_states: Iterable[str] | None = None,
        profile: str | None = None,
        search: str = "",
    ) -> tuple[FindingView, ...]:
        target_filter = frozenset(targets or ())
        discovery_filter = frozenset(
            value.upper() for value in (discovery_states or ())
        )
        crypto_filter = frozenset(value.upper() for value in (crypto_states or ()))
        needle = search.strip().casefold()
        profile_name = (profile or "").strip().casefold()
        if profile_name not in {"", "accepted", "review", "rejected", "crypto-valid"}:
            raise ValueError(f"unknown result filter profile: {profile}")

        result = []
        for item in report.findings:
            if target_filter and item.target not in target_filter:
                continue
            if discovery_filter and item.discovery_state not in discovery_filter:
                continue
            if crypto_filter and item.crypto_state not in crypto_filter:
                continue
            if profile_name and not self._matches_profile(item, profile_name):
                continue
            if needle and needle not in self._search_text(item):
                continue
            result.append(item)
        return tuple(result)

    @staticmethod
    def prioritize(findings: Iterable[FindingView]) -> tuple[FindingView, ...]:
        """Order findings for human review without changing their state."""
        return tuple(sorted(
            findings,
            key=lambda item: (
                item.review_priority,
                -(item.confidence if item.confidence is not None else -1.0),
                item.file_path or "",
                item.start_offset if item.start_offset is not None else -1,
                item.target,
                item.artifact_kind,
            ),
        ))

    @staticmethod
    def _summary_int(
        summary: Mapping[str, Any], key: str, fallback: int
    ) -> int:
        value = summary.get(key)
        return value if isinstance(value, int) and value >= 0 else fallback

    @staticmethod
    def _computed_summary(findings: Iterable[FindingView]) -> ResultSummary:
        displayed = accepted = review = rejected = crypto_valid = 0
        for item in findings:
            displayed += 1
            is_accepted = item.discovery_state == "ACCEPTED"
            is_rejected = item.discovery_state == "REJECTED"
            accepted += is_accepted
            rejected += is_rejected
            review += (
                item.discovery_state == "CANDIDATE"
                or (
                    is_accepted
                    and item.recovery_relevance == "CONTEXT_REVIEW"
                )
            )
            crypto_valid += item.crypto_state == "VALID"
        return ResultSummary(
            displayed_findings=displayed,
            accepted=accepted,
            review=review,
            rejected=rejected,
            crypto_valid=crypto_valid,
        )

    @staticmethod
    def _matches_profile(item: FindingView, profile: str) -> bool:
        if profile == "accepted":
            return item.discovery_state == "ACCEPTED"
        if profile == "review":
            return (
                item.discovery_state == "CANDIDATE"
                or (
                    item.discovery_state == "ACCEPTED"
                    and item.recovery_relevance == "CONTEXT_REVIEW"
                )
            )
        if profile == "rejected":
            return item.discovery_state == "REJECTED"
        if profile == "crypto-valid":
            return item.crypto_state == "VALID"
        return True

    @staticmethod
    def _search_text(item: FindingView) -> str:
        values = (
            item.target,
            item.artifact_kind,
            item.validation_status,
            item.structural_status,
            item.file_path or "",
            item.relative_path or "",
            " ".join(item.reason_codes),
            item.recommended_recovery_action or "",
        )
        return " ".join(values).casefold()

    @staticmethod
    def _finding(row: object) -> FindingView:
        if not isinstance(row, dict):
            raise ResultServiceError("target finding must be a JSON object")

        normalized = row.get("normalized_state")
        if isinstance(normalized, dict):
            required = {
                "discovery_state",
                "structural_state",
                "crypto_state",
                "recovery_relevance",
            }
            if not required.issubset(normalized):
                raise ResultServiceError("finding normalized_state is incomplete")
            state = {name: str(normalized[name]).upper() for name in required}
        else:
            try:
                public = normalize_finding(row)
            except (TypeError, ValueError) as error:
                raise ResultServiceError(
                    f"unable to normalize report finding: {error}"
                ) from error
            state = public.safe_dict()

        start = row.get("file_offset_start", row.get("physical_start"))
        end = row.get("file_offset_end", row.get("physical_end"))
        start_offset = start if isinstance(start, int) else None
        end_offset = end if isinstance(end, int) else None

        confidence = row.get("confidence")
        confidence_value = (
            float(confidence) if isinstance(confidence, (int, float)) else None
        )
        metadata = row.get("safe_metadata")
        if not isinstance(metadata, dict):
            metadata = {}

        return FindingView(
            target=str(row.get("target") or ""),
            artifact_kind=str(row.get("artifact_kind") or ""),
            discovery_state=str(state["discovery_state"]).upper(),
            structural_state=str(state["structural_state"]).upper(),
            crypto_state=str(state["crypto_state"]).upper(),
            recovery_relevance=str(state["recovery_relevance"]).upper(),
            validation_status=str(row.get("validation_status") or ""),
            structural_status=str(row.get("structural_status") or ""),
            confidence=confidence_value,
            start_offset=start_offset,
            end_offset=end_offset,
            file_path=(
                str(row["file_path"]) if isinstance(row.get("file_path"), str)
                else None
            ),
            relative_path=(
                str(row["relative_path"])
                if isinstance(row.get("relative_path"), str)
                else None
            ),
            reason_codes=tuple(
                str(value) for value in row.get("reason_codes", ())
            ),
            correlated_evidence=tuple(
                str(value) for value in row.get("correlated_evidence", ())
            ),
            recommended_recovery_action=(
                str(row["recommended_recovery_action"])
                if isinstance(row.get("recommended_recovery_action"), str)
                else None
            ),
            safe_metadata=dict(metadata),
        )
