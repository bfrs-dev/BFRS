"""Build spatial hotspots from raw scanner hits without source I/O."""

from collections.abc import Iterable

from bfrs.core.models import Hotspot, RawHit
from bfrs.validators.evidence_strength import classify_raw_hit


DEFAULT_CLUSTER_GAP = 2 * 1024 * 1024
DEFAULT_PADDING = 1 * 1024 * 1024


class HotspotBuilder:
    def __init__(
        self,
        cluster_gap: int = DEFAULT_CLUSTER_GAP,
        padding: int = DEFAULT_PADDING,
    ) -> None:
        if cluster_gap < 0:
            raise ValueError("cluster_gap must not be negative")
        if padding < 0:
            raise ValueError("padding must not be negative")

        self.cluster_gap = cluster_gap
        self.padding = padding

    def build(self, hits: Iterable[RawHit], source_size: int) -> list[Hotspot]:
        if source_size < 0:
            raise ValueError("source_size must not be negative")

        unique_hits: list[RawHit] = []
        for hit in hits:
            if not 0 <= hit.start_offset <= hit.end_offset <= source_size:
                raise ValueError("hit range must be within source bounds")
            if hit not in unique_hits:
                unique_hits.append(hit)

        if not unique_hits:
            return []

        sources = {hit.source for hit in unique_hits}
        if len(sources) != 1:
            raise ValueError("all hits must come from the same source")

        ordered_hits = sorted(
            unique_hits,
            key=lambda hit: (hit.start_offset, hit.end_offset, hit.hit_type),
        )
        clusters: list[list[RawHit]] = [[ordered_hits[0]]]

        for hit in ordered_hits[1:]:
            if hit.start_offset - clusters[-1][-1].start_offset <= self.cluster_gap:
                clusters[-1].append(hit)
            else:
                clusters.append([hit])

        source = ordered_hits[0].source
        return [self._make_hotspot(cluster, source, source_size) for cluster in clusters]

    def _make_hotspot(
        self,
        cluster: list[RawHit],
        source: str,
        source_size: int,
    ) -> Hotspot:
        start_offset = max(0, cluster[0].start_offset - self.padding)
        end_offset = min(
            source_size,
            max(hit.end_offset for hit in cluster) + self.padding,
        )

        signals = tuple(classify_raw_hit(hit) for hit in cluster)
        return Hotspot(
            start_offset=start_offset,
            end_offset=end_offset,
            score=0.0,
            source=source,
            evidence={
                "hit_count": len(cluster),
                "hit_types": tuple(hit.hit_type for hit in cluster),
                "hit_offsets": tuple(hit.start_offset for hit in cluster),
                "hit_targets": tuple(hit.target for hit in cluster),
                "hit_artifact_kinds": tuple(hit.artifact_kind for hit in cluster),
                "hit_structural_statuses": tuple(
                    hit.structural_status for hit in cluster
                ),
                "hit_validation_statuses": tuple(
                    hit.validation_status for hit in cluster
                ),
                "hit_evidence_strengths": tuple(
                    signal.strength.name for signal in signals
                ),
            },
        )
