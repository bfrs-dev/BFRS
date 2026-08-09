from copy import deepcopy

import pytest

from bfrs.core.models import Hotspot
from bfrs.validators.candidate_policy import CandidateDecision, CandidatePolicy


def make_hotspot(
    hit_types: tuple[str, ...] = ("TYPE_A", "TYPE_B"),
    hit_offsets: tuple[int, ...] | None = None,
    *,
    score: float = 0.0,
) -> Hotspot:
    offsets = hit_offsets or tuple(range(0, len(hit_types) * 10, 10))
    return Hotspot(
        start_offset=0,
        end_offset=1000,
        score=score,
        source="source.img",
        evidence={
            "hit_count": len(hit_types),
            "hit_types": hit_types,
            "hit_offsets": offsets,
        },
    )


def test_default_policy_accepts_two_distinct_types() -> None:
    decision = CandidatePolicy().evaluate(make_hotspot())

    assert decision == CandidateDecision(True, (), 2, ("TYPE_A", "TYPE_B"), 10)


def test_single_hit_is_rejected() -> None:
    decision = CandidatePolicy().evaluate(make_hotspot(("TYPE_A",), (5,)))

    assert decision.accepted is False
    assert decision.reasons == ("insufficient_hits", "insufficient_distinct_types")


def test_many_hits_of_one_type_are_rejected() -> None:
    decision = CandidatePolicy().evaluate(
        make_hotspot(("NOISE",) * 5, (0, 1, 2, 3, 4))
    )

    assert decision.reasons == ("insufficient_distinct_types",)


def test_min_hits_rule() -> None:
    decision = CandidatePolicy(min_hits=3, min_distinct_types=1).evaluate(
        make_hotspot(("A", "B"), (0, 1))
    )

    assert decision.reasons == ("insufficient_hits",)


def test_min_distinct_types_rule() -> None:
    decision = CandidatePolicy(min_hits=1, min_distinct_types=3).evaluate(
        make_hotspot(("A", "B", "B"), (0, 1, 2))
    )

    assert decision.reasons == ("insufficient_distinct_types",)


def test_empty_required_groups_add_no_rule() -> None:
    assert CandidatePolicy(required_groups=()).evaluate(make_hotspot()).accepted


def test_one_required_group_is_satisfied() -> None:
    policy = CandidatePolicy(required_groups=(frozenset({"TYPE_A", "ALT"}),))

    assert policy.evaluate(make_hotspot()).accepted


def test_one_required_group_can_be_missing() -> None:
    policy = CandidatePolicy(required_groups=(frozenset({"OTHER"}),))

    assert policy.evaluate(make_hotspot()).reasons == ("missing_required_group",)


def test_all_required_groups_must_be_satisfied() -> None:
    policy = CandidatePolicy(
        required_groups=(frozenset({"TYPE_A"}), frozenset({"TYPE_B"}))
    )

    assert policy.evaluate(make_hotspot()).accepted


def test_one_missing_required_group_rejects() -> None:
    policy = CandidatePolicy(
        required_groups=(frozenset({"TYPE_A"}), frozenset({"OTHER"}))
    )

    assert policy.evaluate(make_hotspot()).reasons == ("missing_required_group",)


def test_alternatives_within_group_are_supported() -> None:
    policy = CandidatePolicy(required_groups=(frozenset({"ALT", "TYPE_B"}),))

    assert policy.evaluate(make_hotspot()).accepted


def test_unlimited_signal_span_accepts_distant_hits() -> None:
    decision = CandidatePolicy(max_signal_span=None).evaluate(
        make_hotspot(hit_offsets=(0, 10_000_000))
    )

    assert decision.accepted
    assert decision.signal_span == 10_000_000


def test_signal_span_at_limit_is_accepted() -> None:
    decision = CandidatePolicy(max_signal_span=100).evaluate(
        make_hotspot(hit_offsets=(10, 110))
    )

    assert decision.accepted


def test_signal_span_over_limit_is_rejected() -> None:
    decision = CandidatePolicy(max_signal_span=100).evaluate(
        make_hotspot(hit_offsets=(10, 111))
    )

    assert decision.reasons == ("signal_span_too_large",)


def test_all_violated_rules_are_returned_in_stable_order() -> None:
    policy = CandidatePolicy(
        min_hits=3,
        min_distinct_types=2,
        required_groups=(frozenset({"REQUIRED"}),),
        max_signal_span=5,
    )

    decision = policy.evaluate(make_hotspot(("NOISE", "NOISE"), (0, 10)))

    assert decision.reasons == (
        "insufficient_hits",
        "insufficient_distinct_types",
        "missing_required_group",
        "signal_span_too_large",
    )


def test_distinct_types_are_sorted() -> None:
    decision = CandidatePolicy(min_hits=1).evaluate(
        make_hotspot(("ZETA", "ALPHA", "BETA"), (0, 1, 2))
    )

    assert decision.distinct_types == ("ALPHA", "BETA", "ZETA")


def test_evaluate_does_not_mutate_hotspot() -> None:
    hotspot = make_hotspot()
    original_evidence = deepcopy(hotspot.evidence)

    CandidatePolicy().evaluate(hotspot)

    assert hotspot.evidence == original_evidence


def test_hotspot_score_does_not_affect_decision() -> None:
    policy = CandidatePolicy()

    assert policy.evaluate(make_hotspot(score=0.0)) == policy.evaluate(
        make_hotspot(score=999.0)
    )


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"min_hits": 0}, "min_hits"),
        ({"min_distinct_types": 0}, "min_distinct_types"),
        ({"max_signal_span": -1}, "max_signal_span"),
    ],
)
def test_invalid_numeric_policy_parameters_are_rejected(
    kwargs: dict[str, int], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        CandidatePolicy(**kwargs)


def test_empty_required_group_is_rejected() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        CandidatePolicy(required_groups=(frozenset(),))


def test_empty_name_in_required_group_is_rejected() -> None:
    with pytest.raises(ValueError, match="non-empty strings"):
        CandidatePolicy(required_groups=(frozenset({""}),))


def test_string_is_not_accepted_as_required_group() -> None:
    with pytest.raises(ValueError, match="signal type names"):
        CandidatePolicy(required_groups=("TYPE_A",))


@pytest.mark.parametrize(
    "evidence",
    [
        {},
        {"hit_count": "2", "hit_types": ("A", "B"), "hit_offsets": (0, 1)},
        {"hit_count": 1, "hit_types": "A", "hit_offsets": (0,)},
        {"hit_count": 1, "hit_types": ("",), "hit_offsets": (0,)},
        {"hit_count": 1, "hit_types": ("A",), "hit_offsets": "0"},
    ],
)
def test_malformed_evidence_is_rejected(evidence: dict[str, object]) -> None:
    hotspot = make_hotspot()
    hotspot.evidence.clear()
    hotspot.evidence.update(evidence)

    with pytest.raises(ValueError):
        CandidatePolicy().evaluate(hotspot)


def test_non_mapping_evidence_is_rejected() -> None:
    hotspot = make_hotspot()
    object.__setattr__(hotspot, "evidence", None)

    with pytest.raises(ValueError, match="must be a mapping"):
        CandidatePolicy().evaluate(hotspot)


def test_inconsistent_hit_count_is_rejected() -> None:
    hotspot = make_hotspot()
    hotspot.evidence["hit_count"] = 3

    with pytest.raises(ValueError, match="hit_count does not match"):
        CandidatePolicy().evaluate(hotspot)


def test_inconsistent_evidence_lengths_are_rejected() -> None:
    hotspot = make_hotspot()
    hotspot.evidence["hit_offsets"] = (0,)

    with pytest.raises(ValueError, match="counts must match"):
        CandidatePolicy().evaluate(hotspot)


def test_negative_hit_offset_is_rejected() -> None:
    hotspot = make_hotspot(hit_offsets=(-1, 5))

    with pytest.raises(ValueError, match="non-negative integers"):
        CandidatePolicy().evaluate(hotspot)


def test_one_hundred_noise_hits_do_not_become_candidate() -> None:
    decision = CandidatePolicy().evaluate(
        make_hotspot(("NOISE",) * 100, tuple(range(100)))
    )

    assert decision.accepted is False
    assert decision.reasons == ("insufficient_distinct_types",)


def test_independent_signal_types_are_accepted() -> None:
    policy = CandidatePolicy(min_hits=3, min_distinct_types=3)
    hotspot = make_hotspot(
        ("STRUCTURE_A", "RECORD_B", "METADATA_C"), (100, 120, 140)
    )

    assert policy.evaluate(hotspot).accepted


@pytest.mark.parametrize(
    ("types", "accepted"),
    [
        (("STRUCTURE_A", "RECORD_B"), True),
        (("STRUCTURE_A", "STRUCTURE_B"), False),
    ],
)
def test_required_structure_and_record_groups(
    types: tuple[str, ...], accepted: bool
) -> None:
    policy = CandidatePolicy(
        required_groups=(
            frozenset({"STRUCTURE_A", "STRUCTURE_B"}),
            frozenset({"RECORD_A", "RECORD_B"}),
        )
    )

    assert policy.evaluate(make_hotspot(types, (0, 1))).accepted is accepted
