from collections.abc import Iterator
from pathlib import Path

import pytest

from bfrs.core.chunk_reader import Chunk, ChunkReader
from bfrs.scanners.fast_scanner import FastScanner, Signature


def write_source(tmp_path: Path, data: bytes) -> Path:
    path = tmp_path / "source.bin"
    path.write_bytes(data)
    return path


def scan_data(
    tmp_path: Path,
    data: bytes,
    signatures: list[Signature],
    *,
    chunk_size: int = 64,
    overlap: int = 0,
):
    reader = ChunkReader(
        write_source(tmp_path, data), chunk_size=chunk_size, overlap=overlap
    )
    return list(FastScanner(signatures).scan(reader))


def test_one_signature_one_hit(tmp_path: Path) -> None:
    signature = Signature("alpha", b"ABC", "test")

    hits = scan_data(tmp_path, b"--ABC--", [signature])

    assert [(hit.start_offset, hit.end_offset, hit.hit_type) for hit in hits] == [
        (2, 5, "alpha")
    ]
    assert hits[0].evidence == {"category": "test"}
    assert hits[0].confidence == 0.0


def test_one_signature_many_hits(tmp_path: Path) -> None:
    hits = scan_data(
        tmp_path, b"ABC-ABC-ABC", [Signature("alpha", b"ABC", "test")]
    )

    assert [hit.start_offset for hit in hits] == [0, 4, 8]


def test_many_signatures_in_one_file(tmp_path: Path) -> None:
    signatures = [
        Signature("alpha", b"ABC", "first"),
        Signature("omega", b"XYZ", "second"),
    ]

    hits = scan_data(tmp_path, b"ABC--XYZ", signatures)

    assert [(hit.hit_type, hit.start_offset) for hit in hits] == [
        ("alpha", 0),
        ("omega", 5),
    ]


def test_no_hits(tmp_path: Path) -> None:
    hits = scan_data(tmp_path, b"abcdef", [Signature("other", b"XYZ", "test")])

    assert hits == []


def test_offsets_are_absolute_and_source_identifies_file(tmp_path: Path) -> None:
    path = write_source(tmp_path, b"012345ABC")
    reader = ChunkReader(path, chunk_size=5, overlap=2)

    hits = list(FastScanner([Signature("alpha", b"ABC", "test")]).scan(reader))

    assert hits[0].start_offset == 6
    assert hits[0].source == str(path.resolve())


def test_hit_at_offset_zero(tmp_path: Path) -> None:
    hits = scan_data(tmp_path, b"ABC---", [Signature("alpha", b"ABC", "test")])

    assert hits[0].start_offset == 0


def test_hit_at_end_of_file(tmp_path: Path) -> None:
    hits = scan_data(tmp_path, b"---ABC", [Signature("alpha", b"ABC", "test")])

    assert (hits[0].start_offset, hits[0].end_offset) == (3, 6)


def test_hit_crossing_chunk_boundary(tmp_path: Path) -> None:
    hits = scan_data(
        tmp_path,
        b"xxxxxxABCDEFGHyyyy",
        [Signature("crossing", b"ABCDEFGH", "test")],
        chunk_size=10,
        overlap=7,
    )

    assert [hit.start_offset for hit in hits] == [6]


def test_overlap_does_not_duplicate_hit(tmp_path: Path) -> None:
    hits = scan_data(
        tmp_path,
        b"--ABC---",
        [Signature("alpha", b"ABC", "test")],
        chunk_size=5,
        overlap=2,
    )

    assert [hit.start_offset for hit in hits] == [2]


def test_different_signatures_at_same_offset_are_preserved(tmp_path: Path) -> None:
    signatures = [
        Signature("short", b"ABC", "first"),
        Signature("long", b"ABCD", "second"),
    ]

    hits = scan_data(tmp_path, b"ABCD", signatures)

    assert [(hit.hit_type, hit.start_offset) for hit in hits] == [
        ("short", 0),
        ("long", 0),
    ]


def test_overlapping_occurrences_are_reported(tmp_path: Path) -> None:
    hits = scan_data(tmp_path, b"ABABA", [Signature("repeat", b"ABA", "test")])

    assert [hit.start_offset for hit in hits] == [0, 2]


def test_scan_respects_start_and_end(tmp_path: Path) -> None:
    path = write_source(tmp_path, b"ABC--ABC--ABC")
    reader = ChunkReader(path, chunk_size=4, overlap=2)

    hits = list(
        FastScanner([Signature("alpha", b"ABC", "test")]).scan(
            reader, start=5, end=10
        )
    )

    assert [hit.start_offset for hit in hits] == [5]


@pytest.mark.parametrize(
    ("name", "pattern", "category"),
    [("", b"ABC", "test"), ("alpha", b"", "test"), ("alpha", b"ABC", "")],
)
def test_signature_rejects_empty_fields(
    name: str, pattern: bytes, category: str
) -> None:
    with pytest.raises(ValueError):
        Signature(name, pattern, category)


def test_empty_signature_collection_is_rejected() -> None:
    with pytest.raises(ValueError):
        FastScanner([])


def test_duplicate_signature_definition_is_rejected() -> None:
    with pytest.raises(ValueError):
        FastScanner(
            [
                Signature("alpha", b"ABC", "first"),
                Signature("alpha", b"ABC", "second"),
            ]
        )


def test_insufficient_overlap_is_rejected_for_multichunk_scan(tmp_path: Path) -> None:
    path = write_source(tmp_path, b"0123456789ABC")
    reader = ChunkReader(path, chunk_size=8, overlap=2)
    scanner = FastScanner([Signature("long", b"ABCDEFGH", "test")])

    with pytest.raises(ValueError, match="overlap must be at least 7"):
        list(scanner.scan(reader))


def test_overlap_is_not_required_for_single_chunk_scan(tmp_path: Path) -> None:
    path = write_source(tmp_path, b"ABCDEFGH")
    reader = ChunkReader(path, chunk_size=8, overlap=0)
    scanner = FastScanner([Signature("whole", b"ABCDEFGH", "test")])

    assert len(list(scanner.scan(reader))) == 1


def test_many_signatures_use_one_chunk_iteration(tmp_path: Path) -> None:
    class CountingReader(ChunkReader):
        calls = 0

        def iter_chunks(
            self, start: int = 0, end: int | None = None
        ) -> Iterator[Chunk]:
            self.calls += 1
            yield from super().iter_chunks(start=start, end=end)

    path = write_source(tmp_path, b"ABC--XYZ")
    reader = CountingReader(path, chunk_size=16)
    scanner = FastScanner(
        [Signature("alpha", b"ABC", "first"), Signature("omega", b"XYZ", "second")]
    )

    assert len(list(scanner.scan(reader))) == 2
    assert reader.calls == 1
