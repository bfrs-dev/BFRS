from pathlib import Path

import pytest

from bfrs.core.chunk_reader import DEFAULT_CHUNK_SIZE, Chunk, ChunkReader


def write_source(tmp_path: Path, data: bytes) -> Path:
    path = tmp_path / "source.bin"
    path.write_bytes(data)
    return path


def test_default_chunk_size_is_64_mib(tmp_path: Path) -> None:
    reader = ChunkReader(write_source(tmp_path, b""))

    assert reader.chunk_size == DEFAULT_CHUNK_SIZE == 64 * 1024 * 1024


def test_reads_file_smaller_than_chunk_size(tmp_path: Path) -> None:
    path = write_source(tmp_path, b"abc")

    assert list(ChunkReader(path, chunk_size=8).iter_chunks()) == [Chunk(0, b"abc")]


def test_reads_file_exactly_chunk_size(tmp_path: Path) -> None:
    path = write_source(tmp_path, b"abcdefgh")

    assert list(ChunkReader(path, chunk_size=8).iter_chunks()) == [
        Chunk(0, b"abcdefgh")
    ]


def test_reads_multiple_chunks_with_absolute_offsets(tmp_path: Path) -> None:
    path = write_source(tmp_path, b"abcdefghij")

    chunks = list(ChunkReader(path, chunk_size=4).iter_chunks())

    assert chunks == [Chunk(0, b"abcd"), Chunk(4, b"efgh"), Chunk(8, b"ij")]
    assert [chunk.end_offset for chunk in chunks] == [4, 8, 10]


def test_overlap_zero_produces_adjacent_chunks(tmp_path: Path) -> None:
    path = write_source(tmp_path, b"abcdefghij")

    chunks = list(ChunkReader(path, chunk_size=4, overlap=0).iter_chunks())

    assert [chunk.offset for chunk in chunks] == [0, 4, 8]


def test_positive_overlap_changes_step(tmp_path: Path) -> None:
    path = write_source(tmp_path, b"abcdefghijkl")

    chunks = list(ChunkReader(path, chunk_size=6, overlap=2).iter_chunks())

    assert chunks == [
        Chunk(0, b"abcdef"),
        Chunk(4, b"efghij"),
        Chunk(8, b"ijkl"),
    ]


def test_last_chunk_can_be_shorter(tmp_path: Path) -> None:
    path = write_source(tmp_path, b"abcdef")

    chunks = list(ChunkReader(path, chunk_size=4).iter_chunks())

    assert chunks[-1] == Chunk(4, b"ef")


def test_empty_file_has_size_zero_and_no_chunks(tmp_path: Path) -> None:
    reader = ChunkReader(write_source(tmp_path, b""), chunk_size=4)

    assert reader.file_size == 0
    assert list(reader.iter_chunks()) == []


def test_reads_only_requested_half_open_range(tmp_path: Path) -> None:
    path = write_source(tmp_path, b"0123456789")

    chunks = list(ChunkReader(path, chunk_size=3).iter_chunks(start=2, end=8))

    assert chunks == [Chunk(2, b"234"), Chunk(5, b"567")]


def test_equal_start_and_end_returns_no_chunks(tmp_path: Path) -> None:
    reader = ChunkReader(write_source(tmp_path, b"abcdef"), chunk_size=4)

    assert list(reader.iter_chunks(start=3, end=3)) == []


@pytest.mark.parametrize("chunk_size", [0, -1])
def test_rejects_invalid_chunk_size(tmp_path: Path, chunk_size: int) -> None:
    path = write_source(tmp_path, b"abc")

    with pytest.raises(ValueError):
        ChunkReader(path, chunk_size=chunk_size)


@pytest.mark.parametrize("overlap", [-1, 4, 5])
def test_rejects_invalid_overlap(tmp_path: Path, overlap: int) -> None:
    path = write_source(tmp_path, b"abc")

    with pytest.raises(ValueError):
        ChunkReader(path, chunk_size=4, overlap=overlap)


def test_rejects_negative_start(tmp_path: Path) -> None:
    reader = ChunkReader(write_source(tmp_path, b"abc"), chunk_size=2)

    with pytest.raises(ValueError):
        list(reader.iter_chunks(start=-1))


def test_rejects_end_beyond_file_size(tmp_path: Path) -> None:
    reader = ChunkReader(write_source(tmp_path, b"abc"), chunk_size=2)

    with pytest.raises(ValueError):
        list(reader.iter_chunks(end=4))


def test_rejects_start_greater_than_end(tmp_path: Path) -> None:
    reader = ChunkReader(write_source(tmp_path, b"abc"), chunk_size=2)

    with pytest.raises(ValueError):
        list(reader.iter_chunks(start=2, end=1))


def test_missing_file_raises_file_not_found(tmp_path: Path) -> None:
    reader = ChunkReader(tmp_path / "missing.bin")

    with pytest.raises(FileNotFoundError):
        _ = reader.file_size


def test_overlap_preserves_pattern_crossing_plain_chunk_boundary(tmp_path: Path) -> None:
    pattern = b"ABCDEFGH"
    path = write_source(tmp_path, b"xxxxxx" + pattern + b"yyyy")

    chunks = list(ChunkReader(path, chunk_size=10, overlap=6).iter_chunks())

    assert any(pattern in chunk.data for chunk in chunks)
