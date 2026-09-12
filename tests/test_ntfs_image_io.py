from io import BytesIO
from pathlib import Path

import pytest

import bfrs.recovery.ntfs_bitcoin_artifacts as ntfs_module
from bfrs.recovery.ntfs_bitcoin_artifacts import (
    NTFSBitcoinArtifactLocator,
    _Image,
)
from tests.test_ntfs_bitcoin_artifacts import (
    data_resident,
    file_record,
    filename,
    image_with,
)


def _synthetic_image(tmp_path: Path) -> Path:
    path = tmp_path / "synthetic-ntfs.img"
    path.write_bytes(image_with({
        1: file_record(1, (filename("wallet.dat"), data_resident(b"test"))),
        2: file_record(2, (filename("bitcoin.conf"), data_resident(b"test"))),
        3: file_record(3, (filename("notes.txt"), data_resident(b"test"))),
    }))
    return path.resolve()


def _track_path_opens(monkeypatch, selected: Path):
    original_open = Path.open
    handles = []

    class TrackedHandle:
        def __init__(self, wrapped):
            self.wrapped = wrapped
            self.seek_count = 0
            self.read_count = 0

        @property
        def closed(self):
            return self.wrapped.closed

        def seek(self, *args, **kwargs):
            self.seek_count += 1
            return self.wrapped.seek(*args, **kwargs)

        def read(self, *args, **kwargs):
            self.read_count += 1
            return self.wrapped.read(*args, **kwargs)

        def close(self):
            return self.wrapped.close()

        def __enter__(self):
            self.wrapped.__enter__()
            return self

        def __exit__(self, *args):
            return self.wrapped.__exit__(*args)

    def tracked_open(path, *args, **kwargs):
        handle = original_open(path, *args, **kwargs)
        mode = args[0] if args else kwargs.get("mode", "r")
        if path.resolve() == selected and mode == "rb":
            tracked = TrackedHandle(handle)
            handles.append(tracked)
            return tracked
        return handle

    monkeypatch.setattr(Path, "open", tracked_open)
    return handles


def test_index_many_records_opens_source_once_and_closes_handle(
        tmp_path, monkeypatch):
    path = _synthetic_image(tmp_path)
    handles = _track_path_opens(monkeypatch, path)

    result = NTFSBitcoinArtifactLocator().index(path)

    assert result.mft_records_scanned > 1
    assert len(handles) == 1
    assert handles[0].read_count > 1
    assert handles[0].seek_count == handles[0].read_count
    assert handles[0].closed is True


def test_multiple_read_at_calls_reuse_context_handle(tmp_path, monkeypatch):
    path = _synthetic_image(tmp_path)
    expected = path.read_bytes()
    handles = _track_path_opens(monkeypatch, path)
    image = _Image(path)

    with image:
        assert image.read_at(0, 16) == expected[:16]
        assert image.read_at(512, 16) == expected[512:528]
        assert len(handles) == 1
        assert handles[0].seek_count == 2
        assert handles[0].read_count == 2
        assert handles[0].closed is False

    assert handles[0].closed is True


def test_read_at_outside_context_preserves_ephemeral_handle_contract(
        tmp_path, monkeypatch):
    path = _synthetic_image(tmp_path)
    handles = _track_path_opens(monkeypatch, path)
    image = _Image(path)

    image.read_at(0, 8)
    image.read_at(8, 8)

    assert len(handles) == 2
    assert all(handle.closed for handle in handles)


def test_index_exception_always_closes_handle(tmp_path, monkeypatch):
    path = _synthetic_image(tmp_path)
    handles = _track_path_opens(monkeypatch, path)
    locator = NTFSBitcoinArtifactLocator()
    monkeypatch.setattr(
        locator,
        "_discover",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            RuntimeError("synthetic index failure")),
    )

    with pytest.raises(RuntimeError, match="synthetic index failure"):
        locator.index(path)

    assert len(handles) == 1
    assert handles[0].closed is True


def test_read_at_bounds_eof_and_short_read_behavior_are_preserved():
    class FakeStat:
        st_size = 4

    class FakePath:
        def __init__(self):
            self.handles = []

        def stat(self):
            return FakeStat()

        def open(self, mode):
            assert mode == "rb"
            handle = BytesIO(b"ab")
            self.handles.append(handle)
            return handle

    path = FakePath()
    image = _Image(path)  # type: ignore[arg-type]
    assert image.read_at(4, 0) == b""
    with pytest.raises(ValueError, match="read_outside_image"):
        image.read_at(4, 1)
    with pytest.raises(OSError, match="short_image_read"):
        image.read_at(0, 4)
    assert all(handle.closed for handle in path.handles)


def test_consecutive_indexes_use_distinct_closed_handles(tmp_path, monkeypatch):
    path = _synthetic_image(tmp_path)
    handles = _track_path_opens(monkeypatch, path)
    locator = NTFSBitcoinArtifactLocator()

    first = locator.index(path)
    second = locator.index(path)

    assert first == second
    assert len(handles) == 2
    assert handles[0] is not handles[1]
    assert all(handle.closed for handle in handles)


def test_index_result_matches_legacy_per_read_open_model(tmp_path, monkeypatch):
    path = _synthetic_image(tmp_path)
    current_image = ntfs_module._Image
    original_open = Path.open
    legacy_opens = 0

    class LegacyImage:
        def __init__(self, source):
            self.path = source
            self.size = source.stat().st_size

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return None

        def read_at(self, offset, length):
            nonlocal legacy_opens
            if (offset < 0 or length < 0 or offset > self.size
                    or length > self.size - offset):
                raise ValueError("read_outside_image")
            legacy_opens += 1
            with original_open(self.path, "rb") as source:
                source.seek(offset)
                data = source.read(length)
            if len(data) != length:
                raise OSError("short_image_read")
            return data

    monkeypatch.setattr(ntfs_module, "_Image", LegacyImage)
    before = NTFSBitcoinArtifactLocator().index(path)
    assert legacy_opens > 1

    monkeypatch.setattr(ntfs_module, "_Image", current_image)
    handles = _track_path_opens(monkeypatch, path)
    after = NTFSBitcoinArtifactLocator().index(path)

    assert after == before
    assert len(handles) == 1
    assert handles[0].closed is True
