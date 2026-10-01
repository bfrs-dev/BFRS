import importlib.util
from pathlib import Path
import struct

import pytest


_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "pe_machine.py"
_SPEC = importlib.util.spec_from_file_location("bfrs_pe_machine", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)


def make_pe(path: Path, machine: int) -> Path:
    payload = bytearray(512)
    payload[0:2] = b"MZ"
    pe_offset = 0x80
    payload[0x3C:0x40] = struct.pack("<I", pe_offset)
    payload[pe_offset:pe_offset + 4] = b"PE\0\0"
    payload[pe_offset + 4:pe_offset + 6] = struct.pack("<H", machine)
    path.write_bytes(payload)
    return path


@pytest.mark.parametrize(
    ("machine", "expected"),
    [
        (0x8664, "x64"),
        (0xAA64, "arm64"),
    ],
)
def test_pe_machine_detects_supported_windows_architectures(
    tmp_path, machine, expected
):
    executable = make_pe(tmp_path / "BFRS.exe", machine)

    assert _MODULE.pe_machine(executable) == expected


def test_pe_machine_rejects_non_pe_file(tmp_path):
    executable = tmp_path / "not-pe.exe"
    executable.write_bytes(b"not a PE")

    with pytest.raises(ValueError, match="MZ"):
        _MODULE.pe_machine(executable)


def test_pe_machine_rejects_unknown_machine(tmp_path):
    executable = make_pe(tmp_path / "unknown.exe", 0x014C)

    with pytest.raises(ValueError, match="unsupported PE machine"):
        _MODULE.pe_machine(executable)
