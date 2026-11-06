"""Create synthetic sparse fixtures without allocating their logical size."""
from contextlib import contextmanager
import os

import pytest


def _mark_windows_sparse(stream):
    import ctypes
    from ctypes import wintypes
    import msvcrt

    device_io_control = ctypes.WinDLL('kernel32', use_last_error=True).DeviceIoControl
    device_io_control.argtypes = (wintypes.HANDLE, wintypes.DWORD,
                                 wintypes.LPVOID, wintypes.DWORD,
                                 wintypes.LPVOID, wintypes.DWORD,
                                 ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID)
    device_io_control.restype = wintypes.BOOL
    returned = wintypes.DWORD()
    if not device_io_control(msvcrt.get_osfhandle(stream.fileno()), 0x900C4,
                             None, 0, None, 0, ctypes.byref(returned), None):
        raise ctypes.WinError(ctypes.get_last_error())


@contextmanager
def sparse_file(path):
    """Mark a new Windows file sparse before any seek/write; no dense fallback.

    FSCTL_SET_SPARSE is necessary on Windows even for writes beyond EOF.
    Only fixture setup is skipped if the filesystem cannot enable sparseness;
    opening, writing and scanner errors still fail the test.
    """
    with path.open('wb') as stream:
        if os.name == 'nt':
            try:
                _mark_windows_sparse(stream)
            except OSError as error:
                pytest.skip(f'Filesystem cannot create a sparse fixture: {error}')
        yield stream
