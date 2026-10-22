"""Select a file in Explorer without opening it or constructing shell commands."""
import ctypes
import os


def reveal_in_explorer(path):
    if os.name != 'nt':
        raise OSError('Zaznaczanie w Eksploratorze jest dostępne w Windows.')
    shell = ctypes.WinDLL('shell32', use_last_error=True)
    com = ctypes.WinDLL('ole32', use_last_error=True)
    _reveal(path, shell, com)


def _reveal(path, shell, com):
    pointer = ctypes.c_void_p
    hresult = ctypes.c_int32
    com.CoInitializeEx.argtypes = [pointer, ctypes.c_uint32]
    com.CoInitializeEx.restype = hresult
    com.CoUninitialize.argtypes = []
    com.CoUninitialize.restype = None
    com.CoTaskMemFree.argtypes = [pointer]
    com.CoTaskMemFree.restype = None
    shell.SHParseDisplayName.argtypes = [ctypes.c_wchar_p, pointer,
                                        ctypes.POINTER(pointer), ctypes.c_uint32, pointer]
    shell.SHParseDisplayName.restype = hresult
    shell.SHOpenFolderAndSelectItems.argtypes = [pointer, ctypes.c_uint32, pointer, ctypes.c_uint32]
    shell.SHOpenFolderAndSelectItems.restype = hresult
    initialized = com.CoInitializeEx(None, 2)
    # RPC_E_CHANGED_MODE means COM was already initialized in another mode.
    if initialized < 0 and initialized & 0xffffffff != 0x80010106:
        raise OSError('Nie udało się zainicjować Eksploratora Windows.')
    pidl = pointer()
    try:
        code = shell.SHParseDisplayName(str(path), None, ctypes.byref(pidl), 0, None)
        if code < 0 or not pidl.value:
            raise OSError('Nie udało się znaleźć pliku w Eksploratorze Windows.')
        code = shell.SHOpenFolderAndSelectItems(pidl, 0, None, 0)
        if code < 0:
            raise OSError('Nie udało się pokazać pliku w Eksploratorze Windows.')
    finally:
        if pidl.value:
            com.CoTaskMemFree(pidl)
        if initialized >= 0:
            com.CoUninitialize()
