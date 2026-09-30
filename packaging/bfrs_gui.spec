# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files


ROOT = Path.cwd()
DATAS = collect_data_files("bfrs.recovery.mnemonic", include_py_files=False)
DATAS += collect_data_files("bfrs.gui", include_py_files=False, includes=["assets/*.png"])

analysis = Analysis(
    [str(ROOT / "src" / "bfrs" / "gui" / "app.py")],
    pathex=[str(ROOT / "src")],
    binaries=[],
    datas=DATAS,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(analysis.pure)

exe = EXE(
    pyz,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="BFRS",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    icon=str(ROOT / "packaging" / "bfrs.ico"),
)

collection = COLLECT(
    exe,
    analysis.binaries,
    analysis.datas,
    strip=False,
    upx=False,
    name="BFRS",
)
