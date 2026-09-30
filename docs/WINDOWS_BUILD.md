# Windows standalone builds

BFRS GUI is packaged as a native Windows **onedir** application. The ZIP
contains the whole `BFRS` directory; run `BFRS.exe` inside it.

## Supported build targets

Build each architecture with a Python interpreter of the same architecture:

- **Windows x64**: use native x64 Python. Artifact: `BFRS-<version>-win-x64.zip`.
- **Windows ARM64**: use native ARM64 Python. Artifact: `BFRS-<version>-win-arm64.zip`.

The build script refuses unsupported Python platforms and verifies the PE
machine type of the generated `BFRS.exe`.

## Build ZIP

From the repository root in PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_windows.ps1
```

The script:

1. detects the Python platform,
2. installs `.[dev,gui,package]`,
3. runs the full pytest suite,
4. builds the PySide6 GUI with PyInstaller,
5. verifies the executable architecture,
6. writes `BUILDINFO.txt`,
7. creates the ZIP,
8. writes a SHA-256 sidecar file.

Artifacts are written to `artifacts\`.

To skip tests during an iterative packaging debug run:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_windows.ps1 -SkipTests
```

For normal/release builds, do not use `-SkipTests`.

## Select an explicit Python interpreter

If `py` resolves to the wrong architecture, pass a native interpreter:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_windows.ps1 \
  -PythonExe "C:\Path\To\python.exe"
```

You can check the interpreter platform first:

```powershell
py -c "import sysconfig; print(sysconfig.get_platform())"
```

Expected values are `win-amd64` or `win-arm64`.

## Optional installer

Install Inno Setup (version 7 recommended), then run:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_windows.ps1 -Installer
```

This also creates:

- `BFRS-<version>-win-x64-setup.exe`, or
- `BFRS-<version>-win-arm64-setup.exe`

with a matching `.sha256` file.

The x64 installer is restricted to x64 Windows when the separate native ARM64
package is used. The ARM64 installer is restricted to Arm64 Windows.

## Notes

- Building does not change the scan/recovery engine.
- The packaged GUI still stores user preferences in the normal per-user BFRS
  settings location.
- Reports, checkpoints, recovery output, and source images are not bundled into
  the application.
- Visual Studio is not required to run the finished package.
