param(
    [string]$PythonExe = "py",
    [switch]$SkipTests,
    [switch]$Installer
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = Split-Path -Parent $PSScriptRoot
Push-Location $Root
try {
    Write-Host "== BFRS Windows build =="

    $platform = (& $PythonExe -c "import sysconfig; print(sysconfig.get_platform())").Trim()
    switch ($platform) {
        "win-amd64" {
            $artifactArch = "win-x64"
            $expectedPe = "x64"
        }
        "win-arm64" {
            $artifactArch = "win-arm64"
            $expectedPe = "arm64"
        }
        default {
            throw "Unsupported Python platform '$platform'. Use native Windows x64 or ARM64 Python."
        }
    }

    $version = (& $PythonExe -c "import sys; sys.path.insert(0, r'src'); from bfrs.version import VERSION; print(VERSION)").Trim()
    if (-not $version) {
        throw "Unable to read BFRS version."
    }

    Write-Host "Python platform: $platform"
    Write-Host "BFRS version:    $version"
    Write-Host "Artifact arch:   $artifactArch"

    Write-Host "Installing build dependencies..."
    & $PythonExe -m pip install -e ".[dev,gui,package]"
    if ($LASTEXITCODE -ne 0) {
        throw "pip install failed."
    }

    if (-not $SkipTests) {
        Write-Host "Running test suite..."
        & $PythonExe -m pytest -q
        if ($LASTEXITCODE -ne 0) {
            throw "Tests failed; build aborted."
        }
    }

    $buildRoot = Join-Path $Root "build\windows-$artifactArch"
    $distRoot = Join-Path $Root "dist\windows-$artifactArch"
    $artifactRoot = Join-Path $Root "artifacts"

    Remove-Item $buildRoot -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $distRoot -Recurse -Force -ErrorAction SilentlyContinue

    if (Test-Path $distRoot) {
        throw (
            "Unable to clean '$distRoot'. Close every running BFRS window " +
            "and any Explorer window opened inside that folder, then rerun the build."
        )
    }

    New-Item -ItemType Directory -Path $buildRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $distRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null

    Write-Host "Building standalone GUI with PyInstaller..."
    $pyInstallerArgs = @(
        "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--workpath", $buildRoot,
        "--distpath", $distRoot,
        "packaging\bfrs_gui.spec"
    )
    & $PythonExe @pyInstallerArgs
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller build failed."
    }

    $appDir = Join-Path $distRoot "BFRS"
    $exe = Join-Path $appDir "BFRS.exe"
    if (-not (Test-Path $exe -PathType Leaf)) {
        throw "Expected executable not found: $exe"
    }

    Write-Host "Verifying executable architecture..."
    & $PythonExe "scripts\pe_machine.py" $exe --expect $expectedPe
    if ($LASTEXITCODE -ne 0) {
        throw "PE architecture verification failed."
    }

    $pyVersion = (& $PythonExe -c "import platform; print(platform.python_version())").Trim()
    $qtVersion = (& $PythonExe -c "import PySide6; print(PySide6.__version__)").Trim()
    $installerVersion = (& $PythonExe -c "import PyInstaller; print(PyInstaller.__version__)").Trim()

    $buildInfo = @(
        "BFRS $version",
        "artifact_arch=$artifactArch",
        "python_platform=$platform",
        "python_version=$pyVersion",
        "pyside6_version=$qtVersion",
        "pyinstaller_version=$installerVersion"
    )
    Set-Content -Path (Join-Path $appDir "BUILDINFO.txt") -Value $buildInfo -Encoding utf8

    $zipName = "BFRS-$version-$artifactArch.zip"
    $zipPath = Join-Path $artifactRoot $zipName
    Remove-Item $zipPath -Force -ErrorAction SilentlyContinue

    Write-Host "Creating ZIP artifact..."
    Compress-Archive -Path $appDir -DestinationPath $zipPath -CompressionLevel Optimal

    $zipHash = (Get-FileHash -Algorithm SHA256 $zipPath).Hash.ToLowerInvariant()
    $hashPath = "$zipPath.sha256"
    Set-Content -Path $hashPath -Value "$zipHash  $zipName" -Encoding ascii

    Write-Host "ZIP:    $zipPath"
    Write-Host "SHA256: $zipHash"

    if ($Installer) {
        $isccCandidates = @(
            "$env:ProgramFiles\Inno Setup 7\ISCC.exe",
            "${env:ProgramFiles(x86)}\Inno Setup 7\ISCC.exe",
            "$env:LOCALAPPDATA\Programs\Inno Setup 7\ISCC.exe"
        ) | Where-Object { $_ -and (Test-Path $_ -PathType Leaf) }

        if (-not $isccCandidates) {
            throw "Inno Setup compiler (ISCC.exe) not found. Install Inno Setup 7 or rerun without -Installer."
        }

        $iscc = $isccCandidates[0]
        Write-Host "Building installer with: $iscc"
        $isccArgs = @(
            "/DMyAppVersion=$version",
            "/DBuildArch=$artifactArch",
            "/DSourceDir=$appDir",
            "/DOutputDir=$artifactRoot",
            "packaging\bfrs.iss"
        )
        & $iscc @isccArgs
        if ($LASTEXITCODE -ne 0) {
            throw "Inno Setup build failed."
        }

        $setupPath = Join-Path $artifactRoot "BFRS-$version-$artifactArch-setup.exe"
        if (-not (Test-Path $setupPath -PathType Leaf)) {
            throw "Expected installer not found: $setupPath"
        }

        $setupHash = (Get-FileHash -Algorithm SHA256 $setupPath).Hash.ToLowerInvariant()
        Set-Content -Path "$setupPath.sha256" -Value "$setupHash  $(Split-Path -Leaf $setupPath)" -Encoding ascii
        Write-Host "SETUP:  $setupPath"
        Write-Host "SHA256: $setupHash"
    }

    Write-Host "Build complete."
}
finally {
    Pop-Location
}
