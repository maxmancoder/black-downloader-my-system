#!/usr/bin/env python3
"""Black Server My System - Requirements checker.

Checks if all requirements are met before launching the main server.
If anything is missing, opens a visible CMD window with large
"DOWNLOADING REQUIREMENTS" text, installs everything, then launches
the main program.

Requirements:
  - Python 3.9+
  - cloudflared.exe in bin/

This file is intentionally self-contained (stdlib only) so it can
run before any pip packages are installed.
"""

import os
import platform
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
BIN_DIR = PROJECT_ROOT / "bin"
CLOUDFLARED_EXE = BIN_DIR / "cloudflared.exe"
CLOUDFLARED_URL = (
    "https://github.com/cloudflare/cloudflared/releases/latest/download/"
    "cloudflared-windows-amd64.exe"
)


def find_python() -> str | None:
    """Return a usable Python command, or None."""
    for cmd in ("python", "py -3"):
        try:
            r = subprocess.run(
                cmd.split() + ["--version"],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode == 0 and "Python 3" in r.stdout:
                return cmd
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def python_version_ok() -> bool:
    """Check that the current Python is 3.9+."""
    v = sys.version_info
    return v.major == 3 and v.minor >= 9


def cloudflared_ok() -> bool:
    """Check that cloudflared.exe exists and is executable."""
    if not CLOUDFLARED_EXE.exists():
        return False
    if CLOUDFLARED_EXE.stat().st_size < 1_000_000:
        return False
    return True


def download_cloudflared() -> bool:
    """Download cloudflared.exe using urllib (no pip needed)."""
    import urllib.request
    import tempfile

    BIN_DIR.mkdir(parents=True, exist_ok=True)
    tmp = BIN_DIR / "cloudflared.exe.tmp"
    try:
        print(f"    Downloading cloudflared.exe from GitHub ...")
        urllib.request.urlretrieve(CLOUDFLARED_URL, tmp)
        # Verify it's a real executable (> 10 MB)
        if tmp.stat().st_size < 10_000_000:
            print("    [ERROR] Downloaded file is too small - might be corrupt.")
            tmp.unlink(missing_ok=True)
            return False
        tmp.replace(CLOUDFLARED_EXE)
        print("    [OK] cloudflared.exe downloaded successfully.")
        return True
    except Exception as exc:
        print(f"    [ERROR] Download failed: {exc}")
        tmp.unlink(missing_ok=True)
        return False


def all_requirements_met() -> tuple[bool, list[str]]:
    """Check all requirements. Returns (ok, list of missing items)."""
    missing = []

    if not python_version_ok():
        v = sys.version_info
        missing.append(f"Python 3.9+ (found {v.major}.{v.minor}.{v.micro})")

    if not cloudflared_ok():
        missing.append("cloudflared.exe (not found in bin/)")

    return (len(missing) == 0, missing)


def open_install_window() -> None:
    """Open a visible CMD window that installs requirements, then launches server."""
    # Build the batch script content
    bat_lines = [
        "@echo off",
        "title Black Server My System - Installing Requirements",
        "color 0F",
        "cls",
        "",
        "echo.",
        "echo  ============================================================",
        "echo.",
        "echo       DOWNLOADING REQUIREMENTS",
        "echo.",
        "echo       Black Server My System needs the following:",
        "echo.",
        "echo       - Python 3.9 or newer",
        "echo       - cloudflared.exe (Cloudflare tunnel client)",
        "echo.",
        "echo  ============================================================",
        "echo.",
        "echo.",
    ]

    # Python check
    bat_lines += [
        "echo  [1/2] Checking Python ...",
        "python --version >nul 2>&1",
        "if errorlevel 1 (",
        "    py -3 --version >nul 2>&1",
        "    if errorlevel 1 (",
        "        echo.",
        "        echo  [ERROR] Python is not installed!",
        "        echo.",
        "        echo  Please install Python 3 from:",
        "        echo    https://www.python.org/downloads/",
        "        echo.",
        "        echo  During setup, tick \"Add python.exe to PATH\".",
        "        echo.",
        "        echo  After installing, run start_server.bat again.",
        "        echo.",
        "        pause",
        "        exit /b 1",
        "    ) else (",
        '        echo  [OK] Python detected: py -3',
        "        set \"PY_CMD=py -3\"",
        "    )",
        ") else (",
        '    echo  [OK] Python detected: python',
        '    set "PY_CMD=python"',
        ")",
        "echo.",
        "",
        "echo  [2/2] Checking cloudflared.exe ...",
        'if exist "bin\\cloudflared.exe" (',
        '    echo  [OK] cloudflared.exe found.',
        ") else (",
        '    echo  [..] cloudflared.exe not found. Downloading ...',
        "    echo.",
        "    echo  ============================================================",
        "    echo    Downloading from GitHub (this may take a minute) ...",
        "    echo  ============================================================",
        "    echo.",
        "",
        "    %PY_CMD% -c \"import urllib.request; urllib.request.urlretrieve('https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe', 'bin/cloudflared.exe.tmp')\"",
        '    if exist "bin\\cloudflared.exe.tmp" (',
        '        move /y "bin\\cloudflared.exe.tmp" "bin\\cloudflared.exe" >nul 2>&1',
        '        echo  [OK] cloudflared.exe downloaded.',
        "    ) else (",
        "        echo.",
        "        echo  [ERROR] Could not download cloudflared.exe.",
        "        echo  Please download it manually from:",
        "        echo    https://github.com/cloudflare/cloudflared/releases/latest",
        "        echo  Save the Windows 64-bit file as: bin\\cloudflared.exe",
        "        echo.",
        "        pause",
        "        exit /b 1",
        "    )",
        ")",
        "echo.",
        "",
        "echo  ============================================================",
        "echo    All requirements are installed!",
        "echo    Launching Black Server My System ...",
        "echo  ============================================================",
        "echo.",
        "timeout /t 2 >nul",
        "",
        # Launch the server
        'start "" "%~dp0start_server.bat"',
    ]

    # Write temp bat file
    tmp_bat = PROJECT_ROOT / "_install_requirements.bat"
    tmp_bat.write_text("\r\n".join(bat_lines), encoding="utf-8")

    # Open it in a new visible window
    subprocess.Popen(
        ["cmd", "/c", str(tmp_bat)],
        creationflags=subprocess.CREATE_NEW_WINDOW,
    )


def main() -> int:
    ok, missing = all_requirements_met()
    if ok:
        return 0  # all good, just run server.py
    else:
        print("[..] Missing requirements:")
        for item in missing:
            print(f"       - {item}")
        print("    Opening install window ...")
        open_install_window()
        return 2  # signal to start_server.bat: install window opened


if __name__ == "__main__":
    sys.exit(main())
