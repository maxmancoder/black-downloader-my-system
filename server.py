#!/usr/bin/env python3
"""Public File Download Server for Windows.

Serves the contents of ``./downloads`` over HTTP, bound to ``127.0.0.1`` only,
and publishes it to the internet through a Cloudflare Quick Tunnel
(``cloudflared``).

Architecture::

    Internet
       |
       v
    Cloudflare Quick Tunnel   (cloudflared)
       |
       v
    127.0.0.1:<port>          (this file server)
       |
       v
    ./downloads/

The whole program relies on the Python standard library only.  It works as a
small orchestrator: it starts the local file server in a background thread,
spawns ``cloudflared`` as a child process, captures its output, extracts the
public ``https://*.trycloudflare.com`` URL and prints a clear banner.

The design keeps the tunneling layer isolated (:class:`CloudflareTunnel`) so
that switching to a *named / managed* Cloudflare Tunnel later (for a custom
domain such as ``files.example.com``) only requires changing the command that
is launched, not the rest of the project.
"""

from __future__ import annotations

import argparse
import functools
import html
import io
import json
import logging
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import webbrowser
import zipfile
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional, Tuple

# ---------------------------------------------------------------------------
# Paths and constants (everything is relative to the project directory, so the
# project can live anywhere and be launched from any working directory).
# ---------------------------------------------------------------------------

PROJECT_ROOT: Path = Path(__file__).resolve().parent
DOWNLOADS_DIR: Path = PROJECT_ROOT / "downloads"
LOGS_DIR: Path = PROJECT_ROOT / "logs"
BIN_DIR: Path = PROJECT_ROOT / "bin"
CLOUDFLARED_EXE: Path = BIN_DIR / "cloudflared.exe"
LOCK_FILE: Path = LOGS_DIR / "server.lock"

HOST: str = "127.0.0.1"          # bind to localhost only, never 0.0.0.0
DEFAULT_PORT: int = 8080
PORT_SCAN_LIMIT: int = 20        # how many ports to try after the default one
CHUNK_SIZE: int = 64 * 1024      # streaming chunk size (keeps RAM usage flat)

# Official, always-latest Cloudflare release asset for 64-bit Windows.
CLOUDFLARED_DOWNLOAD_URL: str = (
    "https://github.com/cloudflare/cloudflared/releases/latest/download/"
    "cloudflared-windows-amd64.exe"
)

# Matches the Quick Tunnel URL printed by cloudflared, e.g.
#   https://random-name-here.trycloudflare.com
#
# Requires at least one hyphen in the sub-domain.  This deliberately excludes
# infrastructure hosts such as "api.trycloudflare.com" or "edge.trycloudflare.com"
# that cloudflared also logs, so only real per-tunnel URLs are captured.
TUNNEL_URL_RE: re.Pattern[str] = re.compile(
    r"https://[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)+\.trycloudflare\.com"
)

# Lines that mean the quick tunnel could not be created at all.
TUNNEL_FATAL_RE: re.Pattern[str] = re.compile(
    r"failed to (?:request|create).*tunnel|Failed to create quick tunnel|"
    r"fatal|INTERNAL ERROR",
    re.IGNORECASE,
)

# --- SSH fallback tunnel providers -------------------------------------------
# Used automatically when Cloudflare is blocked (e.g. national filters).
# Each provider only needs an outbound SSH connection; the URL regex and
# command differ per provider.  Providers are tried in order until one works.
SSH_STARTUP_TIMEOUT: float = 45.0
SSH_REACH_TRIES: int = 6
SSH_REACH_DELAY: float = 4.0


def _ssh_cmd(dest: str, port: int, remote_port: str = "80") -> list:
    """Build a standard SSH reverse-tunnel command."""
    return [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ServerAliveInterval=5",
        "-o", "ServerAliveCountMax=3",
        "-o", "ExitOnForwardFailure=yes",
        "-R", f"{remote_port}:127.0.0.1:{port}",
        dest,
        "-p", "22",
    ]


# Ordered list of SSH tunnel providers (tried first → last).
SSH_PROVIDERS: list[dict] = [
    {
        "name": "localhost.run",
        "log_name": "localhostrun.log",
        "url_re": re.compile(r"https://[a-zA-Z0-9-]+\.lhr\.life"),
        "cmd": lambda port: _ssh_cmd("nokey@localhost.run", port),
    },
    {
        "name": "serveo.net",
        "log_name": "serveo.log",
        "url_re": re.compile(r"https://[a-zA-Z0-9.-]+\.serveousercontent\.com"),
        "cmd": lambda port: _ssh_cmd("serveo.net", port),
    },
]

# ANSI escape sequences that cloudflared uses to colour its log output.
ANSI_RE: re.Pattern[str] = re.compile(r"\x1b\[[0-9;]*m")

logger = logging.getLogger("public-download-server")


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging(verbose: bool = False) -> None:
    """Configure console + rotating file logging (never logs secrets)."""
    LOGS_DIR.mkdir(parents=True, exist_ok=True)

    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"
    )

    file_handler = RotatingFileHandler(
        LOGS_DIR / "server.log",
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setFormatter(fmt)
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(fmt)
    console_handler.setLevel(logging.DEBUG if verbose else logging.WARNING)
    logger.addHandler(console_handler)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def human_size(num_bytes: int) -> str:
    """Return a human readable file size such as ``4.2 GB``."""
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def is_process_running(pid: int) -> bool:
    """Best-effort check whether *pid* is still alive (Windows friendly)."""
    if pid <= 0:
        return False
    try:
        result = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return str(pid) in (result.stdout or "")


def acquire_single_instance_lock() -> Tuple[bool, Optional[int]]:
    """Prevent two servers from running at once.

    Returns ``(True, own_pid)`` when the lock was acquired, otherwise
    ``(False, existing_pid)``.
    """
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    if LOCK_FILE.exists():
        try:
            existing = int(LOCK_FILE.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            existing = 0
        if existing and is_process_running(existing):
            return False, existing
    try:
        LOCK_FILE.write_text(str(os.getpid()), encoding="utf-8")
    except OSError:
        logger.warning("Could not write lock file %s", LOCK_FILE)
    return True, os.getpid()


def release_single_instance_lock() -> None:
    """Remove the lock file on a clean shutdown."""
    try:
        if LOCK_FILE.exists():
            LOCK_FILE.unlink()
    except OSError:
        logger.warning("Could not remove lock file %s", LOCK_FILE)


def find_free_port(preferred: int = DEFAULT_PORT) -> int:
    """Return the first free TCP port on localhost.

    Tries ``preferred`` first, then the following ports, and finally lets the
    OS pick an ephemeral port.  This keeps the server and cloudflared in sync
    because the chosen port is returned to the caller.
    """
    candidates = list(range(preferred, preferred + PORT_SCAN_LIMIT))
    candidates.append(0)  # let the OS choose a free port

    for port in candidates:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind((HOST, port))
            except OSError:
                continue
            return probe.getsockname()[1]
    raise OSError("No free TCP port could be found on localhost.")


def wait_for_port(host: str, port: int, timeout: float = 10.0) -> bool:
    """Poll a TCP endpoint until it accepts connections or *timeout* expires."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(0.5)
            if probe.connect_ex((host, port)) == 0:
                return True
        time.sleep(0.15)
    return False


def check_internet(timeout: float = 4.0) -> bool:
    """Quick reachability check so we can print a helpful warning.

    This is only a heuristic (many networks block ICMP/DNS of well-known
    hosts yet still allow the Cloudflare edge), so a ``False`` result never
    blocks the tunnel - it only produces a warning.
    """
    for target in (
        ("1.1.1.1", 443),
        ("8.8.8.8", 53),
        ("www.cloudflare.com", 443),
    ):
        try:
            with socket.create_connection(target, timeout=timeout):
                return True
        except OSError:
            continue
    return False


def copy_to_clipboard(text: str) -> bool:
    """Put *text* on the Windows clipboard (best effort, never fatal)."""
    try:
        subprocess.run(
            "clip",
            input=text,
            text=True,
            shell=True,
            check=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return True
    except Exception:  # noqa: BLE001 - clipboard failures must not crash us
        pass
    try:
        subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Set-Clipboard -Value $input",
            ],
            input=text,
            text=True,
            check=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return True
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# cloudflared management
# ---------------------------------------------------------------------------

def print_log_tail(log_path: Path, max_lines: int = 12) -> None:
    """Print the tail of a tunnel log to help the user self-diagnose."""
    try:
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return
    for line in lines[-max_lines:]:
        if line.strip():
            print("        " + line.strip()[:200])


def verify_cloudflared(exe: Path) -> Optional[str]:
    """Run ``cloudflared --version`` and return the version string."""
    try:
        result = subprocess.run(
            [str(exe), "--version"],
            capture_output=True,
            text=True,
            timeout=20,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.error("cloudflared could not be executed: %s", exc)
        return None
    output = (result.stdout or result.stderr or "").strip()
    if result.returncode != 0:
        logger.error("cloudflared --version failed: %s", output)
        return None
    return output.splitlines()[0] if output else "cloudflared"


def download_cloudflared() -> Optional[str]:
    """Download cloudflared from the official Cloudflare/GitHub release.

    The file is written to a temporary path first and only moved into place
    after the download looks valid, so a failed download never leaves a broken
    ``bin/cloudflared.exe`` behind.
    """
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    tmp_path = CLOUDFLARED_EXE.with_suffix(".exe.download")

    print("[..] Downloading cloudflared from Cloudflare/GitHub ...")
    request = urllib.request.Request(
        CLOUDFLARED_DOWNLOAD_URL,
        headers={"User-Agent": "public-download-server/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response, open(
            tmp_path, "wb"
        ) as out_file:
            shutil.copyfileobj(response, out_file, length=CHUNK_SIZE)
    except Exception as exc:  # noqa: BLE001 - report any network error clearly
        logger.error("cloudflared download failed: %s", exc)
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        return None

    # Sanity check: a Windows executable starts with the "MZ" magic bytes.
    try:
        with open(tmp_path, "rb") as probe:
            if probe.read(2) != b"MZ":
                raise ValueError("downloaded file is not a valid Windows executable")
        os.replace(tmp_path, CLOUDFLARED_EXE)
    except (OSError, ValueError) as exc:
        logger.error("cloudflared download is invalid: %s", exc)
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        return None

    print(f"[OK] Downloaded to {CLOUDFLARED_EXE}")
    return verify_cloudflared(CLOUDFLARED_EXE)


def ensure_cloudflared(force_download: bool = False) -> Optional[Path]:
    """Make sure ``bin/cloudflared.exe`` exists and runs.

    Returns the path on success or ``None`` on failure.
    """
    if CLOUDFLARED_EXE.exists() and not force_download:
        version = verify_cloudflared(CLOUDFLARED_EXE)
        if version:
            print(f"[OK] cloudflared found: {version}")
            return CLOUDFLARED_EXE
        logger.warning("Existing cloudflared binary is not usable; re-downloading.")

    # No hard internet pre-check here: connectivity probes can give false
    # negatives, and the download below reports a clear error if it fails.
    version = download_cloudflared()
    if not version:
        print("[ERROR] Could not download cloudflared automatically.")
        print("        Download it manually from:")
        print("        https://github.com/cloudflare/cloudflared/releases/latest")
        print(f"        and save it as: {CLOUDFLARED_EXE}")
        return None

    print(f"[OK] cloudflared ready: {version}")
    return CLOUDFLARED_EXE


class CloudflareTunnel:
    """Runs ``cloudflared tunnel --url http://127.0.0.1:<port>``.

    The tunneling layer is intentionally isolated: supporting a named tunnel
    with a custom domain later means passing different arguments here, without
    touching the file server.
    """

    def __init__(self, exe: Path, port: int, log_path: Path, protocol: str = "auto") -> None:
        self.exe = exe
        self.port = port
        self.log_path = log_path
        self.protocol = protocol
        self.process: Optional[subprocess.Popen] = None
        self.public_url: Optional[str] = None
        self.registered = False       # data plane connected to the edge
        self.fatal_error: Optional[str] = None
        self._url_event = threading.Event()
        self._registered_event = threading.Event()
        self._fatal_event = threading.Event()
        self._reader_thread: Optional[threading.Thread] = None

    def _command(self) -> list:
        # Quick Tunnel.  ``--no-autoupdate`` keeps behaviour deterministic.
        cmd = [
            str(self.exe),
            "tunnel",
            "--url",
            f"http://{HOST}:{self.port}",
            "--no-autoupdate",
        ]
        if self.protocol and self.protocol != "auto":
            cmd += ["--protocol", self.protocol]
        return cmd

    def start(self) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        logger.info("Starting tunnel: %s", " ".join(self._command()))
        self.process = subprocess.Popen(
            self._command(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        self._reader_thread = threading.Thread(
            target=self._read_output, name="cloudflared-reader", daemon=True
        )
        self._reader_thread.start()

    def _read_output(self) -> None:
        """Tee cloudflared output to a log file and watch for the public URL."""
        assert self.process is not None and self.process.stdout is not None
        with open(self.log_path, "a", encoding="utf-8") as log_file:
            for raw_line in self.process.stdout:
                line = ANSI_RE.sub("", raw_line).rstrip()
                if not line:
                    continue
                log_file.write(line + "\n")
                log_file.flush()
                logger.debug("cloudflared: %s", line)
                if self.public_url is None:
                    match = TUNNEL_URL_RE.search(line)
                    if match:
                        self.public_url = match.group(0)
                        self._url_event.set()
                if not self.registered and "Registered tunnel connection" in line:
                    # Data plane is up: the public URL is actually reachable now.
                    logger.info("Cloudflare tunnel connection registered.")
                    self.registered = True
                    self._registered_event.set()
                if self.fatal_error is None and TUNNEL_FATAL_RE.search(line):
                    # The quick tunnel itself could not be created (e.g. DNS or
                    # API blocked).  Abort the wait early instead of timeouting.
                    self.fatal_error = line.strip()
                    self._fatal_event.set()

    def wait_for_url(self, timeout: float) -> Optional[str]:
        """Block until the public URL is found (or fail fast on a fatal error)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._url_event.is_set():
                return self.public_url
            if self._fatal_event.is_set() or (
                self.process is not None and self.process.poll() is not None
            ):
                return None
            time.sleep(0.25)
        return None

    def wait_for_registration(self, timeout: float) -> bool:
        """Block until the tunnel data plane connects to the Cloudflare edge."""
        return self._registered_event.wait(timeout)

    def stop(self) -> None:
        """Terminate the tunnel process, escalating to kill if needed."""
        if self.process is None:
            return
        if self.process.poll() is None:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except (subprocess.TimeoutExpired, OSError):
                try:
                    self.process.kill()
                except OSError:
                    pass
        self.process = None
        logger.info("cloudflared stopped.")


class SshTunnel:
    """A public reverse tunnel borrowed over SSH.

    Used as an automatic fallback when Cloudflare is unreachable.  Works with
    nothing but an outbound SSH connection to a free provider.  The provider
    config (command builder + URL regex) is passed in from ``SSH_PROVIDERS``.
    """

    def __init__(self, port: int, log_path: Path, provider: dict) -> None:
        self.port = port
        self.log_path = log_path
        self.provider = provider
        self.process: Optional[subprocess.Popen] = None
        self.public_url: Optional[str] = None
        self.reachable = False          # URL served our local content (verified)
        self._log_file = None
        self._url_event = threading.Event()

    def _command(self) -> list:
        return self.provider["cmd"](self.port)

    def start(self) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        logger.info("Starting SSH tunnel: %s", " ".join(self._command()))
        # On Windows, ssh.exe produces no output through a pipe (subprocess.PIPE).
        # Redirect stdout to the log file directly instead — this matches how
        # the manual probe successfully captured the URL.
        self._log_file = open(
            self.log_path, "w", encoding="utf-8", errors="replace"
        )
        self.process = subprocess.Popen(
            self._command(),
            stdout=self._log_file,
            stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )
        self._reader_thread = threading.Thread(
            target=self._poll_for_url, name="ssh-tunnel-reader", daemon=True
        )
        self._reader_thread.start()

    def _poll_for_url(self) -> None:
        """Watch the log file for the public URL (ssh writes to a file on Windows)."""
        deadline = time.monotonic() + SSH_STARTUP_TIMEOUT
        url_re = self.provider["url_re"]
        while time.monotonic() < deadline:
            if self.process is not None and self.process.poll() is not None:
                break
            try:
                text = self.log_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                time.sleep(0.5)
                continue
            match = url_re.search(text)
            if match:
                self.public_url = match.group(0)
                self._url_event.set()
                return
            time.sleep(0.5)
        # Final read — the URL may have appeared right before the timeout.
        try:
            text = self.log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        match = url_re.search(text)
        if match:
            self.public_url = match.group(0)
            self._url_event.set()

    def wait_for_url(self, timeout: float) -> Optional[str]:
        """Block until the public URL is found (or the process exits)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._url_event.is_set():
                return self.public_url
            if self.process is not None and self.process.poll() is not None:
                return None
            time.sleep(0.25)
        return None

    def stop(self) -> None:
        """Terminate the ssh process, escalating to kill if needed."""
        if self.process is None:
            return
        if self.process.poll() is None:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except (subprocess.TimeoutExpired, OSError):
                try:
                    self.process.kill()
                except OSError:
                    pass
        if self._log_file and not self._log_file.closed:
            self._log_file.close()
        self.process = None
        logger.info("SSH tunnel stopped.")


def wait_reachable(url: str, tries: int = SSH_REACH_TRIES,
                   delay: float = SSH_REACH_DELAY, timeout: float = 12.0) -> bool:
    """Best-effort check that the public URL actually reaches the local server.

    Reverse tunnels over SSH can take a few seconds before the first request
    is forwarded; ``delay`` lets the tunnel settle between attempts.
    """
    for _ in range(tries):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310
                if resp.status == HTTPStatus.OK:
                    return True
        except Exception:  # noqa: BLE001 - any failure just means "try again"
            pass
        time.sleep(delay)
    return False


def try_ssh_fallback(port: int, timeout: float = SSH_STARTUP_TIMEOUT,
                     reason: str = "") -> Tuple[Optional[SshTunnel], Optional[str]]:
    """Try each SSH provider in order; return the first working ``(tunnel, url)``."""
    if reason:
        print(f"[i] {reason}")

    for provider in SSH_PROVIDERS:
        name = provider["name"]
        print(f"[..] Trying SSH tunnel provider: {name} ...")
        ssh = SshTunnel(port, LOGS_DIR / provider["log_name"], provider)
        try:
            ssh.start()
        except OSError as exc:
            print(f"    [!] Could not start ssh ({name}): {exc}")
            continue

        public_url = ssh.wait_for_url(timeout)
        if public_url:
            print(f"    [OK] {name} gave URL: {public_url}")
            return ssh, public_url

        # No URL — try next provider.
        print(f"    [!] {name} did not give a URL in {int(timeout)}s.")
        ssh.stop()

    print("[ERROR] All SSH tunnel providers failed.")
    return None, None


# ---------------------------------------------------------------------------
# File icons (based on extension)
# ---------------------------------------------------------------------------

_FILE_ICONS: dict[str, str] = {
    ".zip": "\U0001F4E6", ".rar": "\U0001F4E6", ".7z": "\U0001F4E6",
    ".tar": "\U0001F4E6", ".gz": "\U0001F4E6",
    ".pdf": "\U0001F4C4",
    ".doc": "\U0001F4C3", ".docx": "\U0001F4C3",
    ".xls": "\U0001F4CA", ".xlsx": "\U0001F4CA",
    ".ppt": "\U0001F4AC", ".pptx": "\U0001F4AC",
    ".txt": "\U0001F4DD", ".md": "\U0001F4DD",
    ".jpg": "\U0001F5BC\uFE0F", ".jpeg": "\U0001F5BC\uFE0F",
    ".png": "\U0001F5BC\uFE0F", ".gif": "\U0001F5BC\uFE0F",
    ".webp": "\U0001F5BC\uFE0F", ".bmp": "\U0001F5BC\uFE0F",
    ".svg": "\U0001F5BC\uFE0F", ".ico": "\U0001F5BC\uFE0F",
    ".mp3": "\U0001F3B5", ".wav": "\U0001F3B5", ".flac": "\U0001F3B5",
    ".aac": "\U0001F3B5", ".ogg": "\U0001F3B5", ".m4a": "\U0001F3B5",
    ".mp4": "\U0001F3AC", ".mkv": "\U0001F3AC", ".avi": "\U0001F3AC",
    ".mov": "\U0001F3AC", ".wmv": "\U0001F3AC", ".webm": "\U0001F3AC",
    ".exe": "\u2699\uFE0F", ".msi": "\u2699\uFE0F",
    ".py": "\U0001F40D", ".js": "\U0001F4DC", ".ts": "\U0001F4DC",
    ".html": "\U0001F310", ".css": "\U0001F310",
    ".json": "\U0001F4CB", ".xml": "\U0001F4CB", ".csv": "\U0001F4CB",
    ".iso": "\U0001F4BF", ".img": "\U0001F4BF",
    ".apk": "\U0001F4F1",
    ".ttf": "\U0001F5A8\uFE0F", ".otf": "\U0001F5A8\uFE0F",
    ".log": "\U0001F4DD", ".ini": "\u2699\uFE0F",
    ".bak": "\U0001F4BE",
}


def _file_icon(ext: str) -> str:
    """Return an emoji icon for a file extension."""
    return _FILE_ICONS.get(ext, "\U0001F4C4")


_FILE_BADGES: dict[str, tuple[str, str]] = {
    # ext: (css class, inner label)
    ".html": ("html", "&lt;/&gt;"),
    ".htm": ("html", "&lt;/&gt;"),
    ".css": ("css", "#"),
    ".js": ("js", "JS"),
    ".ts": ("ts", "TS"),
    ".json": ("json", "{}"),
    ".md": ("md", "MD"),
    ".txt": ("txt", "TXT"),
    ".png": ("img", "IMG"),
    ".jpg": ("img", "IMG"),
    ".jpeg": ("img", "IMG"),
    ".gif": ("img", "IMG"),
    ".webp": ("img", "IMG"),
    ".svg": ("img", "SVG"),
    ".ico": ("ico", "&#9733;"),
    ".pdf": ("pdf", "PDF"),
    ".zip": ("zip", "ZIP"),
    ".rar": ("zip", "ZIP"),
    ".7z": ("zip", "ZIP"),
    ".mp4": ("vid", "MP4"),
    ".mkv": ("vid", "MKV"),
    ".mp3": ("aud", "MP3"),
    ".py": ("py", "PY"),
    ".exe": ("exe", "EXE"),
}


def _file_badge(ext: str) -> str:
    """Colored rounded badge matching the file-manager UI."""
    cls, label = _FILE_BADGES.get(ext, ("file", "FILE"))
    return f'<span class="badge {cls}">{label}</span>'


def _fmt_mtime(ts: float) -> str:
    """Human-friendly modified time like ``Today, 05:30 PM`` / ``May 1, 2023``."""
    dt = time.localtime(ts)
    now = time.localtime()
    if dt.tm_year == now.tm_year and dt.tm_yday == now.tm_yday:
        return "Today, " + time.strftime("%I:%M %p", dt).lstrip("0")
    if dt.tm_year == now.tm_year and dt.tm_yday == now.tm_yday - 1:
        return "Yesterday, " + time.strftime("%I:%M %p", dt).lstrip("0")
    return time.strftime("%b %d, %Y", dt)


def _perm_string(path: Path) -> str:
    """Unix-style permission string, e.g. ``drwxr-xr-x`` / ``rw-r--r--``."""
    try:
        st = path.stat()
    except OSError:
        return "rwxr-xr-x" if path.is_dir() else "rw-r--r--"
    prefix = "d" if path.is_dir() else "-"
    perms = ""
    for shift in (6, 3, 0):
        triple = (st.st_mode >> shift) & 0o7
        perms += "r" if triple & 4 else "-"
        perms += "w" if triple & 2 else "-"
        perms += "x" if triple & 1 else "-"
    return prefix + perms


def _sidebar_tree(current: Path) -> str:
    """Build the nested folder tree for the left sidebar."""
    root = DOWNLOADS_DIR.resolve()

    def walk(directory: Path) -> str:
        try:
            subdirs = sorted(
                (
                    p for p in directory.iterdir()
                    if p.is_dir() and not p.name.startswith(".")
                ),
                key=lambda p: p.name.lower(),
            )
        except OSError:
            return ""
        parts = []
        for sd in subdirs:
            href = "/" + sd.relative_to(root).as_posix() + "/"
            is_self = sd.resolve() == current.resolve()
            under = str(current.resolve()).startswith(
                str(sd.resolve()) + os.sep
            ) or is_self
            cls = " active" if is_self else ""
            open_cls = " open" if under else ""
            children = walk(sd)
            parts.append(
                f'<div class="tnode{open_cls}">'
                f'<a class="tlink{cls}" href="{html.escape(href)}">'
                f'<span class="tfolder"></span>'
                f'<span class="tname">{html.escape(sd.name)}</span></a>'
                f"{children}</div>"
            )
        return f'<div class="tkids">{"".join(parts)}</div>' if parts else ""

    root_active = " active" if current.resolve() == root else ""
    children = walk(root)
    return (
        '<div class="tnode open">'
        f'<a class="tlink{root_active}" href="/">'
        '<span class="tfolder root"></span>'
        '<span class="tname">/</span></a>'
        f"{children}</div>"
    )


# ---------------------------------------------------------------------------
# File server
# ---------------------------------------------------------------------------

class DownloadRequestHandler(SimpleHTTPRequestHandler):
    """Serves files from ``./downloads`` with listing, streaming and ranges.

    Security properties:
      * the root directory is fixed to ``./downloads``;
      * path traversal / symlink escapes are rejected;
      * dot-files (e.g. ``.env``, ``.gitignore``) are never served;
      * GET/HEAD serve files; POST supports upload / mkdir / create only
        (no admin API, names are validated against traversal).
    """

    server_version = "BlackServer/1.0"
    protocol_version = "HTTP/1.1"

    # -- logging ----------------------------------------------------------
    def _client_ip(self) -> str:
        """Real client IP, taken from the tunnel's forwarding header."""
        forwarded = self.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return self.client_address[0]

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        logger.info("%s - %s", self._client_ip(), fmt % args)

    # -- path resolution --------------------------------------------------
    def _resolve_path(self) -> Optional[Path]:
        """Map the request path to a real path inside ``downloads``."""
        root = DOWNLOADS_DIR.resolve()
        try:
            candidate = Path(self.translate_path(self.path)).resolve()
        except OSError:
            return None
        # Defence in depth: translate_path already cannot escape, but resolving
        # symlinks makes the containment check explicit and robust.
        if candidate != root and root not in candidate.parents:
            return None
        return candidate

    @staticmethod
    def _is_hidden(path: Path) -> bool:
        root = DOWNLOADS_DIR.resolve()
        try:
            relative = path.relative_to(root)
        except ValueError:
            return True
        return any(part.startswith(".") for part in relative.parts)

    @staticmethod
    def _safe_name(raw: str, *, allow_basename: bool = False) -> Optional[str]:
        """Validate a user-supplied file/folder name (no traversal).

        With ``allow_basename`` (uploads) a client path is reduced to its
        final component; otherwise any path separator is rejected.
        """
        name = (raw or "").strip()
        if not allow_basename:
            name = name.replace("\\", "/")
            if "/" in name or name in (".", "..") or ".." in name:
                return None
        else:
            name = name.replace("\\", "/").split("/")[-1].strip()
            if not name or name in (".", ".."):
                return None
        if not name or name in (".", ".."):
            return None
        if any(ch in name for ch in '<>:"|?*\x00'):
            return None
        if len(name) > 200:
            return None
        return name

    def _json_response(self, code: int, obj: dict) -> None:
        data = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _read_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > 200 * 1024 * 1024:  # 200 MB cap
            return b""
        return self.rfile.read(length)

    def _target_dir(self) -> Optional[Path]:
        """Directory that POST operations act on (current listing path)."""
        path = self._resolve_path()
        if path is None:
            return None
        if path.is_file():
            path = path.parent
        if not path.is_dir() or self._is_hidden(path):
            return None
        return path

    # -- POST: upload / mkdir / create ------------------------------------
    def do_POST(self):  # noqa: N802
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        api = (query.get("__api") or [""])[0]
        if api == "upload":
            return self._handle_upload()
        if api == "mkdir":
            return self._handle_mkdir()
        if api == "create":
            return self._handle_create()
        if api == "delete":
            return self._handle_delete()
        if api == "rename":
            return self._handle_rename()
        if api == "move":
            return self._handle_move()
        if api == "copy":
            return self._handle_copy()
        if api == "tree":
            return self._handle_tree()
        self._json_response(HTTPStatus.NOT_FOUND, {"ok": False, "error": "unknown route"})

    def _handle_upload(self):
        target = self._target_dir()
        if target is None:
            self._json_response(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "bad directory"})
            return
        ctype = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in ctype:
            self._json_response(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "expected multipart"})
            return
        body = self._read_body()
        if not body:
            self._json_response(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "empty body"})
            return
        boundary_m = re.search(r'boundary="?([^";]+)"?', ctype)
        if not boundary_m:
            self._json_response(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "no boundary"})
            return
        boundary = boundary_m.group(1).encode("utf-8", "replace")
        saved = []
        for part in body.split(b"--" + boundary):
            if b"Content-Disposition" not in part:
                continue
            fn_m = re.search(br'filename="([^"]*)"', part)
            if not fn_m:
                # RFC 5987 filename*
                fn_m = re.search(br"filename\*=UTF-8''([^\r\n;]+)", part)
                if not fn_m:
                    continue
                try:
                    fname = urllib.parse.unquote(fn_m.group(1).decode("utf-8", "replace"))
                except Exception:
                    continue
            else:
                try:
                    fname = fn_m.group(1).decode("utf-8")
                except UnicodeDecodeError:
                    fname = fn_m.group(1).decode("latin-1")
            safe = self._safe_name(Path(fname).name, allow_basename=True)
            if not safe:
                continue
            header_end = part.find(b"\r\n\r\n")
            if header_end < 0:
                continue
            content = part[header_end + 4:]
            # strip trailing CRLF that belongs to the multipart framing
            if content.endswith(b"\r\n"):
                content = content[:-2]
            dest = target / safe
            # avoid silent overwrite of a different existing name? keep simple: overwrite allowed
            try:
                dest.write_bytes(content)
                saved.append(safe)
            except OSError as exc:
                logger.warning("upload failed for %s: %s", safe, exc)
        if not saved:
            self._json_response(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "no file received"})
            return
        logger.info("Uploaded %s -> %s", ", ".join(saved), target)
        self._json_response(HTTPStatus.OK, {"ok": True, "files": saved})

    def _handle_mkdir(self):
        target = self._target_dir()
        if target is None:
            self._json_response(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "bad directory"})
            return
        try:
            payload = json.loads(self._read_body().decode("utf-8") or "{}")
        except json.JSONDecodeError:
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        name = self._safe_name(str(payload.get("name", "")))
        if not name:
            self._json_response(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "invalid folder name"})
            return
        dest = target / name
        if dest.exists():
            self._json_response(HTTPStatus.CONFLICT, {"ok": False, "error": "already exists"})
            return
        try:
            dest.mkdir(parents=False, exist_ok=False)
        except OSError as exc:
            self._json_response(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": str(exc)})
            return
        logger.info("Created folder %s in %s", name, target)
        self._json_response(HTTPStatus.OK, {"ok": True, "name": name})

    def _handle_create(self):
        target = self._target_dir()
        if target is None:
            self._json_response(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "bad directory"})
            return
        try:
            payload = json.loads(self._read_body().decode("utf-8") or "{}")
        except json.JSONDecodeError:
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        raw = str(payload.get("name", "")).strip()
        # default extension .txt when none provided
        if raw and "." not in Path(raw).name:
            raw = raw + ".txt"
        name = self._safe_name(raw)
        if not name:
            self._json_response(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "invalid file name"})
            return
        dest = target / name
        if dest.exists():
            self._json_response(HTTPStatus.CONFLICT, {"ok": False, "error": "already exists"})
            return
        try:
            dest.write_bytes(b"")
        except OSError as exc:
            self._json_response(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": str(exc)})
            return
        logger.info("Created file %s in %s", name, target)
        self._json_response(HTTPStatus.OK, {"ok": True, "name": name})

    def _payload(self) -> dict:
        try:
            data = json.loads(self._read_body().decode("utf-8") or "{}")
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}

    def _item_in(self, target: Path, name: str) -> Optional[Path]:
        """Resolve *name* inside *target*, ensuring containment."""
        safe = self._safe_name(name)
        if not safe:
            return None
        item = (target / safe).resolve()
        root = DOWNLOADS_DIR.resolve()
        if item != root and root not in item.parents:
            return None
        if self._is_hidden(item):
            return None
        return item

    def _dest_dir(self, dest: str) -> Optional[Path]:
        """Resolve a destination folder path relative to downloads root."""
        raw = (dest or "/").strip().replace("\\", "/")
        if not raw.startswith("/"):
            raw = "/" + raw
        parts = [p for p in raw.split("/") if p and p != "."]
        if any(p == ".." for p in parts):
            return None
        candidate = DOWNLOADS_DIR.resolve()
        for p in parts:
            safe = self._safe_name(p)
            if not safe:
                return None
            candidate = candidate / safe
        try:
            candidate = candidate.resolve()
        except OSError:
            return None
        root = DOWNLOADS_DIR.resolve()
        if candidate != root and root not in candidate.parents:
            return None
        if not candidate.is_dir() or self._is_hidden(candidate):
            return None
        return candidate

    def _handle_delete(self):
        target = self._target_dir()
        if target is None:
            self._json_response(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "bad directory"})
            return
        payload = self._payload()
        item = self._item_in(target, str(payload.get("name", "")))
        if item is None or not item.exists():
            self._json_response(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not found"})
            return
        if item.resolve() == DOWNLOADS_DIR.resolve():
            self._json_response(HTTPStatus.FORBIDDEN, {"ok": False, "error": "cannot delete root"})
            return
        try:
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()
        except OSError as exc:
            self._json_response(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": str(exc)})
            return
        logger.info("Deleted %s", item)
        self._json_response(HTTPStatus.OK, {"ok": True, "name": item.name})

    def _handle_rename(self):
        target = self._target_dir()
        if target is None:
            self._json_response(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "bad directory"})
            return
        payload = self._payload()
        item = self._item_in(target, str(payload.get("name", "")))
        if item is None or not item.exists():
            self._json_response(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not found"})
            return
        new_name = self._safe_name(str(payload.get("newName", "")))
        if not new_name:
            self._json_response(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "invalid new name"})
            return
        dest = target / new_name
        if dest.exists() and dest.resolve() != item.resolve():
            self._json_response(HTTPStatus.CONFLICT, {"ok": False, "error": "already exists"})
            return
        if dest.resolve() == item.resolve():
            self._json_response(HTTPStatus.OK, {"ok": True, "name": new_name})
            return
        try:
            item.rename(dest)
        except OSError as exc:
            self._json_response(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": str(exc)})
            return
        logger.info("Renamed %s -> %s", item.name, new_name)
        self._json_response(HTTPStatus.OK, {"ok": True, "name": new_name})

    def _handle_move(self):
        target = self._target_dir()
        if target is None:
            self._json_response(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "bad directory"})
            return
        payload = self._payload()
        item = self._item_in(target, str(payload.get("name", "")))
        if item is None or not item.exists():
            self._json_response(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not found"})
            return
        dest_dir = self._dest_dir(str(payload.get("dest", "/")))
        if dest_dir is None:
            self._json_response(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "invalid destination"})
            return
        dest = dest_dir / item.name
        try:
            if dest.resolve() == item.resolve():
                self._json_response(HTTPStatus.OK, {"ok": True, "name": item.name, "dest": str(payload.get("dest"))})
                return
            if dest.exists():
                self._json_response(HTTPStatus.CONFLICT, {"ok": False, "error": "already exists at destination"})
                return
            # prevent moving a folder into itself / its child
            if item.is_dir():
                try:
                    item.resolve().relative_to(dest_dir.resolve())
                    self._json_response(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "cannot move into itself"})
                    return
                except ValueError:
                    pass
            shutil.move(str(item), str(dest))
        except OSError as exc:
            self._json_response(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": str(exc)})
            return
        logger.info("Moved %s -> %s", item, dest)
        self._json_response(HTTPStatus.OK, {"ok": True, "name": item.name, "dest": dest_dir.name or "/"})

    def _handle_copy(self):
        target = self._target_dir()
        if target is None:
            self._json_response(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "bad directory"})
            return
        payload = self._payload()
        item = self._item_in(target, str(payload.get("name", "")))
        if item is None or not item.exists():
            self._json_response(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not found"})
            return
        dest_dir = self._dest_dir(str(payload.get("dest", "/")))
        if dest_dir is None:
            self._json_response(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "invalid destination"})
            return
        dest = dest_dir / item.name
        if dest.exists():
            self._json_response(HTTPStatus.CONFLICT, {"ok": False, "error": "already exists at destination"})
            return
        if item.is_dir():
            try:
                item.resolve().relative_to(dest_dir.resolve())
                self._json_response(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "cannot copy into itself"})
                return
            except ValueError:
                pass
        try:
            if item.is_dir():
                shutil.copytree(item, dest)
            else:
                shutil.copy2(item, dest)
        except OSError as exc:
            self._json_response(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": str(exc)})
            return
        logger.info("Copied %s -> %s", item, dest)
        self._json_response(HTTPStatus.OK, {"ok": True, "name": item.name, "dest": dest_dir.name or "/"})

    def _handle_tree(self):
        """JSON tree of all folders under downloads (for move/copy dest picker)."""
        root = DOWNLOADS_DIR.resolve()

        def walk(directory: Path) -> dict:
            rel = "/" + directory.relative_to(root).as_posix().lstrip("./")
            if rel == "/.":
                rel = "/"
            node = {"name": directory.name or "/", "path": rel, "dirs": []}
            try:
                subdirs = sorted(
                    (
                        p for p in directory.iterdir()
                        if p.is_dir() and not p.name.startswith(".")
                    ),
                    key=lambda p: p.name.lower(),
                )
            except OSError:
                subdirs = []
            for sd in subdirs:
                node["dirs"].append(walk(sd))
            return node

        self._json_response(HTTPStatus.OK, {"ok": True, "tree": walk(root)})

    # -- request handling -------------------------------------------------
    def send_head(self):
        path = self._resolve_path()
        if path is None or not path.exists() or self._is_hidden(path):
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return None

        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)

        if path.is_dir():
            # Redirect directory requests without a trailing slash so relative
            # links inside the listing work correctly.
            if not self.path.rstrip("?").endswith("/"):
                self.send_response(HTTPStatus.MOVED_PERMANENTLY)
                self.send_header("Location", self.path.split("?")[0] + "/")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return None
            if query.get("zip"):
                return self._send_zip(path)
            return self.list_directory(str(path))

        if query.get("zip"):
            return self._send_zip(path)
        return self._send_file(path)

    def _send_zip(self, path: Path):
        """Stream *path* (file or folder) as a ZIP archive."""
        try:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                if path.is_dir():
                    for root, _dirs, files in os.walk(path):
                        for name in files:
                            full = Path(root) / name
                            if self._is_hidden(full):
                                continue
                            zf.write(full, full.relative_to(path))
                    zip_name = (path.name or "downloads") + ".zip"
                else:
                    zf.write(path, path.name)
                    zip_name = path.stem + ".zip"
            data = buf.getvalue()
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND, "Cannot create ZIP")
            return None

        safe_ascii = "".join(
            ch if 32 <= ord(ch) < 127 and ch not in '"\\' else "_"
            for ch in zip_name
        )
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Length", str(len(data)))
        self.send_header(
            "Content-Disposition",
            f'attachment; filename="{safe_ascii}"; '
            f"filename*=UTF-8''{urllib.parse.quote(zip_name)}",
        )
        self.end_headers()
        return io.BytesIO(data)

    def _send_file(self, path: Path):
        try:
            file_obj = open(path, "rb")
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return None

        try:
            stat = os.fstat(file_obj.fileno())
            file_size = stat.st_size
            self._bytes_to_send = file_size
            start, end = 0, max(file_size - 1, 0)
            range_header = self.headers.get("Range")

            if range_header:
                parsed = self._parse_range(range_header, file_size)
                if parsed is None:
                    # Unsatisfiable range -> 416, tells clients the real size.
                    file_obj.close()
                    self.send_response(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
                    self.send_header("Content-Range", f"bytes */{file_size}")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return None
                start, end = parsed
                self._bytes_to_send = end - start + 1
                self.send_response(HTTPStatus.PARTIAL_CONTENT)
                self.send_header(
                    "Content-Range", f"bytes {start}-{end}/{file_size}"
                )
            else:
                self.send_response(HTTPStatus.OK)

            self.send_header("Content-Type", self.guess_type(str(path)))
            self.send_header("Content-Length", str(self._bytes_to_send))
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Last-Modified", self.date_time_string(stat.st_mtime))
            self.send_header("Content-Disposition", self._content_disposition(path.name))
            self.end_headers()

            if start:
                file_obj.seek(start)
            return file_obj
        except Exception:
            file_obj.close()
            raise

    @staticmethod
    def _parse_range(header: str, size: int) -> Optional[Tuple[int, int]]:
        """Parse a single ``bytes=`` range. Returns ``(start, end)`` or None."""
        if size <= 0 or not header.startswith("bytes="):
            return None
        spec = header[len("bytes="):].split(",")[0].strip()
        if "-" not in spec:
            return None
        start_str, end_str = spec.split("-", 1)
        try:
            if start_str == "":
                # Suffix range: last N bytes.
                length = int(end_str)
                if length <= 0:
                    return None
                start = max(0, size - length)
                end = size - 1
            else:
                start = int(start_str)
                end = int(end_str) if end_str else size - 1
        except ValueError:
            return None
        if start > end or start >= size:
            return None
        return start, min(end, size - 1)

    @staticmethod
    def _content_disposition(filename: str) -> str:
        """Build a safe ``Content-Disposition`` header for any filename."""
        safe_ascii = "".join(
            ch if 32 <= ord(ch) < 127 and ch not in '"\\' else "_"
            for ch in filename
        )
        encoded = urllib.parse.quote(filename)
        return f"attachment; filename=\"{safe_ascii}\"; filename*=UTF-8''{encoded}"

    def copyfile(self, source, outputfile):
        """Stream the body from disk in chunks (never load whole files in RAM).

        Respects ``_bytes_to_send`` so HTTP Range responses send exactly the
        requested slice, which enables resumable downloads of large files.
        """
        length = getattr(self, "_bytes_to_send", None)
        try:
            if length is None:
                shutil.copyfileobj(source, outputfile, length=CHUNK_SIZE)
                return
            remaining = length
            while remaining > 0:
                data = source.read(min(CHUNK_SIZE, remaining))
                if not data:
                    break
                outputfile.write(data)
                remaining -= len(data)
        except (BrokenPipeError, ConnectionResetError):
            logger.info("%s - client disconnected during transfer", self._client_ip())

    # -- directory listing -------------------------------------------------
    def list_directory(self, path):
        try:
            entries = sorted(os.listdir(path), key=str.lower)
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND, "No permission to list directory")
            return None

        # Hide dot-files from the public listing.
        entries = [name for name in entries if not name.startswith(".")]

        root = DOWNLOADS_DIR.resolve()
        current = Path(path)
        display_path = "/" + current.relative_to(root).as_posix().lstrip("./")
        if display_path == "/.":
            display_path = "/"

        tree_html = _sidebar_tree(current)
        has_parent = current != root

        rows = []
        first_file_json = "null"
        file_count = 0

        if has_parent:
            rows.append(
                '<div class="frow dir parent-row" data-href="../" data-name=".." '
                'data-kind="0" data-size="-1" data-mtime="0" '
                'onclick="goParent()" '
                'onmouseenter="hoverRow(this)" onmouseleave="unhoverRow(this)">'
                '<div class="fcell fname">'
                '<span class="badge folder">&#8617;</span>'
                '<span class="ftext"><span class="flabel">..</span>'
                '<span class="fsub">Parent folder</span></span></div>'
                '<div class="fcell fsize">&mdash;</div>'
                '<div class="fcell fmtime">&mdash;</div>'
                '<div class="fcell fdot"></div>'
                "</div>"
            )

        for name in entries:
            full = current / name
            link = urllib.parse.quote(name, safe="")
            label = html.escape(name)
            try:
                st = full.stat()
                mtime = st.st_mtime
                size_b = st.st_size
            except OSError:
                mtime = 0.0
                size_b = 0

            if full.is_dir():
                href = link + "/"
                rows.append(
                    f'<div class="frow dir" data-href="{href}" data-name="{label}" '
                    f'data-kind="1" data-size="-1" data-mtime="{int(mtime)}" '
                    f'onclick="goDir(\'{href}\')" '
                    f'onmouseenter="hoverRow(this)" onmouseleave="unhoverRow(this)">'
                    f'<div class="fcell fname">'
                    f'<span class="badge folder">&#128193;</span>'
                    f'<span class="ftext"><span class="flabel">{label}</span>'
                    f'<span class="fsub">Folder</span></span></div>'
                    f'<div class="fcell fsize">&mdash;</div>'
                    f'<div class="fcell fmtime">{_fmt_mtime(mtime)}</div>'
                    f'<div class="fcell fdot">'
                    f'<button class="dots" type="button" title="More" '
                    f'onclick="openRowMenu(event, this)">&#8943;</button></div>'
                    f"</div>"
                )
            else:
                file_count += 1
                ext = full.suffix.lower()
                badge = _file_badge(ext)
                size_str = human_size(size_b)
                type_label = (ext.lstrip(".") + " file") if ext else "file"
                perms = _perm_string(full)
                rel_path = (display_path.rstrip("/") + "/" + name) if display_path != "/" else "/" + name
                meta = json.dumps({
                    "name": name,
                    "href": link,
                    "size": size_str,
                    "sizeB": size_b,
                    "type": type_label,
                    "mtime": _fmt_mtime(mtime),
                    "mtimeTs": int(mtime),
                    "perm": perms,
                    "path": rel_path,
                    "ext": ext.lstrip(".") or "file",
                }, ensure_ascii=False)
                if first_file_json == "null":
                    first_file_json = meta
                rows.append(
                    f'<div class="frow file" data-meta=\'{meta}\' '
                    f'data-name="{label}" data-kind="2" data-size="{size_b}" '
                    f'data-mtime="{int(mtime)}" '
                    f'onclick="selectFile(this)" '
                    f'onmouseenter="hoverRow(this)" onmouseleave="unhoverRow(this)">'
                    f'<div class="fcell fname">{badge}'
                    f'<span class="ftext"><span class="flabel">{label}</span>'
                    f'<span class="fsub">{type_label} &middot; {size_str}</span></span></div>'
                    f'<div class="fcell fsize">{size_str}</div>'
                    f'<div class="fcell fmtime">{_fmt_mtime(mtime)}</div>'
                    f'<div class="fcell fdot">'
                    f'<button class="dots" type="button" title="More" '
                    f'onclick="openRowMenu(event, this)">&#8943;</button></div>'
                    f"</div>"
                )

        if not rows:
            body_rows = (
                '<div class="empty-state">'
                "<div class=\"empty-icon\">&#128196;</div>"
                "<div>No files in this folder</div>"
                "</div>"
            )
        else:
            body_rows = "\n".join(rows)

        page = f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>File Manager - Black Server</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  :root, [data-theme="dark"] {{
    --bg: #070b14;
    --bg2: #0b1120;
    --panel: #0e1628;
    --panel2: #111c33;
    --panel3: #152240;
    --border: #1c2d4f;
    --border2: #243b66;
    --text: #e8eefc;
    --text2: #8ba0c5;
    --text3: #5a719e;
    --blue: #3b82f6;
    --blue2: #2563eb;
    --green: #22c55e;
    --purple: #8b5cf6;
    --pink: #ec4899;
    --teal: #14b8a6;
    --orange: #f59e0b;
    --sel: rgba(59,130,246,.14);
    --sel-border: rgba(59,130,246,.55);
    --hover: rgba(59,130,246,.07);
    --radius: 14px;
    --shadow: 0 8px 32px rgba(0,0,0,.45);
    --sidebar-bg: rgba(0,0,0,.18);
    --details-bg: rgba(0,0,0,.22);
    --mbar-bg: #1a2744;
    --switch-bg: #1a2744;
    --switch-knob: #f8fafc;
    --glass-bg: rgba(14,22,40,.92);
    --input-bg: #0e1628;
    --body-transition: background .45s ease, color .45s ease;
  }}

  [data-theme="light"] {{
    --bg: #eef1f6;
    --bg2: #f7f8fb;
    --panel: #ffffff;
    --panel2: #f3f5f9;
    --panel3: #e8ecf4;
    --border: #dde3ee;
    --border2: #c9d2e3;
    --text: #152038;
    --text2: #5a6a88;
    --text3: #8b98b3;
    --blue: #3b82f6;
    --blue2: #2563eb;
    --green: #16a34a;
    --purple: #8b5cf6;
    --pink: #ec4899;
    --teal: #14b8a6;
    --orange: #f59e0b;
    --sel: rgba(59,130,246,.12);
    --sel-border: rgba(59,130,246,.5);
    --hover: rgba(59,130,246,.06);
    --radius: 14px;
    --shadow: 0 8px 28px rgba(20,35,70,.12);
    --sidebar-bg: #f7f8fb;
    --details-bg: #f7f8fb;
    --mbar-bg: #e4e9f2;
    --switch-bg: #d8dfecc;
    --switch-knob: #ffffff;
    --glass-bg: rgba(255,255,255,.88);
    --input-bg: #ffffff;
    --body-transition: background .45s ease, color .45s ease;
  }}
  /* fix typo-safe: real value */
  [data-theme="light"] {{ --switch-bg: #d8dfec; }}

  html {{ font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
         -webkit-font-smoothing: antialiased; }}

  body {{
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    padding: 18px;
    transition: var(--body-transition);
  }}
  body, .app, .topbar, .machine, .metric, .gear, .search input,
  .sidebar, .center, .details, .meta-table, .sort-menu, .view-toggle,
  .sort-btn, .btn, .list-tools, .thead, .toast {{
    transition: background .45s ease, color .45s ease,
                border-color .45s ease, box-shadow .45s ease;
  }}

  /* ===== TOP BAR ===== */
  .topbar {{
    display: flex; align-items: center; gap: 14px;
    margin-bottom: 16px;
  }}
  .search {{
    flex: 1; max-width: 520px; position: relative;
  }}
  .search svg {{
    position: absolute; left: 14px; top: 50%; transform: translateY(-50%);
    width: 16px; height: 16px; stroke: var(--text3); fill: none;
    pointer-events: none;
  }}
  .search input {{
    width: 100%; padding: 12px 16px 12px 42px;
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 12px; color: var(--text); font-size: 14px;
    outline: none; transition: border-color .2s, box-shadow .2s, background .45s;
  }}
  .search input::placeholder {{ color: var(--text3); }}
  .search input:focus {{
    border-color: var(--blue);
    box-shadow: 0 0 0 3px rgba(59,130,246,.2);
  }}
  .top-right {{
    margin-left: auto; display: flex; align-items: center; gap: 12px;
  }}

  /* ===== THEME DRAWER SWITCH ===== */
  .theme-switch {{
    position: relative; width: 64px; height: 34px; flex-shrink: 0;
    background: var(--switch-bg);
    border: 1px solid var(--border);
    border-radius: 999px; cursor: pointer;
    box-shadow: inset 0 2px 6px rgba(0,0,0,.25);
    transition: background .4s cubic-bezier(.4,0,.2,1),
                border-color .4s ease, box-shadow .4s ease;
    padding: 0; outline: none;
  }}
  [data-theme="light"] .theme-switch {{
    box-shadow: inset 0 2px 6px rgba(20,35,70,.12);
  }}
  .theme-switch .knob {{
    position: absolute; top: 3px; left: 3px;
    width: 26px; height: 26px; border-radius: 50%;
    background: var(--switch-knob);
    box-shadow: 0 2px 8px rgba(0,0,0,.3);
    display: flex; align-items: center; justify-content: center;
    font-size: 13px; line-height: 1;
    transition: transform .45s cubic-bezier(.34,1.4,.5,1),
                background .4s ease, box-shadow .4s ease;
    z-index: 2;
  }}
  [data-theme="light"] .theme-switch .knob {{
    transform: translateX(30px);
    box-shadow: 0 2px 10px rgba(20,35,70,.2);
  }}
  .theme-switch .icon-moon, .theme-switch .icon-sun {{
    position: absolute; top: 50%; transform: translateY(-50%);
    font-size: 12px; opacity: .55;
    transition: opacity .35s ease, transform .45s cubic-bezier(.34,1.4,.5,1);
    pointer-events: none;
  }}
  .theme-switch .icon-sun {{ right: 9px; opacity: 0; transform: translateY(-50%) rotate(-90deg) scale(.5); }}
  .theme-switch .icon-moon {{ left: 9px; opacity: .7; }}
  [data-theme="light"] .theme-switch .icon-sun {{
    opacity: .75; transform: translateY(-50%) rotate(0deg) scale(1);
  }}
  [data-theme="light"] .theme-switch .icon-moon {{
    opacity: 0; transform: translateY(-50%) rotate(90deg) scale(.5);
  }}
  .theme-switch:hover .knob {{ box-shadow: 0 3px 12px rgba(59,130,246,.4); }}
  .theme-switch:active .knob {{ width: 30px; }}
  [data-theme="light"] .theme-switch:active .knob {{
    transform: translateX(26px); width: 30px;
  }}
  /* soft sliding track glow */
  .theme-switch::after {{
    content: ""; position: absolute; inset: 3px;
    border-radius: 999px; pointer-events: none;
    background: linear-gradient(90deg, rgba(59,130,246,.35), transparent 55%);
    opacity: 1; transition: opacity .4s ease, transform .45s ease;
  }}
  [data-theme="light"] .theme-switch::after {{
    background: linear-gradient(90deg, transparent, rgba(245,158,11,.4));
    opacity: 1;
  }}

  .machine {{
    display: flex; align-items: center; gap: 10px;
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 12px; padding: 8px 14px;
  }}
  .machine .mdot {{
    width: 9px; height: 9px; border-radius: 50%;
    background: var(--green); box-shadow: 0 0 8px var(--green);
    animation: pulse 2s infinite;
  }}
  @keyframes pulse {{
    0%,100% {{ opacity: 1; }} 50% {{ opacity: .55; }}
  }}
  .machine .mtext {{ line-height: 1.15; }}
  .machine .mtitle {{ font-size: 13px; font-weight: 600; }}
  .machine .mstatus {{ font-size: 11px; color: var(--green); font-weight: 600; }}
  .metrics {{
    display: flex; gap: 8px;
  }}
  .metric {{
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 10px; padding: 7px 11px; text-align: center;
    min-width: 58px;
  }}
  .metric .mlabel {{
    font-size: 9px; font-weight: 700; letter-spacing: .06em;
    color: var(--text2); margin-bottom: 4px;
  }}
  .metric .mbar {{
    height: 5px; border-radius: 3px; background: var(--mbar-bg); overflow: hidden;
  }}
  .metric .mbar i {{
    display: block; height: 100%; border-radius: 3px;
  }}
  .metric.cpu .mbar i {{ width: 34%; background: var(--blue); }}
  .metric.ram .mbar i {{ width: 56%; background: var(--green); }}
  .metric.disk .mbar i {{ width: 42%; background: var(--purple); }}
  .gear {{
    width: 42px; height: 42px; border-radius: 12px;
    background: var(--panel); border: 1px solid var(--border);
    color: var(--text2); font-size: 18px; cursor: pointer;
    display: flex; align-items: center; justify-content: center;
    transition: all .2s;
  }}
  .gear:hover {{ border-color: var(--blue); color: var(--text); }}

  /* ===== MAIN CARD ===== */
  .app {{
    background: linear-gradient(180deg, var(--panel) 0%, var(--bg2) 100%);
    border: 1px solid var(--border);
    border-radius: 20px;
    box-shadow: var(--shadow);
    overflow: hidden;
    animation: rise .45s cubic-bezier(.16,1,.3,1) both;
    transition: background .45s ease, border-color .45s ease, box-shadow .45s ease;
  }}
  @keyframes rise {{
    from {{ opacity: 0; transform: translateY(16px); }}
    to {{ opacity: 1; transform: translateY(0); }}
  }}

  .app-head {{
    display: flex; align-items: center; justify-content: space-between;
    padding: 22px 26px 18px;
    border-bottom: 1px solid var(--border);
  }}
  .app-head h1 {{
    font-size: 26px; font-weight: 700; letter-spacing: -.02em;
  }}
  .app-head .sub {{
    font-size: 13px; color: var(--text2); margin-top: 4px;
  }}
  .head-actions {{ display: flex; gap: 10px; }}
  .btn {{
    display: inline-flex; align-items: center; gap: 8px;
    padding: 10px 18px; border-radius: 11px;
    font-size: 13.5px; font-weight: 600; cursor: pointer;
    border: 1px solid var(--border2); background: var(--panel2);
    color: var(--text); transition: all .2s;
  }}
  .btn:hover {{ background: var(--panel3); border-color: var(--blue); }}
  .btn.primary {{
    background: linear-gradient(135deg, #4f8cff 0%, #3b5bfc 50%, #6d4df6 100%);
    border: none; color: #fff;
    box-shadow: 0 4px 18px rgba(79,140,255,.35);
  }}
  .btn.primary:hover {{
    transform: translateY(-1px);
    box-shadow: 0 6px 22px rgba(79,140,255,.5);
  }}

  /* ===== 3-COLUMN LAYOUT ===== */
  .layout {{
    display: grid;
    grid-template-columns: 210px 1fr 300px;
    min-height: 520px;
  }}

  /* ---- sidebar tree ---- */
  .sidebar {{
    background: var(--sidebar-bg);
    border-right: 1px solid var(--border);
    padding: 14px 10px;
    overflow-y: auto;
  }}
  .tkids {{ padding-left: 16px; }}
  .tnode > .tkids {{ display: none; }}
  .tnode.open > .tkids {{ display: block; }}
  .tlink {{
    display: flex; align-items: center; gap: 8px;
    padding: 7px 10px; border-radius: 8px;
    color: var(--text2); text-decoration: none;
    font-size: 13.5px; font-weight: 500;
    transition: all .15s;
    white-space: nowrap; overflow: hidden;
  }}
  .tlink:hover {{ background: var(--hover); color: var(--text); }}
  .tlink.active {{
    background: var(--sel); color: #7db4ff; font-weight: 600;
  }}
  .tfolder {{
    width: 16px; height: 12px; flex-shrink: 0;
    background: linear-gradient(180deg, #5b9dff, #3b82f6);
    border-radius: 2px 3px 3px 3px;
    position: relative;
  }}
  .tfolder::before {{
    content: ""; position: absolute; top: -3px; left: 0;
    width: 7px; height: 4px; background: #5b9dff;
    border-radius: 2px 2px 0 0;
  }}
  .tfolder.root {{ background: linear-gradient(180deg, #94a3b8, #64748b); }}
  .tfolder.root::before {{ background: #94a3b8; }}
  .tname {{ overflow: hidden; text-overflow: ellipsis; }}

  /* ---- center file list ---- */
  .center {{
    display: flex; flex-direction: column;
    border-right: 1px solid var(--border);
    min-width: 0;
  }}
  .list-tools {{
    display: flex; align-items: center; justify-content: flex-end;
    gap: 10px; padding: 12px 16px;
    border-bottom: 1px solid var(--border);
  }}
  .view-toggle {{
    display: flex; background: var(--panel2);
    border: 1px solid var(--border); border-radius: 9px;
    overflow: hidden;
  }}
  .view-toggle button {{
    width: 36px; height: 32px; border: none; background: transparent;
    color: var(--text3); cursor: pointer; font-size: 14px;
    display: flex; align-items: center; justify-content: center;
    transition: all .15s;
  }}
  .view-toggle button.on {{
    background: var(--panel3); color: var(--blue);
  }}
  .sort-wrap {{ position: relative; }}
  .sort-btn {{
    display: flex; align-items: center; gap: 6px;
    padding: 7px 14px; border-radius: 9px;
    background: var(--panel2); border: 1px solid var(--border);
    color: var(--text2); font-size: 13px; font-weight: 600;
    cursor: pointer; transition: all .15s;
  }}
  .sort-btn:hover {{ border-color: var(--blue); color: var(--text); }}
  .sort-menu {{
    position: absolute; right: 0; top: calc(100% + 6px);
    background: var(--panel2); border: 1px solid var(--border2);
    border-radius: 10px; min-width: 150px; z-index: 50;
    box-shadow: var(--shadow); display: none; overflow: hidden;
  }}
  .sort-menu.open {{ display: block; }}
  .sort-menu button {{
    display: block; width: 100%; text-align: left;
    padding: 10px 14px; border: none; background: transparent;
    color: var(--text2); font-size: 13px; cursor: pointer;
    transition: background .12s;
  }}
  .sort-menu button:hover {{ background: var(--hover); color: var(--text); }}
  .sort-menu button.on {{ color: var(--blue); font-weight: 600; }}

  .thead {{
    display: grid;
    grid-template-columns: 1fr 90px 150px 40px;
    gap: 8px; padding: 10px 16px;
    border-bottom: 1px solid var(--border);
    font-size: 11.5px; font-weight: 700; letter-spacing: .04em;
    color: var(--text3); text-transform: uppercase;
  }}
  .tbody {{ flex: 1; overflow-y: auto; padding: 6px 8px; }}

  .frow {{
    display: grid;
    grid-template-columns: 1fr 90px 150px 40px;
    gap: 8px; align-items: center;
    padding: 10px 10px; border-radius: 11px;
    cursor: pointer; border: 1.5px solid transparent;
    transition: background .15s, border-color .15s, transform .15s;
    animation: rowIn .35s cubic-bezier(.16,1,.3,1) both;
  }}
  @keyframes rowIn {{
    from {{ opacity: 0; transform: translateX(-8px); }}
    to {{ opacity: 1; transform: translateX(0); }}
  }}
  .frow:hover {{ background: var(--hover); }}
  .frow.selected {{
    background: var(--sel);
    border-color: var(--sel-border);
    box-shadow: 0 0 0 1px var(--sel-border), 0 4px 16px rgba(59,130,246,.15);
  }}
  .frow .fname {{
    display: flex; align-items: center; gap: 12px; min-width: 0;
  }}
  .ftext {{ min-width: 0; display: flex; flex-direction: column; gap: 2px; }}
  .flabel {{
    font-size: 14px; font-weight: 600;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }}
  .fsub {{
    font-size: 11.5px; color: var(--text3);
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }}
  .fsize, .fmtime {{
    font-size: 12.5px; color: var(--text2);
    font-variant-numeric: tabular-nums;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }}
  .fdot {{ text-align: center; position: relative; }}
  .dots {{
    color: var(--text3); font-size: 18px; letter-spacing: 1px;
    opacity: 0; transition: opacity .15s, color .15s, background .15s;
    background: transparent; border: none; cursor: pointer;
    width: 32px; height: 28px; border-radius: 8px;
    display: inline-flex; align-items: center; justify-content: center;
    padding: 0; line-height: 1;
  }}
  .frow:hover .dots, .dots.open {{ opacity: 1; }}
  .dots:hover {{ color: var(--text); background: var(--panel3); }}
  .parent-row .dots {{ display: none; }}

  /* file type badges */
  .badge {{
    width: 38px; height: 38px; flex-shrink: 0;
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 11px; font-weight: 800; letter-spacing: -.02em;
    color: #fff;
  }}
  .badge.html {{ background: linear-gradient(135deg,#f97316,#ea580c); font-size: 12px; }}
  .badge.css  {{ background: linear-gradient(135deg,#38bdf8,#0284c7); }}
  .badge.js   {{ background: linear-gradient(135deg,#facc15,#eab308); color: #1a1a1a; }}
  .badge.ts   {{ background: linear-gradient(135deg,#60a5fa,#2563eb); }}
  .badge.json {{ background: linear-gradient(135deg,#4ade80,#16a34a); font-size: 13px; }}
  .badge.md   {{ background: linear-gradient(135deg,#60a5fa,#3b82f6); }}
  .badge.txt  {{ background: linear-gradient(135deg,#f472b6,#db2777); font-size: 9px; }}
  .badge.img  {{ background: linear-gradient(135deg,#a78bfa,#7c3aed); font-size: 9px; }}
  .badge.svg  {{ background: linear-gradient(135deg,#fb923c,#f97316); font-size: 9px; }}
  .badge.ico  {{ background: linear-gradient(135deg,#fde047,#eab308); color: #854d0e; font-size: 16px; }}
  .badge.pdf  {{ background: linear-gradient(135deg,#f87171,#dc2626); }}
  .badge.zip  {{ background: linear-gradient(135deg,#c084fc,#a855f7); }}
  .badge.vid  {{ background: linear-gradient(135deg,#f472b6,#ec4899); font-size: 9px; }}
  .badge.aud  {{ background: linear-gradient(135deg,#2dd4bf,#0d9488); font-size: 9px; }}
  .badge.py   {{ background: linear-gradient(135deg,#fbbf24,#f59e0b); }}
  .badge.exe  {{ background: linear-gradient(135deg,#94a3b8,#64748b); font-size: 9px; }}
  .badge.file {{ background: linear-gradient(135deg,#64748b,#475569); font-size: 9px; }}
  .badge.folder {{
    background: linear-gradient(135deg,#60a5fa,#3b82f6);
    font-size: 16px;
  }}

  .empty-state {{
    text-align: center; padding: 60px 20px; color: var(--text3);
    font-size: 14px;
  }}
  .empty-icon {{ font-size: 42px; margin-bottom: 12px; opacity: .5; }}

  /* ---- right details panel ---- */
  .details {{
    background: var(--details-bg);
    padding: 22px 18px;
    overflow-y: auto;
    display: flex; flex-direction: column; gap: 22px;
  }}
  .detail-top {{
    display: flex; flex-direction: column; align-items: center;
    text-align: center; gap: 6px;
  }}
  .detail-icon {{
    width: 72px; height: 72px; border-radius: 18px;
    display: flex; align-items: center; justify-content: center;
    font-size: 26px; font-weight: 800; color: #fff;
    margin-bottom: 6px;
    box-shadow: 0 8px 24px rgba(0,0,0,.35);
  }}
  .detail-icon.html {{ background: linear-gradient(135deg,#f97316,#ea580c); }}
  .detail-icon.css  {{ background: linear-gradient(135deg,#38bdf8,#0284c7); }}
  .detail-icon.js   {{ background: linear-gradient(135deg,#facc15,#eab308); color:#1a1a1a; }}
  .detail-icon.file {{ background: linear-gradient(135deg,#64748b,#475569); }}
  .detail-icon.folder {{ background: linear-gradient(135deg,#60a5fa,#3b82f6); }}
  .detail-name {{
    font-size: 17px; font-weight: 700; word-break: break-all;
  }}
  .detail-path {{
    font-size: 12px; color: var(--text3); word-break: break-all;
  }}
  .meta-table {{
    display: flex; flex-direction: column; gap: 0;
    background: var(--panel2); border: 1px solid var(--border);
    border-radius: 12px; overflow: hidden;
  }}
  .meta-row {{
    display: flex; justify-content: space-between; align-items: center;
    padding: 11px 14px; font-size: 13px;
    border-bottom: 1px solid var(--border);
  }}
  .meta-row:last-child {{ border-bottom: none; }}
  .meta-row .mk {{ color: var(--text3); font-weight: 500; }}
  .meta-row .mv {{ color: var(--text); font-weight: 600; text-align: right; }}

  .dl-title {{
    font-size: 16px; font-weight: 700; margin-bottom: 4px;
  }}
  .dl-center {{ display: flex; flex-direction: column; gap: 12px; }}
  .dl-btn {{
    display: flex; align-items: center; gap: 12px;
    padding: 14px 14px; border-radius: 14px;
    text-decoration: none; color: #fff; cursor: pointer;
    border: none; width: 100%; text-align: left;
    font-family: inherit;
    transition: transform .2s, box-shadow .2s, filter .2s;
    position: relative; overflow: hidden;
  }}
  .dl-btn::after {{
    content: ""; position: absolute; inset: 0;
    background: linear-gradient(135deg, rgba(255,255,255,.18), transparent 50%);
    opacity: 0; transition: opacity .2s;
  }}
  .dl-btn:hover {{ transform: translateY(-2px); filter: brightness(1.08); }}
  .dl-btn:hover::after {{ opacity: 1; }}
  .dl-btn:active {{ transform: translateY(0); }}
  .dl-btn.blue {{
    background: linear-gradient(135deg, #60a5fa 0%, #3b82f6 55%, #2563eb 100%);
    box-shadow: 0 6px 20px rgba(59,130,246,.4);
  }}
  .dl-btn.teal {{
    background: linear-gradient(135deg, #2dd4bf 0%, #14b8a6 55%, #0d9488 100%);
    box-shadow: 0 6px 20px rgba(20,184,166,.4);
  }}
  .dl-btn.purple {{
    background: linear-gradient(135deg, #a78bfa 0%, #8b5cf6 55%, #7c3aed 100%);
    box-shadow: 0 6px 20px rgba(139,92,246,.4);
  }}
  .dl-btn.pink {{
    background: linear-gradient(135deg, #f472b6 0%, #ec4899 55%, #db2777 100%);
    box-shadow: 0 6px 20px rgba(236,72,153,.4);
  }}
  .dl-ico {{
    width: 42px; height: 42px; border-radius: 11px; flex-shrink: 0;
    background: rgba(255,255,255,.2);
    display: flex; align-items: center; justify-content: center;
    font-size: 18px;
  }}
  .dl-txt {{ flex: 1; min-width: 0; }}
  .dl-txt .t {{ font-size: 14px; font-weight: 700; }}
  .dl-txt .s {{
    font-size: 11.5px; opacity: .88; margin-top: 2px;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }}
  .dl-arrow {{
    width: 32px; height: 32px; border-radius: 50%; flex-shrink: 0;
    background: rgba(255,255,255,.22);
    display: flex; align-items: center; justify-content: center;
    font-size: 14px; font-weight: 700;
  }}

  /* ---- grid view ---- */
  .tbody.grid-view {{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
    gap: 10px; padding: 12px;
    align-content: start;
  }}
  .tbody.grid-view .frow {{
    display: flex; flex-direction: column; text-align: center;
    gap: 8px; padding: 18px 8px 14px;
    grid-template-columns: none;
    min-height: 120px;
    justify-content: center;
    position: relative;
  }}
  .tbody.grid-view .fcell.fsize,
  .tbody.grid-view .fcell.fmtime {{ display: none; }}
  .tbody.grid-view .fcell.fdot {{
    display: block;
    position: absolute; top: 6px; right: 6px;
    width: auto; text-align: center;
  }}
  .tbody.grid-view .dots {{ opacity: 1; width: 28px; height: 28px; font-size: 16px; }}
  .tbody.grid-view .fname {{
    flex-direction: column; gap: 8px; width: 100%;
  }}
  .tbody.grid-view .badge {{ width: 52px; height: 52px; border-radius: 14px; font-size: 14px; margin: 0 auto; }}
  .tbody.grid-view .ftext {{ align-items: center; width: 100%; }}
  .tbody.grid-view .flabel {{
    white-space: normal; word-break: break-word; line-height: 1.3;
    max-height: 2.6em; overflow: hidden;
    display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical;
  }}
  .tbody.grid-view .fsub {{ display: block; font-size: 10.5px; }}
  .tbody.grid-view .empty-state {{ grid-column: 1 / -1; }}

  /* ---- toast ---- */
  .toast {{
    position: fixed; bottom: 28px; left: 50%;
    transform: translateX(-50%) translateY(80px);
    background: var(--panel3); border: 1px solid var(--border2);
    color: var(--text); padding: 12px 22px; border-radius: 12px;
    font-size: 13.5px; font-weight: 600; z-index: 999;
    box-shadow: var(--shadow); opacity: 0;
    transition: all .35s cubic-bezier(.16,1,.3,1);
    pointer-events: none;
  }}
  .toast.show {{ opacity: 1; transform: translateX(-50%) translateY(0); }}

  /* ===== ROW CONTEXT MENU ===== */
  .ctx-menu {{
    position: fixed; z-index: 300;
    min-width: 180px;
    background: var(--glass-bg);
    border: 1px solid var(--border2);
    border-radius: 14px;
    box-shadow: 0 16px 48px rgba(0,0,0,.4), inset 0 1px 0 rgba(255,255,255,.06);
    backdrop-filter: blur(24px) saturate(1.3);
    -webkit-backdrop-filter: blur(24px) saturate(1.3);
    padding: 6px;
    display: none;
    transform-origin: top right;
    animation: ctxIn .18s cubic-bezier(.16,1,.3,1) both;
  }}
  .ctx-menu.open {{ display: block; }}
  @keyframes ctxIn {{
    from {{ opacity: 0; transform: scale(.92) translateY(-6px); }}
    to {{ opacity: 1; transform: scale(1) translateY(0); }}
  }}
  .ctx-item {{
    display: flex; align-items: center; gap: 10px;
    width: 100%; padding: 10px 12px;
    background: transparent; border: none; border-radius: 9px;
    color: var(--text); font-size: 13.5px; font-weight: 500;
    cursor: pointer; text-align: left; font-family: inherit;
    transition: background .12s;
  }}
  .ctx-item:hover {{ background: var(--hover); }}
  .ctx-item.danger {{ color: #ff6b6b; }}
  .ctx-item.danger:hover {{ background: rgba(255,80,80,.12); }}
  .ctx-item .ci {{
    width: 22px; text-align: center; font-size: 14px; opacity: .9;
  }}
  .ctx-sep {{
    height: 1px; background: var(--border);
    margin: 4px 8px;
  }}
  .ctx-title {{
    font-size: 11px; font-weight: 700; color: var(--text3);
    padding: 6px 12px 4px; letter-spacing: .04em;
    text-transform: uppercase;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    max-width: 200px;
  }}

  /* ===== DEST PICKER (move/copy) ===== */
  .dest-tree {{
    max-height: 240px; overflow-y: auto;
    background: var(--input-bg); border: 1.5px solid var(--border);
    border-radius: 12px; padding: 8px; text-align: left;
    margin-top: 4px;
  }}
  .dest-opt {{
    display: flex; align-items: center; gap: 8px;
    width: 100%; padding: 8px 10px;
    background: transparent; border: none; border-radius: 8px;
    color: var(--text2); font-size: 13.5px; font-family: inherit;
    cursor: pointer; transition: all .12s; text-align: left;
  }}
  .dest-opt:hover {{ background: var(--hover); color: var(--text); }}
  .dest-opt.on {{
    background: var(--sel); color: #7db4ff; font-weight: 600;
    outline: 1px solid var(--sel-border);
  }}
  .dest-opt .di {{ font-size: 14px; }}
  .dest-indent {{ width: 14px; flex-shrink: 0; }}

  /* ===== SETTINGS ===== */
  .set-row {{
    display: flex; align-items: center; justify-content: space-between;
    gap: 12px; padding: 12px 14px;
    background: var(--panel2); border: 1px solid var(--border);
    border-radius: 12px; margin-bottom: 10px;
    text-align: right;
  }}
  .set-info {{ min-width: 0; }}
  .set-info .st {{ font-size: 13.5px; font-weight: 600; color: var(--text); }}
  .set-info .ss {{ font-size: 11.5px; color: var(--text3); margin-top: 2px; }}
  .set-seg {{
    display: flex; background: var(--input-bg);
    border: 1px solid var(--border); border-radius: 9px;
    overflow: hidden; flex-shrink: 0;
  }}
  .set-seg button {{
    padding: 7px 12px; border: none; background: transparent;
    color: var(--text3); font-size: 12px; font-weight: 600;
    cursor: pointer; font-family: inherit; transition: all .15s;
  }}
  .set-seg button.on {{
    background: var(--blue); color: #fff;
  }}
  .set-badge {{
    font-size: 11px; font-weight: 700; color: var(--green);
    background: rgba(34,197,94,.12); border: 1px solid rgba(34,197,94,.3);
    padding: 4px 10px; border-radius: 999px;
  }}
  .set-brand {{
    text-align: center; padding: 6px 0 14px;
    border-bottom: 1px solid var(--border); margin-bottom: 14px;
  }}
  .set-brand .bn {{
    font-size: 16px; font-weight: 800; letter-spacing: -.02em;
  }}
  .set-brand .bv {{
    font-size: 11.5px; color: var(--text3); margin-top: 3px;
  }}

  /* ===== GLASS MODALS ===== */
  .modal-back {{
    position: fixed; inset: 0; z-index: 200;
    background: rgba(5,10,25,.55);
    backdrop-filter: blur(10px);
    -webkit-backdrop-filter: blur(10px);
    display: flex; align-items: center; justify-content: center;
    opacity: 0; pointer-events: none;
    transition: opacity .35s cubic-bezier(.16,1,.3,1);
    padding: 16px;
  }}
  [data-theme="light"] .modal-back {{
    background: rgba(20,30,60,.35);
  }}
  .modal-back.open {{ opacity: 1; pointer-events: auto; }}
  .modal {{
    background: var(--glass-bg);
    border: 1px solid var(--border2);
    border-radius: 22px;
    box-shadow: 0 24px 64px rgba(0,0,0,.45), inset 0 1px 0 rgba(255,255,255,.08);
    backdrop-filter: blur(28px) saturate(1.3);
    -webkit-backdrop-filter: blur(28px) saturate(1.3);
    padding: 28px 26px 24px;
    width: 100%; max-width: 380px;
    transform: translateY(24px) scale(.94);
    transition: transform .4s cubic-bezier(.34,1.35,.5,1);
    text-align: center;
  }}
  .modal-back.open .modal {{ transform: translateY(0) scale(1); }}
  .modal h2 {{
    font-size: 18px; font-weight: 700; margin-bottom: 6px;
    color: var(--text);
  }}
  .modal .msub {{
    font-size: 12.5px; color: var(--text2); margin-bottom: 20px;
  }}
  .choice-grid {{
    display: grid; grid-template-columns: 1fr 1fr; gap: 12px;
  }}
  .choice {{
    display: flex; flex-direction: column; align-items: center; gap: 10px;
    padding: 22px 12px 18px;
    background: var(--panel2); border: 1.5px solid var(--border);
    border-radius: 16px; cursor: pointer;
    color: var(--text); font-family: inherit;
    transition: all .25s cubic-bezier(.16,1,.3,1);
  }}
  .choice:hover {{
    border-color: var(--blue);
    background: var(--sel);
    transform: translateY(-4px);
    box-shadow: 0 10px 28px rgba(59,130,246,.2);
  }}
  .choice:active {{ transform: translateY(-1px); }}
  .choice .cico {{
    width: 52px; height: 52px; border-radius: 15px;
    display: flex; align-items: center; justify-content: center;
    font-size: 24px; color: #fff;
    box-shadow: 0 6px 18px rgba(0,0,0,.25);
  }}
  .choice .cico.folder {{ background: linear-gradient(135deg,#60a5fa,#3b82f6); }}
  .choice .cico.file {{ background: linear-gradient(135deg,#a78bfa,#7c3aed); }}
  .choice .clabel {{ font-size: 14px; font-weight: 700; }}
  .choice .cdesc {{ font-size: 11px; color: var(--text3); }}

  .field-label {{
    display: block; text-align: right;
    font-size: 12.5px; font-weight: 600; color: var(--text2);
    margin-bottom: 8px;
  }}
  .field-input {{
    width: 100%; padding: 13px 16px;
    background: var(--input-bg); border: 1.5px solid var(--border);
    border-radius: 12px; color: var(--text); font-size: 15px;
    outline: none; text-align: left;
    transition: border-color .2s, box-shadow .2s;
    font-family: inherit;
  }}
  .field-input:focus {{
    border-color: var(--blue);
    box-shadow: 0 0 0 3px rgba(59,130,246,.2);
  }}
  .field-hint {{
    font-size: 11.5px; color: var(--text3); margin-top: 8px;
    text-align: right; min-height: 16px;
  }}
  .modal-actions {{
    display: flex; gap: 10px; margin-top: 20px;
  }}
  .modal-actions .btn {{ flex: 1; justify-content: center; padding: 11px 14px; }}
  .btn.ghost {{ background: transparent; }}
  .btn.ok {{
    background: linear-gradient(135deg, #4f8cff, #3b5bfc);
    border: none; color: #fff;
    box-shadow: 0 4px 16px rgba(79,140,255,.35);
  }}
  .btn.ok:hover {{ transform: translateY(-1px); box-shadow: 0 6px 20px rgba(79,140,255,.5); }}
  .btn[disabled] {{ opacity: .5; pointer-events: none; }}
  .spinner {{
    display: inline-block; width: 14px; height: 14px;
    border: 2px solid rgba(255,255,255,.35);
    border-top-color: #fff; border-radius: 50%;
    animation: spin .7s linear infinite; vertical-align: -2px;
    margin-left: 6px;
  }}
  @keyframes spin {{ to {{ transform: rotate(360deg); }} }}

  /* ---- responsive ---- */
  @media (max-width: 980px) {{
    .layout {{ grid-template-columns: 1fr; }}
    .sidebar {{ display: none; }}
    .center {{ border-right: none; }}
    .details {{ border-top: 1px solid var(--border); }}
    .metrics {{ display: none; }}
    .thead, .frow {{ grid-template-columns: 1fr 80px 40px; }}
    .thead .h-mtime, .frow .fmtime {{ display: none; }}
  }}
  @media (max-width: 600px) {{
    body {{ padding: 8px; }}
    .app-head {{ flex-direction: column; gap: 14px; align-items: flex-start; }}
    .top-right .machine .mtext {{ display: none; }}
    .thead, .frow {{ grid-template-columns: 1fr 40px; }}
    .thead .h-size, .frow .fsize {{ display: none; }}
  }}
</style>
</head>
<body>

<!-- top bar -->
<div class="topbar">
  <div class="search">
    <svg viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round">
      <circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>
    </svg>
    <input type="text" id="searchInput" placeholder="Search files, folders, or commands..."
           oninput="filterRows()">
  </div>
  <div class="top-right">
    <button class="theme-switch" id="themeSwitch" title="Toggle theme"
            onclick="toggleTheme()" aria-label="Toggle theme">
      <span class="icon-moon">&#9789;</span>
      <span class="icon-sun">&#9728;</span>
      <span class="knob" id="themeKnob">&#127769;</span>
    </button>
    <div class="machine">
      <span class="mdot"></span>
      <div class="mtext">
        <div class="mtitle">Local Machine</div>
        <div class="mstatus">Online</div>
      </div>
    </div>
    <div class="metrics">
      <div class="metric cpu"><div class="mlabel">CPU</div><div class="mbar"><i></i></div></div>
      <div class="metric ram"><div class="mlabel">RAM</div><div class="mbar"><i></i></div></div>
      <div class="metric disk"><div class="mlabel">DISK</div><div class="mbar"><i></i></div></div>
    </div>
    <button class="gear" title="Settings" onclick="openSettings()">&#9881;</button>
  </div>
</div>

<!-- main app -->
<div class="app">
  <div class="app-head">
    <div>
      <h1>File Manager</h1>
      <div class="sub">Browse and manage your server files</div>
    </div>
    <div class="head-actions">
      <button class="btn" onclick="openNewModal()">
        &#10010; جدید
      </button>
      <button class="btn primary" onclick="document.getElementById('fileInput').click()">
        &#8682; Upload
      </button>
      <input type="file" id="fileInput" multiple hidden onchange="uploadFiles(this.files)">
    </div>
  </div>

  <div class="layout">
    <!-- sidebar -->
    <aside class="sidebar">
      {tree_html}
    </aside>

    <!-- center list -->
    <section class="center">
      <div class="list-tools">
        <div class="view-toggle">
          <button id="btnGrid" title="Grid view" onclick="setView('grid')">&#9638;</button>
          <button id="btnList" class="on" title="List view" onclick="setView('list')">&#9776;</button>
        </div>
        <div class="sort-wrap">
          <button class="sort-btn" onclick="toggleSort(event)">Sort &#9662;</button>
          <div class="sort-menu" id="sortMenu">
            <button data-k="name" class="on" onclick="sortRows('name',this)">Name</button>
            <button data-k="size" onclick="sortRows('size',this)">Size</button>
            <button data-k="date" onclick="sortRows('date',this)">Last Modified</button>
          </div>
        </div>
      </div>
      <div class="thead">
        <div>Name</div>
        <div class="h-size">Size</div>
        <div class="h-mtime">Last Modified</div>
        <div></div>
      </div>
      <div class="tbody" id="tbody">
{body_rows}
      </div>
    </section>

    <!-- right details -->
    <aside class="details">
      <div class="detail-top">
        <div class="detail-icon file" id="dIcon">&#128196;</div>
        <div class="detail-name" id="dName">No file selected</div>
        <div class="detail-path" id="dPath">{html.escape(display_path)}</div>
      </div>

      <div class="meta-table">
        <div class="meta-row"><span class="mk">File size</span><span class="mv" id="dSize">&mdash;</span></div>
        <div class="meta-row"><span class="mk">File type</span><span class="mv" id="dType">&mdash;</span></div>
        <div class="meta-row"><span class="mk">Modified</span><span class="mv" id="dMod">&mdash;</span></div>
        <div class="meta-row"><span class="mk">Permissions</span><span class="mv" id="dPerm">&mdash;</span></div>
      </div>

      <div>
        <div class="dl-title">Download Center</div>
        <div class="dl-center" style="margin-top:12px">
          <button class="dl-btn blue" id="btnDownload" onclick="actDownload()">
            <span class="dl-ico">&#8681;</span>
            <span class="dl-txt">
              <span class="t">Download File</span>
              <span class="s" id="dlSub1">Select a file</span>
            </span>
            <span class="dl-arrow">&#8250;</span>
          </button>
          <button class="dl-btn teal" id="btnZip" onclick="actZip()">
            <span class="dl-ico">&#128230;</span>
            <span class="dl-txt">
              <span class="t">Download as ZIP</span>
              <span class="s" id="dlSub2">Compress and download</span>
            </span>
            <span class="dl-arrow">&#8250;</span>
          </button>
          <button class="dl-btn purple" onclick="actShare()">
            <span class="dl-ico">&#128279;</span>
            <span class="dl-txt">
              <span class="t">Create Share Link</span>
              <span class="s">Generate temporary download URL</span>
            </span>
            <span class="dl-arrow">&#8250;</span>
          </button>
          <button class="dl-btn pink" onclick="actCopy()">
            <span class="dl-ico">&#10697;</span>
            <span class="dl-txt">
              <span class="t">Copy Direct Link</span>
              <span class="s">Copy file URL to clipboard</span>
            </span>
            <span class="dl-arrow">&#8250;</span>
          </button>
        </div>
      </div>
    </aside>
  </div>
</div>

<div class="toast" id="toast"></div>

<!-- row context menu -->
<div class="ctx-menu" id="ctxMenu" role="menu">
  <div class="ctx-title" id="ctxTitle"></div>
  <button class="ctx-item" onclick="ctxAction('rename')"><span class="ci">&#9998;</span> تغییر نام</button>
  <button class="ctx-item" onclick="ctxAction('move')"><span class="ci">&#8644;</span> انتقال</button>
  <button class="ctx-item" onclick="ctxAction('copy')"><span class="ci">&#10697;</span> کپی</button>
  <div class="ctx-sep"></div>
  <button class="ctx-item danger" onclick="ctxAction('delete')"><span class="ci">&#128465;</span> حذف</button>
</div>

<!-- glass modal: new folder / new file choice -->
<div class="modal-back" id="newModal" onclick="if(event.target===this)closeNewModal()">
  <div class="modal" role="dialog" aria-modal="true">
    <h2>ایجاد مورد جدید</h2>
    <div class="msub">در مسیر فعلی ساخته می‌شود: <strong dir="ltr">{html.escape(display_path)}</strong></div>
    <div class="choice-grid">
      <button class="choice" onclick="openNameModal('folder')">
        <span class="cico folder">&#128193;</span>
        <span class="clabel">پوشه جدید</span>
        <span class="cdesc">New folder</span>
      </button>
      <button class="choice" onclick="openNameModal('file')">
        <span class="cico file">&#128196;</span>
        <span class="clabel">فایل جدید</span>
        <span class="cdesc">New file</span>
      </button>
    </div>
    <div class="modal-actions">
      <button class="btn ghost" onclick="closeNewModal()">انصراف</button>
    </div>
  </div>
</div>

<!-- glass modal: name prompt -->
<div class="modal-back" id="nameModal" onclick="if(event.target===this)closeNameModal()">
  <div class="modal" role="dialog" aria-modal="true">
    <h2 id="nameTitle">نام را وارد کنید</h2>
    <div class="msub" id="nameSub"></div>
    <label class="field-label" for="nameInput" id="nameLabel">نام</label>
    <input class="field-input" id="nameInput" type="text" autocomplete="off"
           oninput="nameInputChanged()" onkeydown="if(event.key==='Enter')confirmName()">
    <div class="field-hint" id="nameHint"></div>
    <div class="modal-actions">
      <button class="btn ghost" onclick="closeNameModal()">انصراف</button>
      <button class="btn ok" id="nameOk" onclick="confirmName()">تایید</button>
    </div>
  </div>
</div>

<!-- glass modal: delete confirm -->
<div class="modal-back" id="delModal" onclick="if(event.target===this)closeDelModal()">
  <div class="modal" role="dialog" aria-modal="true">
    <h2>حذف مورد</h2>
    <div class="msub">این عملیات برگشت‌پذیر نیست و از سرور هم پاک می‌شود.</div>
    <div class="set-row" style="margin-top:4px">
      <div class="set-info">
        <div class="st" id="delName">&mdash;</div>
        <div class="ss" id="delKind">&mdash;</div>
      </div>
    </div>
    <div class="modal-actions">
      <button class="btn ghost" onclick="closeDelModal()">انصراف</button>
      <button class="btn ok" id="delOk" style="background:linear-gradient(135deg,#ff6b6b,#e11d48);box-shadow:0 4px 16px rgba(225,29,72,.35)"
              onclick="confirmDelete()">حذف</button>
    </div>
  </div>
</div>

<!-- glass modal: rename -->
<div class="modal-back" id="renModal" onclick="if(event.target===this)closeRenModal()">
  <div class="modal" role="dialog" aria-modal="true">
    <h2>تغییر نام</h2>
    <div class="msub" id="renSub"></div>
    <label class="field-label" for="renInput">نام جدید</label>
    <input class="field-input" id="renInput" type="text" autocomplete="off"
           onkeydown="if(event.key==='Enter')confirmRename()">
    <div class="field-hint" id="renHint"></div>
    <div class="modal-actions">
      <button class="btn ghost" onclick="closeRenModal()">انصراف</button>
      <button class="btn ok" id="renOk" onclick="confirmRename()">تایید</button>
    </div>
  </div>
</div>

<!-- glass modal: move / copy destination -->
<div class="modal-back" id="destModal" onclick="if(event.target===this)closeDestModal()">
  <div class="modal" role="dialog" aria-modal="true">
    <h2 id="destTitle">انتخاب مقصد</h2>
    <div class="msub" id="destSub"></div>
    <div class="dest-tree" id="destTree"></div>
    <div class="field-hint" id="destHint">مقصد: /</div>
    <div class="modal-actions">
      <button class="btn ghost" onclick="closeDestModal()">انصراف</button>
      <button class="btn ok" id="destOk" onclick="confirmDest()">تایید</button>
    </div>
  </div>
</div>

<!-- glass modal: settings -->
<div class="modal-back" id="setModal" onclick="if(event.target===this)closeSettings()">
  <div class="modal" role="dialog" aria-modal="true">
    <div class="set-brand">
      <div class="bn">&#9679; Black Server My System</div>
      <div class="bv">File Manager &middot; Settings</div>
    </div>
    <div class="set-row">
      <div class="set-info">
        <div class="st">تم رابط کاربری</div>
        <div class="ss">روشن یا تیره — با انیمیشن نرم</div>
      </div>
      <div class="set-seg">
        <button id="setDark" class="on" onclick="setTheme('dark')">&#9789; تیره</button>
        <button id="setLight" onclick="setTheme('light')">&#9728; روشن</button>
      </div>
    </div>
    <div class="set-row">
      <div class="set-info">
        <div class="st">نمای پیش‌فرض</div>
        <div class="ss">حالت نمایش فایل‌ها هنگام باز شدن</div>
      </div>
      <div class="set-seg">
        <button id="setListV" class="on" onclick="setPrefView('list')">&#9776; لیست</button>
        <button id="setGridV" onclick="setPrefView('grid')">&#9638; گرید</button>
      </div>
    </div>
    <div class="set-row">
      <div class="set-info">
        <div class="st">وضعیت سرور</div>
        <div class="ss" id="setPath">{html.escape(display_path)}</div>
      </div>
      <span class="set-badge">Online</span>
    </div>
    <div class="set-row">
      <div class="set-info">
        <div class="st">مسیر فایل‌ها</div>
        <div class="ss">downloads/ &mdash; فقط خواندنی در لینک‌ها؛ نوشتن از طریق مدیریت</div>
      </div>
    </div>
    <div class="modal-actions">
      <button class="btn ghost" onclick="closeSettings()">بستن</button>
      <button class="btn ok" onclick="closeSettings();toast('Settings saved')">ذخیره</button>
    </div>
  </div>
</div>

<script>
var BASE = {json.dumps(display_path)};
var SELECTED = {first_file_json};
var TOTAL = {file_count};

(function init() {{
  if (SELECTED) applyMeta(SELECTED);
  else document.getElementById("dName").textContent = "No file selected";
  var rows = document.querySelectorAll(".frow.file");
  if (rows.length) selectFile(rows[0]);
  try {{
    var v = localStorage.getItem("bs-view");
    if (v === "grid" || v === "list") setView(v);
  }} catch (e) {{}}
  try {{
    var th = localStorage.getItem("bs-theme");
    if (th === "light" || th === "dark") {{
      document.documentElement.setAttribute("data-theme", th);
      updateThemeKnob();
    }}
  }} catch (e) {{}}
}})();

function applyMeta(m) {{
  SELECTED = m;
  var icon = document.getElementById("dIcon");
  var ext = (m.ext || "file").toLowerCase();
  var map = {{html:"</>", css:"#", js:"JS", json:"{{}}", md:"MD", txt:"TXT",
              png:"IMG", jpg:"IMG", jpeg:"IMG", gif:"IMG", ico:"&#9733;",
              pdf:"PDF", zip:"ZIP", py:"PY"}};
  var cls = {{html:"html", css:"css", js:"js", css:"css"}};
  var badgeCls = "file";
  if (ext === "html" || ext === "htm") badgeCls = "html";
  else if (ext === "css") badgeCls = "css";
  else if (ext === "js") badgeCls = "js";
  else if (ext === "json") badgeCls = "json";
  else if (ext === "md") badgeCls = "md";
  else if (ext === "zip" || ext === "rar" || ext === "7z") badgeCls = "zip";
  else if (ext === "pdf") badgeCls = "pdf";
  else if (ext === "png" || ext === "jpg" || ext === "jpeg" || ext === "gif") badgeCls = "html";
  icon.className = "detail-icon " + badgeCls;
  icon.innerHTML = map[ext] || "&#128196;";
  document.getElementById("dName").textContent = m.name;
  document.getElementById("dPath").textContent = m.path;
  document.getElementById("dSize").textContent = m.size;
  document.getElementById("dType").textContent = m.type;
  document.getElementById("dMod").textContent = m.mtime;
  document.getElementById("dPerm").textContent = m.perm;
  document.getElementById("dlSub1").textContent = "Get " + m.name + " (" + m.size + ")";
  document.getElementById("dlSub2").textContent = "Download " + m.name + " as ZIP";
}}

function selectFile(row) {{
  document.querySelectorAll(".frow.selected").forEach(function(r) {{
    r.classList.remove("selected");
  }});
  row.classList.add("selected");
  try {{ applyMeta(JSON.parse(row.getAttribute("data-meta"))); }}
  catch (e) {{}}
}}

function goDir(href) {{ window.location.href = href; }}
function goParent() {{ window.location.href = "../"; }}
function hoverRow(r) {{ if (!r.classList.contains("selected")) r.style.background = "var(--hover)"; }}
function unhoverRow(r) {{ if (!r.classList.contains("selected")) r.style.background = ""; }}

function filterRows() {{
  var q = document.getElementById("searchInput").value.toLowerCase();
  document.querySelectorAll("#tbody .frow").forEach(function(r) {{
    var t = r.textContent.toLowerCase();
    r.style.display = t.indexOf(q) >= 0 ? "" : "none";
  }});
}}

function setView(v) {{
  var tb = document.getElementById("tbody");
  var bg = document.getElementById("btnGrid");
  var bl = document.getElementById("btnList");
  if (v === "grid") {{ tb.classList.add("grid-view"); bg.classList.add("on"); bl.classList.remove("on"); }}
  else {{ tb.classList.remove("grid-view"); bl.classList.add("on"); bg.classList.remove("on"); }}
  try {{ localStorage.setItem("bs-view", v); }} catch (e) {{}}
}}

function toggleSort(e) {{
  e.stopPropagation();
  document.getElementById("sortMenu").classList.toggle("open");
}}
document.addEventListener("click", function() {{
  document.getElementById("sortMenu").classList.remove("open");
  closeRowMenu();
}});

function sortRows(key, btn) {{
  document.querySelectorAll(".sort-menu button").forEach(function(b) {{
    b.classList.remove("on");
  }});
  btn.classList.add("on");
  var tb = document.getElementById("tbody");
  var empty = tb.querySelector(".empty-state");
  var rows = Array.prototype.slice.call(tb.querySelectorAll(".frow"));
  rows.sort(function(a, b) {{
    var ka = +(a.getAttribute("data-kind") || 2);
    var kb = +(b.getAttribute("data-kind") || 2);
    if (ka !== kb) return ka - kb;
    if (key === "name") {{
      var na = a.getAttribute("data-name") || "";
      var nb = b.getAttribute("data-name") || "";
      try {{ return na.localeCompare(nb, undefined, {{numeric: true, sensitivity: "base"}}); }}
      catch (e) {{ return na < nb ? -1 : na > nb ? 1 : 0; }}
    }}
    if (key === "size") {{
      var sa = +(a.getAttribute("data-size") || -1);
      var sb = +(b.getAttribute("data-size") || -1);
      if (sa !== sb) return sb - sa;
      var xa = a.getAttribute("data-name") || "";
      var xb = b.getAttribute("data-name") || "";
      try {{ return xa.localeCompare(xb, undefined, {{numeric: true, sensitivity: "base"}}); }}
      catch (e) {{ return 0; }}
    }}
    if (key === "date") {{
      var da = +(a.getAttribute("data-mtime") || 0);
      var db = +(b.getAttribute("data-mtime") || 0);
      if (da !== db) return db - da;
      var xa2 = a.getAttribute("data-name") || "";
      var xb2 = b.getAttribute("data-name") || "";
      try {{ return xa2.localeCompare(xb2, undefined, {{numeric: true, sensitivity: "base"}}); }}
      catch (e) {{ return 0; }}
    }}
    return 0;
  }});
  rows.forEach(function(r) {{ tb.appendChild(r); }});
  if (empty) tb.appendChild(empty);
}}

function currentHref() {{
  if (!SELECTED) return null;
  return SELECTED.href;
}}

function actDownload() {{
  if (!SELECTED) {{ toast("Select a file first"); return; }}
  window.location.href = SELECTED.href;
}}
function actZip() {{
  if (!SELECTED) {{ toast("Select a file first"); return; }}
  window.location.href = SELECTED.href + "?zip=1";
}}
function actShare() {{
  if (!SELECTED) {{ toast("Select a file first"); return; }}
  var url = location.origin + BASE.replace(/\\/$/, "") + "/" + SELECTED.href;
  copyText(url, "Share link copied!");
}}
function actCopy() {{
  if (!SELECTED) {{ toast("Select a file first"); return; }}
  var url = location.origin + BASE.replace(/\\/$/, "") + "/" + SELECTED.href;
  copyText(url, "Direct link copied!");
}}
function copyText(t, msg) {{
  if (navigator.clipboard && navigator.clipboard.writeText) {{
    navigator.clipboard.writeText(t).then(function() {{ toast(msg); }},
      function() {{ fallbackCopy(t, msg); }});
  }} else fallbackCopy(t, msg);
}}
function fallbackCopy(t, msg) {{
  var ta = document.createElement("textarea");
  ta.value = t; document.body.appendChild(ta);
  ta.select(); try {{ document.execCommand("copy"); }} catch (e) {{}}
  document.body.removeChild(ta); toast(msg);
}}

var toastTimer = null;
function toast(msg) {{
  var el = document.getElementById("toast");
  el.textContent = msg;
  el.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(function() {{ el.classList.remove("show"); }}, 2400);
}}

/* ===== THEME DRAWER SWITCH ===== */
(function initTheme() {{
  var t = localStorage.getItem("bs-theme");
  if (t !== "light" && t !== "dark") t = "dark";
  document.documentElement.setAttribute("data-theme", t);
  updateThemeKnob();
}})();
function toggleTheme() {{
  var el = document.documentElement;
  var cur = el.getAttribute("data-theme") === "light" ? "dark" : "light";
  el.setAttribute("data-theme", cur);
  localStorage.setItem("bs-theme", cur);
  updateThemeKnob();
}}
function updateThemeKnob() {{
  var t = document.documentElement.getAttribute("data-theme");
  var k = document.getElementById("themeKnob");
  if (k) k.innerHTML = t === "light" ? "&#9728;" : "&#127769;";
}}

/* ===== UPLOAD ===== */
function uploadFiles(fileList) {{
  if (!fileList || !fileList.length) return;
  var fd = new FormData();
  for (var i = 0; i < fileList.length; i++) fd.append("file", fileList[i]);
  toast("Uploading " + fileList.length + " file(s)...");
  fetch(location.pathname + "?__api=upload", {{ method: "POST", body: fd }})
    .then(function(r) {{ return r.json().then(function(j) {{ return {{s: r.status, j: j}}; }}); }})
    .then(function(res) {{
      if (res.j && res.j.ok) {{
        toast("Uploaded: " + res.j.files.join(", "));
        setTimeout(function() {{ location.reload(); }}, 600);
      }} else {{
        toast((res.j && res.j.error) || "Upload failed");
      }}
      document.getElementById("fileInput").value = "";
    }})
    .catch(function() {{ toast("Upload failed"); document.getElementById("fileInput").value = ""; }});
}}

/* ===== NEW MODAL (جدید -> folder | file) ===== */
var createKind = null; /* "folder" | "file" | null */

function openNewModal() {{
  document.getElementById("newModal").classList.add("open");
  createKind = null;
}}
function closeNewModal() {{
  document.getElementById("newModal").classList.remove("open");
}}
function openNameModal(kind) {{
  createKind = kind;
  closeNewModal();
  var title = document.getElementById("nameTitle");
  var sub = document.getElementById("nameSub");
  var label = document.getElementById("nameLabel");
  var input = document.getElementById("nameInput");
  var hint = document.getElementById("nameHint");
  var ok = document.getElementById("nameOk");
  ok.disabled = false;
  ok.innerHTML = "تایید";
  input.value = "";
  if (kind === "folder") {{
    title.textContent = "پوشه جدید";
    sub.innerHTML = "مسیر: <strong dir=\\"ltr\\">{html.escape(display_path)}</strong>";
    label.textContent = "نام پوشه";
    hint.textContent = "پوشه در مسیر فعلی ساخته می‌شود";
  }} else {{
    title.textContent = "فایل جدید";
    sub.innerHTML = "مسیر: <strong dir=\\"ltr\\">{html.escape(display_path)}</strong>";
    label.textContent = "نام فایل";
    hint.textContent = "بدون پسوند → .txt اضافه می‌شود";
  }}
  document.getElementById("nameModal").classList.add("open");
  setTimeout(function() {{ input.focus(); }}, 200);
}}
function closeNameModal() {{
  document.getElementById("nameModal").classList.remove("open");
  createKind = null;
}}
function nameInputChanged() {{
  var v = document.getElementById("nameInput").value.trim();
  var hint = document.getElementById("nameHint");
  if (createKind === "file") {{
    if (v && v.indexOf(".") < 0) hint.textContent = "ذخیره می‌شود با: " + v + ".txt";
    else if (v) hint.textContent = "ذخیره می‌شود با: " + v;
    else hint.textContent = "بدون پسوند → .txt اضافه می‌شود";
  }} else {{
    hint.textContent = v ? "پوشه: " + v : "پوشه در مسیر فعلی ساخته می‌شود";
  }}
}}
function confirmName() {{
  var input = document.getElementById("nameInput");
  var name = input.value.trim();
  if (!name) {{ toast("نام را وارد کنید"); input.focus(); return; }}
  if (name.indexOf("/") >= 0 || name.indexOf("\\\\") >= 0 || name === "." || name === "..") {{
    toast("نام نامعتبر است"); return;
  }}
  var api = createKind === "folder" ? "mkdir" : "create";
  var ok = document.getElementById("nameOk");
  ok.disabled = true;
  ok.innerHTML = "در حال ساخت...<span class=\\"spinner\\"></span>";
  fetch(location.pathname + "?__api=" + api, {{
    method: "POST",
    headers: {{ "Content-Type": "application/json" }},
    body: JSON.stringify({{ name: name }})
  }})
    .then(function(r) {{ return r.json().then(function(j) {{ return {{s: r.status, j: j}}; }}); }})
    .then(function(res) {{
      if (res.j && res.j.ok) {{
        toast((createKind === "folder" ? "پوشه ساخته شد: " : "فایل ساخته شد: ") + res.j.name);
        closeNameModal();
        setTimeout(function() {{ location.reload(); }}, 500);
      }} else {{
        toast((res.j && res.j.error) || "خطا");
        ok.disabled = false;
        ok.innerHTML = "تایید";
      }}
    }})
    .catch(function() {{
      toast("خطا در ارتباط با سرور");
      ok.disabled = false;
      ok.innerHTML = "تایید";
    }});
}}
document.addEventListener("keydown", function(e) {{
  if (e.key === "Escape") {{
    closeNewModal(); closeNameModal();
    closeDelModal(); closeRenModal(); closeDestModal(); closeSettings();
    closeRowMenu();
  }}
}});

/* ===== ROW CONTEXT MENU (three dots) ===== */
var CTX = null; /* {{name, kind}} kind: 1=dir 2=file */
var destMode = null; /* "move" | "copy" | null */
var destPath = "/";

function stopRowClick(e) {{
  if (e) {{ e.preventDefault(); e.stopPropagation(); }}
}}

function openRowMenu(e, btn) {{
  stopRowClick(e);
  var row = btn.closest(".frow");
  if (!row || row.classList.contains("parent-row")) return;
  CTX = {{
    name: row.getAttribute("data-name") || "",
    kind: +(row.getAttribute("data-kind") || 2)
  }};
  if (row.classList.contains("file")) {{
    try {{ selectFile(row); }} catch (err) {{}}
  }}
  var menu = document.getElementById("ctxMenu");
  document.getElementById("ctxTitle").textContent = CTX.name;
  document.querySelectorAll(".dots.open").forEach(function(d) {{ d.classList.remove("open"); }});
  btn.classList.add("open");
  menu.classList.add("open");
  var r = btn.getBoundingClientRect();
  var mw = menu.offsetWidth || 180;
  var mh = menu.offsetHeight || 200;
  var left = Math.max(8, Math.min(r.right - mw, window.innerWidth - mw - 8));
  var top = r.bottom + 6;
  if (top + mh > window.innerHeight - 8) top = Math.max(8, r.top - mh - 6);
  menu.style.left = left + "px";
  menu.style.top = top + "px";
  if (e) e.stopPropagation();
}}

function closeRowMenu() {{
  var menu = document.getElementById("ctxMenu");
  if (menu) menu.classList.remove("open");
  document.querySelectorAll(".dots.open").forEach(function(d) {{ d.classList.remove("open"); }});
}}

function ctxAction(action) {{
  if (!CTX) return;
  closeRowMenu();
  if (action === "delete") openDelModal();
  else if (action === "rename") openRenModal();
  else if (action === "move") openDestModal("move");
  else if (action === "copy") openDestModal("copy");
}}

function postApi(api, body) {{
  return fetch(location.pathname + "?__api=" + api, {{
    method: "POST",
    headers: {{ "Content-Type": "application/json" }},
    body: JSON.stringify(body)
  }}).then(function(r) {{
    return r.json().then(function(j) {{ return {{s: r.status, j: j}}; }});
  }});
}}

/* ---- delete ---- */
function openDelModal() {{
  if (!CTX) return;
  document.getElementById("delName").textContent = CTX.name;
  document.getElementById("delKind").textContent =
    CTX.kind === 1 ? "Folder - removes all contents" : "File - permanent";
  document.getElementById("delModal").classList.add("open");
}}
function closeDelModal() {{
  document.getElementById("delModal").classList.remove("open");
}}
function confirmDelete() {{
  if (!CTX) return;
  var ok = document.getElementById("delOk");
  ok.disabled = true;
  ok.textContent = "...";
  postApi("delete", {{ name: CTX.name }})
    .then(function(res) {{
      ok.disabled = false;
      ok.textContent = "حذف";
      if (res.j && res.j.ok) {{
        toast("Deleted: " + CTX.name);
        closeDelModal();
        setTimeout(function() {{ location.reload(); }}, 500);
      }} else toast((res.j && res.j.error) || "Delete failed");
    }})
    .catch(function() {{
      ok.disabled = false;
      ok.textContent = "حذف";
      toast("Connection error");
    }});
}}

/* ---- rename ---- */
function openRenModal() {{
  if (!CTX) return;
  document.getElementById("renSub").textContent = CTX.name;
  var input = document.getElementById("renInput");
  input.value = CTX.name;
  document.getElementById("renHint").textContent =
    CTX.kind === 1 ? "Folder" : "Keep the extension for files";
  document.getElementById("renModal").classList.add("open");
  setTimeout(function() {{
    input.focus();
    var dot = CTX.name.lastIndexOf(".");
    if (CTX.kind === 2 && dot > 0) input.setSelectionRange(0, dot);
    else input.select();
  }}, 200);
}}
function closeRenModal() {{
  document.getElementById("renModal").classList.remove("open");
}}
function confirmRename() {{
  if (!CTX) return;
  var input = document.getElementById("renInput");
  var nn = input.value.trim();
  if (!nn) {{ toast("Enter a name"); input.focus(); return; }}
  if (nn.indexOf("/") >= 0 || nn.indexOf("\\\\") >= 0 || nn === "." || nn === "..") {{
    toast("Invalid name"); return;
  }}
  var ok = document.getElementById("renOk");
  ok.disabled = true;
  ok.innerHTML = "...<span class=\\"spinner\\"></span>";
  postApi("rename", {{ name: CTX.name, newName: nn }})
    .then(function(res) {{
      ok.disabled = false;
      ok.textContent = "تایید";
      if (res.j && res.j.ok) {{
        toast("Renamed to: " + res.j.name);
        closeRenModal();
        setTimeout(function() {{ location.reload(); }}, 500);
      }} else toast((res.j && res.j.error) || "Rename failed");
    }})
    .catch(function() {{
      ok.disabled = false;
      ok.textContent = "تایید";
      toast("Connection error");
    }});
}}

/* ---- move / copy dest picker ---- */
function openDestModal(mode) {{
  if (!CTX) return;
  destMode = mode;
  destPath = "/";
  document.getElementById("destTitle").textContent =
    mode === "move" ? "انتقال به..." : "کپی به...";
  document.getElementById("destSub").textContent = CTX.name;
  document.getElementById("destHint").textContent = "مقصد: /";
  var tree = document.getElementById("destTree");
  tree.innerHTML = "<div style=\\"color:var(--text3);font-size:12px;padding:8px\\">Loading...</div>";
  document.getElementById("destModal").classList.add("open");
  fetch(location.pathname + "?__api=tree", {{ method: "POST", headers: {{ "Content-Type": "application/json" }}, body: "{{}}" }})
    .then(function(r) {{ return r.json(); }})
    .then(function(j) {{
      tree.innerHTML = "";
      if (j && j.ok && j.tree) renderDestTree(j.tree, tree, 0);
      else tree.innerHTML = "<div style=\\"color:var(--text3);font-size:12px;padding:8px\\">No folders</div>";
    }})
    .catch(function() {{
      tree.innerHTML = "<div style=\\"color:var(--text3);font-size:12px;padding:8px\\">Error</div>";
    }});
}}
function renderDestTree(node, el, depth) {{
  var btn = document.createElement("button");
  btn.type = "button";
  btn.className = "dest-opt" + (node.path === destPath ? " on" : "");
  btn.setAttribute("data-path", node.path);
  btn.innerHTML = '<span class="di">&#128193;</span>' +
    (depth ? '<span class="dest-indent"></span>'.repeat(depth) : "") +
    "<span>" + (depth ? node.name : "downloads /") + "</span>";
  btn.onclick = function() {{
    destPath = node.path;
    document.querySelectorAll(".dest-opt").forEach(function(o) {{ o.classList.remove("on"); }});
    btn.classList.add("on");
    document.getElementById("destHint").textContent = "مقصد: " + destPath;
  }};
  el.appendChild(btn);
  (node.dirs || []).forEach(function(ch) {{ renderDestTree(ch, el, depth + 1); }});
}}
function closeDestModal() {{
  document.getElementById("destModal").classList.remove("open");
  destMode = null;
}}
function confirmDest() {{
  if (!CTX || !destMode) return;
  var ok = document.getElementById("destOk");
  ok.disabled = true;
  ok.innerHTML = "...<span class=\\"spinner\\"></span>";
  postApi(destMode, {{ name: CTX.name, dest: destPath }})
    .then(function(res) {{
      ok.disabled = false;
      ok.textContent = "تایید";
      if (res.j && res.j.ok) {{
        toast((destMode === "move" ? "Moved: " : "Copied: ") + CTX.name);
        closeDestModal();
        setTimeout(function() {{ location.reload(); }}, 500);
      }} else toast((res.j && res.j.error) || "Failed");
    }})
    .catch(function() {{
      ok.disabled = false;
      ok.textContent = "تایید";
      toast("Connection error");
    }});
}}

/* ---- settings ---- */
function openSettings() {{
  syncSettingsUI();
  document.getElementById("setModal").classList.add("open");
}}
function closeSettings() {{
  document.getElementById("setModal").classList.remove("open");
}}
function syncSettingsUI() {{
  var th = document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
  document.getElementById("setDark").classList.toggle("on", th === "dark");
  document.getElementById("setLight").classList.toggle("on", th === "light");
  var v = "list";
  try {{ v = localStorage.getItem("bs-view") || "list"; }} catch (e) {{}}
  document.getElementById("setListV").classList.toggle("on", v !== "grid");
  document.getElementById("setGridV").classList.toggle("on", v === "grid");
}}
function setTheme(t) {{
  document.documentElement.setAttribute("data-theme", t);
  try {{ localStorage.setItem("bs-theme", t); }} catch (e) {{}}
  updateThemeKnob();
  syncSettingsUI();
}}
function setPrefView(v) {{
  setView(v);
  syncSettingsUI();
}}
</script>
</body>
</html>
"""
        payload = page.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        return io.BytesIO(payload)


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------

def create_http_server(preferred_port: int) -> Tuple[ThreadingHTTPServer, int]:
    """Create the threaded HTTP server bound to localhost on a free port."""
    handler = functools.partial(
        DownloadRequestHandler, directory=str(DOWNLOADS_DIR)
    )
    last_error: Optional[OSError] = None

    candidates = list(range(preferred_port, preferred_port + PORT_SCAN_LIMIT))
    candidates.append(0)

    for port in candidates:
        try:
            httpd = ThreadingHTTPServer((HOST, port), handler)
        except OSError as exc:
            last_error = exc
            logger.warning("Port %s is not available: %s", port, exc)
            continue
        httpd.daemon_threads = True
        return httpd, httpd.server_address[1]

    raise OSError(f"Could not start the local server: {last_error}")


def print_banner(
    local_url: str,
    public_url: Optional[str],
    files_dir: Path,
) -> None:
    """Print the final, copy-friendly status banner."""
    public_line = public_url or "(tunnel disabled)"
    print()
    print("========================================")
    print("      BLACK SERVER MY SYSTEM")
    print("========================================")
    print()
    print("Local:")
    print(local_url)
    print()
    print("Public:")
    print(public_line)
    print()
    print("Files:")
    print(str(files_dir))
    print()
    print("Status:")
    print("ONLINE")
    print()
    print("Press Ctrl+C to stop the server.")
    print("========================================")
    print()


def run(args: argparse.Namespace) -> int:
    """Start the file server and (unless disabled) the Cloudflare tunnel."""
    setup_logging(args.verbose)

    # Make sure the required folders exist.
    DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    BIN_DIR.mkdir(parents=True, exist_ok=True)

    if not DOWNLOADS_DIR.is_dir():
        print(f"[ERROR] downloads directory is missing: {DOWNLOADS_DIR}")
        return 1

    # Prevent duplicate instances.
    acquired, existing_pid = acquire_single_instance_lock()
    if not acquired:
        print("[ERROR] Another instance of the server is already running.")
        print(f"        Existing process id: {existing_pid}")
        print("        Stop it (Ctrl+C in its window) and try again.")
        return 1

    httpd: Optional[ThreadingHTTPServer] = None
    tunnel: Optional[CloudflareTunnel] = None
    ssh_tunnel: Optional[SshTunnel] = None
    stop_event = threading.Event()

    def _handle_signal(signum, frame):  # noqa: ARG001
        print("\n[i] Shutdown requested, stopping ...")
        stop_event.set()

    # Clean Ctrl+C / termination handling.  SIGBREAK is Windows-only and is
    # delivered when the console window is closed or CTRL_BREAK is pressed.
    signal.signal(signal.SIGINT, _handle_signal)
    for name in ("SIGTERM", "SIGBREAK"):
        sig = getattr(signal, name, None)
        if sig is not None:
            try:
                signal.signal(sig, _handle_signal)
            except (AttributeError, ValueError, OSError):
                pass

    try:
        # 1) Local file server.
        try:
            httpd, port = create_http_server(args.port)
        except OSError as exc:
            print(f"[ERROR] Could not start the local server: {exc}")
            return 1

        threading.Thread(
            target=httpd.serve_forever, name="http-server", daemon=True
        ).start()
        local_url = f"http://{HOST}:{port}"

        if not wait_for_port(HOST, port, timeout=10):
            print("[ERROR] Local server did not come up on localhost.")
            return 1
        if port != args.port:
            print(f"[i] Port {args.port} was busy; using {port} instead.")
        print(f"[OK] Local server listening on {local_url}")
        print(f"[OK] Serving files from {DOWNLOADS_DIR}")

        # 2) Tunnel (optional).
        if args.no_tunnel:
            print_banner(local_url, None, DOWNLOADS_DIR)
            print("[i] Tunnel disabled (--no-tunnel). Local access only.")
            while not stop_event.wait(0.5):
                pass
            return 0

        exe = ensure_cloudflared(force_download=args.download_cloudflared)
        if exe is None:
            print("[ERROR] cloudflared is not available; cannot create a tunnel.")
            print("        Local server is still running for a few seconds ...")
            return 1

        if not check_internet():
            print("[!] Warning: no obvious internet connectivity detected.")
            print("    Trying anyway - the Cloudflare edge may still be reachable ...")

        # Multi-protocol startup.
        #
        # cloudflared normally talks to the edge over QUIC (UDP port 7844).
        # A lot of networks (firewalls, ISPs, national filters) block egress
        # UDP while leaving TCP open, which makes QUIC hang forever.  The
        # tunnel therefore starts with the requested protocol and, for the
        # default "auto", transparently retries once over HTTP/2 (TCP).
        startup_protocols = (
            ("auto", "http2") if args.protocol == "auto" else (args.protocol,)
        )
        probe_timeout = min(args.register_timeout, 25)

        tunnel: Optional[CloudflareTunnel] = None
        ssh_tunnel: Optional[SshTunnel] = None
        public_url: Optional[str] = None
        for index, protocol in enumerate(startup_protocols):
            if tunnel is not None:
                tunnel.stop()
            if index > 0:
                print(f"[i] QUIC/UDP to the edge seems blocked; retrying with '{protocol}' ...")
            tunnel = CloudflareTunnel(
                exe, port, LOGS_DIR / "cloudflared.log", protocol=protocol
            )
            try:
                tunnel.start()
            except OSError as exc:
                print(f"[ERROR] Could not start cloudflared: {exc}")
                tunnel = None
                break

            print("[..] Waiting for the public URL from Cloudflare ...")
            public_url = tunnel.wait_for_url(args.tunnel_timeout)
            if tunnel.fatal_error:
                break  # the quick tunnel could not be created at all
            if not public_url:
                continue  # try the next protocol
            if tunnel.wait_for_registration(probe_timeout):
                break  # data plane connected - we are live

        # --- Decide which tunnel is in charge ------------------------------

        if tunnel is None:
            return 1

        if public_url is None:
            # Cloudflare could not even mint a URL -> explain, then fall back.
            if tunnel.fatal_error:
                print("[ERROR] Cloudflare refused to create a quick tunnel.")
                print(f"        {tunnel.fatal_error}")
                print("        This is usually a DNS or API/firewall issue between")
                print("        this machine and api.trycloudflare.com.")
            else:
                print("[ERROR] Cloudflare could not produce a public URL.")
                print("        The internet or the Cloudflare edge is unreachable.")
            print_log_tail(tunnel.log_path)
            print("        See logs/cloudflared.log for details.")
            tunnel.stop()
            tunnel = None
            if not args.allow_ssh_fallback:
                return 1
            ssh_tunnel, public_url = try_ssh_fallback(port, args.ssh_timeout)
            if ssh_tunnel is None:
                return 1

        elif not tunnel.registered:
            # A URL is reserved as soon as the request reaches Cloudflare's API.
            # The public URL is only really usable once the tunnel's data plane
            # has connected to the edge ("Registered tunnel connection").
            print(f"[!] Public URL reserved: {public_url}")
            print("    ...but the tunnel connection to Cloudflare's edge has")
            print("    not been established yet, so the link is not live.")
            print("    This usually means the network blocks cloudflared traffic")
            print("    (e.g. UDP/TCP to port 7844 or *.argotunnel.com).")
            print("    You can force a transport with: --protocol http2")
            print(f"    Local server still available at: {local_url}")
            if args.allow_ssh_fallback:
                print("    Giving the Cloudflare tunnel a short chance to recover ...")
                deadline = time.monotonic() + max(args.register_timeout, 25)
                while time.monotonic() < deadline:
                    if tunnel.registered:
                        break
                    if tunnel.process is not None and tunnel.process.poll() is not None:
                        break
                    time.sleep(0.5)
                if not tunnel.registered:
                    print("    ...still not live - switching to the SSH fallback tunnel.")
                    tunnel.stop()
                    tunnel = None
                    ssh_tunnel, public_url = try_ssh_fallback(port, args.ssh_timeout)
                    if ssh_tunnel is None:
                        return 1
            else:
                print("    Waiting for the tunnel to recover (Ctrl+C to stop) ...")

        if ssh_tunnel is not None:
            # The SSH tunnel URL is typically live within seconds.
            print(f"[OK] SSH tunnel URL: {public_url}")

        # 3) As soon as the tunnel is usable, show the banner, copy the URL and
        #    open the browser.  The server keeps running either way.
        banner_shown = False
        online_url: Optional[str] = public_url if (
            ssh_tunnel is not None or (tunnel is not None and tunnel.registered)
        ) else None

        while not stop_event.wait(0.5):
            if not banner_shown and online_url is None:
                if ssh_tunnel is not None:
                    online_url = public_url  # show banner immediately
                elif tunnel is not None and tunnel.wait_for_registration(0):
                    online_url = public_url
            if not banner_shown and online_url:
                banner_shown = True
                if ssh_tunnel is not None:
                    print(f"[i] Public URL (via SSH fallback): {online_url}")
                print_banner(local_url, online_url, DOWNLOADS_DIR)
                if copy_to_clipboard(online_url):
                    print("[OK] Public URL copied to the clipboard.")
                if not args.no_browser:
                    try:
                        webbrowser.open(online_url)
                    except Exception as exc:  # noqa: BLE001 - browser is optional
                        logger.warning("Could not open the browser: %s", exc)
            if ssh_tunnel is not None:
                if ssh_tunnel.process and ssh_tunnel.process.poll() is not None:
                    print("[ERROR] The SSH tunnel stopped unexpectedly.")
                    print_log_tail(ssh_tunnel.log_path)
                    print(f"        See logs/{ssh_tunnel.log_path.name} for details.")
                    break
            elif tunnel is not None and tunnel.process and tunnel.process.poll() is not None:
                if banner_shown:
                    print("[ERROR] cloudflared stopped unexpectedly.")
                else:
                    print("[ERROR] cloudflared exited before the tunnel was ready.")
                    print("        See logs/cloudflared.log for details.")
                print_log_tail(tunnel.log_path)
                break
        return 0

    finally:
        # Clean shutdown: always terminate the tunnel and the HTTP server.
        if tunnel is not None:
            tunnel.stop()
        if ssh_tunnel is not None:
            ssh_tunnel.stop()
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()
        release_single_instance_lock()
        logger.info("Server stopped cleanly.")
        print("[i] Server stopped.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Public file download server - Cloudflare Quick Tunnel with an "
            "automatic SSH fallback tunnel when Cloudflare is blocked."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT,
        help="preferred local port (falls back to a free port if busy)",
    )
    parser.add_argument(
        "--no-tunnel", action="store_true",
        help="serve locally only; do not start cloudflared",
    )
    parser.add_argument(
        "--no-browser", action="store_true",
        help="do not open the public URL in the default browser",
    )
    parser.add_argument(
        "--tunnel-timeout", type=int, default=60,
        help="seconds to wait for the public URL",
    )
    parser.add_argument(
        "--register-timeout", type=int, default=30,
        help="seconds to wait for the tunnel data plane to connect",
    )
    parser.add_argument(
        "--protocol", choices=("auto", "quic", "http2"), default="auto",
        help="cloudflared transport protocol to the Cloudflare edge",
    )
    parser.add_argument(
        "--no-ssh-fallback", action="store_true",
        help="disable the automatic SSH fallback tunnel",
    )
    parser.add_argument(
        "--ssh-timeout", type=int, default=int(SSH_STARTUP_TIMEOUT),
        help="seconds to wait for the SSH fallback tunnel URL",
    )
    parser.add_argument(
        "--ensure-cloudflared", action="store_true",
        help="only make sure bin/cloudflared.exe exists, then exit",
    )
    parser.add_argument(
        "--download-cloudflared", action="store_true",
        help="force a fresh download of cloudflared",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="also print debug logs to the console",
    )
    return parser


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.allow_ssh_fallback = not args.no_ssh_fallback

    if args.ensure_cloudflared or args.download_cloudflared:
        setup_logging(args.verbose)
        BIN_DIR.mkdir(parents=True, exist_ok=True)
        exe = ensure_cloudflared(force_download=args.download_cloudflared)
        return 0 if exe else 1

    try:
        return run(args)
    except KeyboardInterrupt:
        print("\n[i] Interrupted by user.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
