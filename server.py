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


# ---------------------------------------------------------------------------
# File server
# ---------------------------------------------------------------------------

class DownloadRequestHandler(SimpleHTTPRequestHandler):
    """Serves files from ``./downloads`` with listing, streaming and ranges.

    Security properties:
      * the root directory is fixed to ``./downloads``;
      * path traversal / symlink escapes are rejected;
      * dot-files (e.g. ``.env``, ``.gitignore``) are never served;
      * only GET/HEAD are implemented - there is no upload or admin API.
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

    # -- request handling -------------------------------------------------
    def send_head(self):
        path = self._resolve_path()
        if path is None or not path.exists() or self._is_hidden(path):
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return None

        if path.is_dir():
            # Redirect directory requests without a trailing slash so relative
            # links inside the listing work correctly.
            if not self.path.endswith("/"):
                self.send_response(HTTPStatus.MOVED_PERMANENTLY)
                self.send_header("Location", self.path + "/")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return None
            return self.list_directory(str(path))

        return self._send_file(path)

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

        rows = []
        if current != root:
            rows.append(
                '<a class="card dir" href="../">'
                '<span class="icon">&#8617;</span>'
                '<span class="name">.. (parent)</span>'
                '<span class="size"></span>'
                "</a>"
            )

        for name in entries:
            full = current / name
            link = urllib.parse.quote(name, safe="")
            label = html.escape(name)
            if full.is_dir():
                rows.append(
                    f'<a class="card dir" href="{link}/">'
                    f'<span class="icon">&#128193;</span>'
                    f'<span class="name">{label}</span>'
                    '<span class="size">&mdash;</span>'
                    "</a>"
                )
            else:
                try:
                    size = human_size(full.stat().st_size)
                except OSError:
                    size = "?"
                ext = full.suffix.lower()
                icon = _file_icon(ext)
                rows.append(
                    f'<a class="card file" href="{link}" download>'
                    f'<span class="icon">{icon}</span>'
                    f'<span class="name">{label}</span>'
                    f'<span class="size">{size}</span>'
                    '<span class="dl">&#8595;</span>'
                    "</a>"
                )

        if rows:
            body_rows = "\n".join(rows)
        else:
            body_rows = '<div class="empty">No files available.</div>'

        page = f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Black Server - {html.escape(display_path)}</title>
<style>
  *,*::before,*::after {{ box-sizing:border-box; margin:0; padding:0; }}

  :root, [data-theme="dark"] {{
    --bg: #0a0a0f;
    --bg2: #111118;
    --glass: rgba(255,255,255,.06);
    --glass2: rgba(255,255,255,.10);
    --glass-hover: rgba(255,255,255,.14);
    --border: rgba(255,255,255,.10);
    --border-hover: rgba(255,255,255,.22);
    --text: #f2f2f7;
    --text2: #8e8e93;
    --accent: #0a84ff;
    --accent2: #5e5ce6;
    --green: #30d158;
    --orange: #ff9f0a;
    --shadow: 0 8px 32px rgba(0,0,0,.45);
    --shadow-hover: 0 12px 40px rgba(10,132,255,.25);
    --radius: 16px;
    --blur: 24px;
  }}

  [data-theme="light"] {{
    --bg: #f2f2f7;
    --bg2: #ffffff;
    --glass: rgba(255,255,255,.72);
    --glass2: rgba(255,255,255,.88);
    --glass-hover: rgba(255,255,255,.95);
    --border: rgba(0,0,0,.08);
    --border-hover: rgba(0,0,0,.18);
    --text: #1c1c1e;
    --text2: #6e6e73;
    --accent: #007aff;
    --accent2: #5856d6;
    --green: #28a745;
    --orange: #ff9500;
    --shadow: 0 4px 24px rgba(0,0,0,.10);
    --shadow-hover: 0 8px 32px rgba(0,122,255,.22);
    --radius: 16px;
    --blur: 24px;
  }}

  html {{ font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display",
         "SF Pro Text", "Segoe UI", system-ui, sans-serif;
         -webkit-font-smoothing: antialiased; }}

  body {{
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    padding: 1.5rem;
    transition: background .4s, color .4s;
  }}

  body::before {{
    content: "";
    position: fixed; inset: 0;
    background:
      radial-gradient(ellipse 80% 50% at 20% 0%, rgba(10,132,255,.15), transparent),
      radial-gradient(ellipse 60% 40% at 80% 100%, rgba(94,92,230,.12), transparent);
    pointer-events: none;
    z-index: 0;
  }}
  [data-theme="light"] body::before {{
    background:
      radial-gradient(ellipse 80% 50% at 20% 0%, rgba(0,122,255,.08), transparent),
      radial-gradient(ellipse 60% 40% at 80% 100%, rgba(88,86,214,.06), transparent);
  }}

  .wrap {{
    position: relative; z-index: 1;
    max-width: 720px; margin: 0 auto;
  }}

  /* ---- header ---- */
  .header {{
    display: flex; align-items: center; justify-content: space-between;
    margin-bottom: 1.5rem;
  }}
  .header h1 {{
    font-size: 1.5rem; font-weight: 700; letter-spacing: -.02em;
  }}
  .path {{
    color: var(--text2); font-size: .82rem; margin-bottom: 1.5rem;
    word-break: break-all; font-weight: 500;
    padding: .6rem .9rem;
    background: var(--glass);
    border: 1px solid var(--border);
    border-radius: 12px;
    backdrop-filter: blur(var(--blur));
    -webkit-backdrop-filter: blur(var(--blur));
  }}

  /* ---- theme toggle ---- */
  .theme-btn {{
    width: 44px; height: 44px; border-radius: 50%;
    border: 1px solid var(--border);
    background: var(--glass);
    backdrop-filter: blur(var(--blur));
    -webkit-backdrop-filter: blur(var(--blur));
    color: var(--text);
    font-size: 1.15rem; cursor: pointer;
    display: flex; align-items: center; justify-content: center;
    transition: all .3s cubic-bezier(.4,0,.2,1);
    flex-shrink: 0;
  }}
  .theme-btn:hover {{
    background: var(--glass-hover);
    border-color: var(--border-hover);
    transform: scale(1.08) rotate(15deg);
    box-shadow: var(--shadow-hover);
  }}
  .theme-btn:active {{ transform: scale(.95); }}

  /* ---- file cards ---- */
  .cards {{
    display: flex; flex-direction: column; gap: .6rem;
  }}

  .card {{
    display: flex; align-items: center; gap: .9rem;
    padding: .9rem 1.1rem;
    background: var(--glass);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    backdrop-filter: blur(var(--blur));
    -webkit-backdrop-filter: blur(var(--blur));
    text-decoration: none; color: var(--text);
    transition: all .25s cubic-bezier(.4,0,.2,1);
    position: relative;
    overflow: hidden;
  }}
  .card::before {{
    content: "";
    position: absolute; inset: 0;
    background: linear-gradient(135deg, rgba(255,255,255,.06), transparent 60%);
    opacity: 0; transition: opacity .3s;
    pointer-events: none;
  }}
  .card:hover {{
    background: var(--glass-hover);
    border-color: var(--border-hover);
    transform: translateY(-2px) scale(1.01);
    box-shadow: var(--shadow-hover);
  }}
  .card:hover::before {{ opacity: 1; }}
  .card:active {{ transform: translateY(0) scale(.99); }}

  .card .icon {{
    font-size: 1.4rem; width: 36px; height: 36px;
    display: flex; align-items: center; justify-content: center;
    background: var(--glass2);
    border-radius: 10px;
    border: 1px solid var(--border);
    flex-shrink: 0;
    transition: all .3s;
  }}
  .card:hover .icon {{
    background: var(--accent);
    border-color: var(--accent);
    color: #fff;
    transform: scale(1.1);
  }}
  .card.dir:hover .icon {{
    background: var(--orange);
    border-color: var(--orange);
  }}

  .card .name {{
    flex: 1; font-weight: 500; font-size: .92rem;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    transition: color .2s;
  }}
  .card:hover .name {{ color: var(--accent); }}
  .card.dir:hover .name {{ color: var(--orange); }}

  .card .size {{
    color: var(--text2); font-size: .78rem; font-weight: 600;
    font-variant-numeric: tabular-nums;
    background: var(--glass2);
    padding: .2rem .55rem;
    border-radius: 8px;
    border: 1px solid var(--border);
    transition: all .3s;
    flex-shrink: 0;
  }}
  .card:hover .size {{
    background: var(--accent);
    color: #fff;
    border-color: var(--accent);
  }}

  .card .dl {{
    font-size: 1.1rem; color: var(--text2);
    opacity: 0; transform: translateX(-8px);
    transition: all .3s cubic-bezier(.4,0,.2,1);
    flex-shrink: 0; width: 20px; text-align: center;
  }}
  .card:hover .dl {{
    opacity: 1; transform: translateX(0);
    color: var(--green);
  }}

  .empty {{
    text-align: center; color: var(--text2);
    padding: 3rem 1rem; font-size: .95rem;
    background: var(--glass);
    border: 1px dashed var(--border);
    border-radius: var(--radius);
    backdrop-filter: blur(var(--blur));
  }}

  footer {{
    margin-top: 1.5rem; text-align: center;
    color: var(--text2); font-size: .72rem; font-weight: 500;
    opacity: .7;
  }}

  /* ---- responsive ---- */
  @media (max-width: 480px) {{
    body {{ padding: .75rem; }}
    .header h1 {{ font-size: 1.2rem; }}
    .card {{ padding: .75rem .85rem; gap: .7rem; }}
    .card .icon {{ width: 32px; height: 32px; font-size: 1.15rem; }}
    .card .name {{ font-size: .84rem; }}
  }}

  /* ---- entrance animation ---- */
  .card {{ animation: fadeUp .4s ease both; }}
  .card:nth-child(1) {{ animation-delay: .02s; }}
  .card:nth-child(2) {{ animation-delay: .05s; }}
  .card:nth-child(3) {{ animation-delay: .08s; }}
  .card:nth-child(4) {{ animation-delay: .11s; }}
  .card:nth-child(5) {{ animation-delay: .14s; }}
  .card:nth-child(6) {{ animation-delay: .17s; }}
  .card:nth-child(7) {{ animation-delay: .20s; }}
  .card:nth-child(8) {{ animation-delay: .23s; }}
  .card:nth-child(9) {{ animation-delay: .26s; }}
  .card:nth-child(10) {{ animation-delay: .29s; }}

  @keyframes fadeUp {{
    from {{ opacity: 0; transform: translateY(12px); }}
    to {{ opacity: 1; transform: translateY(0); }}
  }}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <h1>&#9679; Black Server</h1>
    <button class="theme-btn" id="themeBtn" title="Toggle theme"
            onclick="toggleTheme()">&#127769;</button>
  </div>
  <div class="path">{html.escape(display_path)}</div>
  <div class="cards">
{body_rows}
  </div>
  <footer>Served via Black Server &middot; read-only</footer>
</div>
<script>
(function(){{
  var t = localStorage.getItem('bs-theme');
  if (t === 'light' || t === 'dark')
    document.documentElement.setAttribute('data-theme', t);
  updateIcon();
}})();
function toggleTheme(){{
  var el = document.documentElement;
  var cur = el.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
  el.setAttribute('data-theme', cur);
  localStorage.setItem('bs-theme', cur);
  updateIcon();
}}
function updateIcon(){{
  var t = document.documentElement.getAttribute('data-theme');
  document.getElementById('themeBtn').innerHTML =
    t === 'light' ? '&#127769;' : '&#127761;';
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
