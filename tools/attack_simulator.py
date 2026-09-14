#!/usr/bin/env python3
"""Local behavior simulator for validating the monitoring pipeline.

This utility is intentionally manual. It creates observable host behaviors for a
controlled lab environment; it is not part of the automated test suite.
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import tempfile
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

DEFAULT_DURATION = 20


def _header(name: str, expected_detection: str) -> None:
    print("=" * 64)
    print(f"Simulation: {name}")
    print(f"PID: {os.getpid()}")
    print(f"Time: {datetime.now().isoformat(timespec='seconds')}")
    print(f"Expected signal: {expected_detection}")
    print("=" * 64)


def simulate_cpu_abuse(duration: int) -> None:
    """Create sustained CPU load in this process."""
    _header("CPU abuse", "high_cpu_usage / crypto_miner")
    deadline = time.monotonic() + duration
    iterations = 0

    try:
        while time.monotonic() < deadline:
            sum(i * i for i in range(10_000))
            iterations += 1
    except KeyboardInterrupt:
        pass

    print(f"Completed {iterations} work iterations.")


def simulate_sensitive_file_access(duration: int) -> None:
    """Open a standard Linux security file when permissions allow it."""
    _header("Sensitive file access", "sensitive_file_access")
    candidates = (Path("/etc/shadow"), Path("/etc/passwd"), Path("/etc/sudoers"))

    handle = None
    opened_path: Path | None = None
    for path in candidates:
        try:
            handle = path.open("r", encoding="utf-8", errors="ignore")
            opened_path = path
            break
        except (OSError, PermissionError):
            continue

    if handle is None or opened_path is None:
        print("No candidate file could be opened with the current permissions.")
        return

    print(f"Opened {opened_path}; holding the descriptor for {duration}s.")
    try:
        time.sleep(duration)
    except KeyboardInterrupt:
        pass
    finally:
        handle.close()


def simulate_suspicious_exec(duration: int) -> None:
    """Execute a harmless shell script from the system temporary directory."""
    _header("Temporary-path execution", "suspicious_exec")

    fd, raw_path = tempfile.mkstemp(prefix="ai-sec-demo-", suffix=".sh", dir="/tmp")
    path = Path(raw_path)
    os.close(fd)

    try:
        path.write_text(f"#!/usr/bin/env bash\necho 'local demo process'\nsleep {duration}\n", encoding="utf-8")
        path.chmod(0o700)
        subprocess.run([str(path)], check=False, timeout=duration + 5)
    except subprocess.TimeoutExpired:
        print("Simulation timed out and was stopped.")
    finally:
        path.unlink(missing_ok=True)


def simulate_reverse_shell_signal(duration: int) -> None:
    """Create a localhost connection to the demo suspicious port 4444.

    No shell is spawned and no command execution is sent over the socket.
    """
    _header("Suspicious localhost connection", "reverse_shell")

    nc = shutil.which("nc") or shutil.which("netcat")
    if nc is None:
        raise RuntimeError("netcat is required for the reverse_shell simulation")

    listener = subprocess.Popen(
        [nc, "-l", "4444"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(3)
    try:
        time.sleep(0.5)
        client.connect(("127.0.0.1", 4444))
        print(f"Connected to 127.0.0.1:4444; holding for {duration}s.")
        time.sleep(duration)
    finally:
        client.close()
        listener.terminate()
        try:
            listener.wait(timeout=3)
        except subprocess.TimeoutExpired:
            listener.kill()
            listener.wait()


def run_all(duration: int) -> None:
    simulations: tuple[tuple[str, Callable[[int], None]], ...] = (
        ("cpu_abuse", simulate_cpu_abuse),
        ("sensitive_file", simulate_sensitive_file_access),
        ("suspicious_exec", simulate_suspicious_exec),
        ("reverse_shell", simulate_reverse_shell_signal),
    )

    for name, simulation in simulations:
        print(f"\n--- {name} ---")
        simulation(duration)
        time.sleep(2)


def _positive_duration(value: str) -> int:
    duration = int(value)
    if duration < 1 or duration > 300:
        raise argparse.ArgumentTypeError("duration must be between 1 and 300 seconds")
    return duration


def main() -> int:
    parser = argparse.ArgumentParser(description="Run explicit local behaviors for detector validation.")
    parser.add_argument(
        "simulation",
        choices=("all", "cpu_abuse", "sensitive_file", "suspicious_exec", "reverse_shell"),
    )
    parser.add_argument("duration", nargs="?", default=DEFAULT_DURATION, type=_positive_duration)
    args = parser.parse_args()

    simulations: dict[str, Callable[[int], None]] = {
        "all": run_all,
        "cpu_abuse": simulate_cpu_abuse,
        "sensitive_file": simulate_sensitive_file_access,
        "suspicious_exec": simulate_suspicious_exec,
        "reverse_shell": simulate_reverse_shell_signal,
    }

    try:
        simulations[args.simulation](args.duration)
    except KeyboardInterrupt:
        print("\nSimulation interrupted.")
        return 130
    except RuntimeError as exc:
        print(f"error: {exc}")
        return 2

    print("\nReview recent decisions with:")
    print("  curl -s 'http://127.0.0.1:8001/sensor/enforcement_history?limit=10' | python3 -m json.tool")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
