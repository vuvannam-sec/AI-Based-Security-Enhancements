#!/usr/bin/env python3
"""Small, local-only workloads for exercising the monitoring pipeline."""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path


def run_cpu(duration: int) -> None:
    print(f"CPU workload: pid={os.getpid()} duration={duration}s")
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        sum(value * value for value in range(10_000))


def run_sensitive_file(duration: int) -> None:
    path = Path("/etc/passwd")
    print(f"Holding a readable security-relevant file open: {path}")
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        handle.read(1)
        time.sleep(duration)


def run_suspicious_exec(duration: int) -> None:
    with tempfile.TemporaryDirectory(prefix="ai-sec-demo-", dir="/tmp") as directory:
        script = Path(directory) / "demo.sh"
        script.write_text(f"#!/bin/sh\nsleep {duration}\n", encoding="utf-8")
        script.chmod(0o700)
        print(f"Executing local demo file from temporary path: {script}")
        subprocess.run([str(script)], check=True, timeout=duration + 5)


def run_suspicious_network(duration: int) -> None:
    ready = threading.Event()
    stop = threading.Event()

    def server() -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 4444))
            listener.listen(1)
            ready.set()
            listener.settimeout(duration + 5)
            conn, _ = listener.accept()
            with conn:
                stop.wait(duration)

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    if not ready.wait(3):
        raise RuntimeError("loopback listener did not start")

    print("Opening a loopback TCP connection to demo port 4444 (no shell is created).")
    with socket.create_connection(("127.0.0.1", 4444), timeout=3):
        time.sleep(duration)
    stop.set()
    thread.join(timeout=2)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "scenario",
        choices=("cpu", "sensitive-file", "suspicious-exec", "suspicious-network"),
    )
    parser.add_argument("--duration", type=int, default=10)
    args = parser.parse_args()
    if not 1 <= args.duration <= 300:
        parser.error("--duration must be between 1 and 300 seconds")
    return args


def main() -> None:
    args = parse_args()
    scenarios = {
        "cpu": run_cpu,
        "sensitive-file": run_sensitive_file,
        "suspicious-exec": run_suspicious_exec,
        "suspicious-network": run_suspicious_network,
    }
    scenarios[args.scenario](args.duration)


if __name__ == "__main__":
    main()
