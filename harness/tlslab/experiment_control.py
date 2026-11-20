"""Lifecycle helpers for isolated experimental processes; no background daemon left behind."""
from contextlib import contextmanager
from pathlib import Path
import csv
import io
import os
import select
import socket
import subprocess
import tempfile
import time

import psutil
import yaml

from .launch import ROOT, build_command
from .netns import exec_in
from .env import pinned


def cpu_ns(pid):
    p = psutil.Process(pid)
    times = p.cpu_times()
    return round((times.user + times.system) * 1_000_000_000)


def await_tcp(host: str, port: int, process: subprocess.Popen, timeout: float = 20):
    """Connection attempts are deliberately not counted as handshakes."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"server exited {process.returncode}")
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"server {host}:{port} did not become ready")


@contextmanager
def running_server(config: Path, log: Path, *, namespace: str | None = None, server_affinity: list[int] | None = None):
    argv, _ = build_command(config)
    if namespace:
        argv = exec_in(namespace, argv)
    if server_affinity:
        # Apply affinity before JVM startup: taskset survives exec() and its
        # mask is inherited by every Java thread, unlike post-spawn PID pinning.
        argv = pinned(argv, server_affinity)
    # A listening leftover JVM can make await_tcp() report readiness before
    # the newly spawned JVM has even tried to bind. Refuse contaminated runs.
    if namespace is None:
        c = yaml.safe_load(config.read_text())
        host = c.get("bindHost", "127.0.0.1")
        for port in (int(c["httpsPort"]), int(c.get("httpPort", 8080))):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.settimeout(0.3)
                if probe.connect_ex((host, port)) == 0:
                    raise RuntimeError(
                        f"Refusing contaminated experiment: {host}:{port} already listening")
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w") as out:
        process = subprocess.Popen(argv, cwd=ROOT, stdout=out, stderr=subprocess.STDOUT)
        try:
            data = yaml.safe_load(config.read_text())
            # When running in netns, TCP readiness checks must occur inside that
            # namespace as host namespace cannot necessarily reach the veth.
            if namespace:
                target = data.get("bindHost", "127.0.0.1")
                cmd = exec_in(namespace, ["python3", "-c",
                    "import socket;socket.create_connection(("+repr(target)+","+repr(int(data["httpsPort"]))+"),2).close()"])
                for attempt in range(200):
                    if process.poll() is not None:
                        raise RuntimeError("server exited before readiness")
                    if subprocess.run(cmd, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL).returncode == 0:
                        break
                    time.sleep(0.1)
                else:
                    raise TimeoutError("TLS endpoint readiness timeout")
            else:
                await_tcp(data.get("bindHost", "127.0.0.1"), int(data["httpsPort"]), process)
            yield process
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def ephemeral_server_profile(base_name: str, changes: dict, folder: Path) -> Path:
    path = ROOT / "configs/server" / f"{base_name}.yaml"
    source = yaml.safe_load(path.read_text())
    source.update(changes)
    folder.mkdir(parents=True, exist_ok=True)
    output = folder / f"profile-{base_name}.yaml"
    output.write_text(yaml.safe_dump(source, sort_keys=True))
    return output


def run_java_csv(class_name: str, arguments: list[str], *, timeout: int = 120,
                 namespace: str | None = None, client_affinity: list[int] | None = None,
                 jvm_args: list[str] | None = None, env: dict | None = None):
    command = ["java", *(jvm_args or []), "-cp", str(ROOT/"java/target/tlslab-server.jar"),
               f"lab.tls13.client.{class_name}", *arguments]
    if namespace:
        command = exec_in(namespace, command)
    if client_affinity:
        command = pinned(command, client_affinity)
    process = subprocess.run(command, text=True, capture_output=True,
                             timeout=timeout, cwd=ROOT,
                             env={**os.environ, **env} if env else None)
    if process.returncode != 0:
        raise RuntimeError(class_name + " failed: " + process.stderr[-1000:])
    return list(csv.DictReader(io.StringIO(process.stdout)))


def read_phase_marker(stream, *, timeout: float = 30) -> str:
    """Bounded, unbuffered read of a single JVM warm-up marker line."""
    deadline = time.monotonic() + timeout
    raw = bytearray()
    while len(raw) < 256:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Timed out waiting for E4 warmup phase marker")
        readable, _, _ = select.select([stream.fileno()], [], [], remaining)
        if not readable:
            raise TimeoutError("Timed out waiting for E4 warmup phase marker")
        one = os.read(stream.fileno(), 1)
        if not one:
            raise RuntimeError("E4 bulk client exited before warmup marker")
        if one == b"\n":
            return raw.decode("utf-8", errors="replace").strip()
        raw.extend(one)
    raise RuntimeError("Overlong E4 warmup marker")


def run_bulk_with_server_cpu(server_pid: int, args: list[str], *, timeout=180,
                             namespace: str | None = None, client_affinity: list[int] | None = None):
    """One E4 transfer with a stderr marker sampled before measured body phase."""
    command = ["java", "-cp", str(ROOT/"java/target/tlslab-server.jar"),
               "lab.tls13.client.BulkClient", *args]
    if namespace:
        command = exec_in(namespace, command)
    if client_affinity:
        command = pinned(command, client_affinity)
    env = os.environ.copy()
    env["TLSLAB_E4_PHASE_MARKER"] = "1"
    diagnostics = tempfile.TemporaryFile(mode="w+t", encoding="utf-8")
    try:
        process = subprocess.Popen(command, cwd=ROOT, env=env,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=diagnostics, text=True, bufsize=1)
    except BaseException:
        diagnostics.close()
        raise
    try:
        # BCJSSE can write provider diagnostics to stderr *before* reaching
        # the warm-up boundary. Never confuse those diagnostics with the marker.
        marker = read_phase_marker(process.stdout, timeout=min(30, timeout))
        if marker != "TLSLAB_E4_WARMUP_COMPLETE":
            out, _ = process.communicate(timeout=10)
            diagnostics.seek(0)
            err = diagnostics.read()
            raise RuntimeError("E4 warmup signal absent: " +
                               (marker + " " + out[:300] + " " + err[:2000])[:2500])
        cpu_before = cpu_ns(server_pid)
        # Acknowledge only after the server CPU baseline is sampled.
        process.stdin.write("R")
        process.stdin.flush()
        process.stdin.close()
        process.stdin = None
        stdout, _ = process.communicate(timeout=timeout)
        diagnostics.seek(0)
        stderr = diagnostics.read()
        cpu_after = cpu_ns(server_pid)
        if process.returncode != 0:
            raise RuntimeError("bulk client failed: " + stderr[-1000:])
        rows = list(csv.DictReader(io.StringIO(stdout)))
        if len(rows) != 1 or int(rows[0]["measured_bytes"]) < 1:
            raise RuntimeError("unexpected E4 CSV output")
        row = rows[0]
        row["server_cpu_ns"] = max(0, cpu_after - cpu_before)
        row["server_cpu_ns_per_byte"] = row["server_cpu_ns"]/int(row["measured_bytes"])
        row["server_cpu_boundary_quality"] = "stderr_phase_marker; process CPU sampled after notification"
        return row
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        diagnostics.close()
