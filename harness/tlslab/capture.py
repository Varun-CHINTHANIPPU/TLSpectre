"""Controlled capture lifecycle, Java keylog agent launch and secret injection."""
from contextlib import contextmanager
from pathlib import Path
import os
import shutil
import signal
import subprocess
import time

from .tool_wrappers import local_tool
from .launch import build_command, ROOT


@contextmanager
def capture_loopback(path: Path, *, interface: str = "lo", port: int = 8443):
    if not shutil.which("tshark"):
        raise FileNotFoundError("tshark not installed")
    if interface not in ("lo", "any", "tlslab-vcs"):
        raise ValueError("capture interface must be a local test interface")
    path.parent.mkdir(parents=True, exist_ok=True)
    diagnostic = path.with_suffix(path.suffix + ".tshark.log")
    # Do not leave tshark's stderr in an undrained pipe: a full pipe would
    # block the capture process and lose packets.
    # Tshark/dumpcap may drop privileges before opening the -w pathname.
    # Open a private capture file in our own process first, and let tshark
    # write a pcapng stream to its inherited stdout file descriptor. This
    # avoids permission errors in a 0700 experiment directory without
    # making capture data or TLS secrets world-readable.
    with path.open("wb") as output, diagnostic.open("wb") as stderr_log:
        os.chmod(path, 0o600)
        process = subprocess.Popen(
            ["tshark", "-i", interface, "-f", f"tcp port {port}",
             "-w", "-"],
            stdout=output, stderr=stderr_log)
        try:
            time.sleep(1)
            if process.poll() is not None:
                reason = diagnostic.read_text(errors="replace")[-1800:]
                raise RuntimeError(
                    f"tshark failed to start (exit {process.returncode}); "
                    f"see {diagnostic}: {reason}")
            yield process
        finally:
            if process.poll() is None:
                time.sleep(2)
                process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            output.flush()


def keylog_server_argv(config: Path, keylog: Path, agent: Path | None = None) -> list[str]:
    if agent is None:
        agent = local_tool("extract-tls-secrets")
    if agent is None or not agent.is_file():
        raise FileNotFoundError("Place pinned extract-tls-secrets-5.0.0.jar under third_party/")
    if not os.environ.get("KS_PASS"):
        raise EnvironmentError("KS_PASS missing")
    args, _ = build_command(config)
    # Append agent before -jar, so Java loads it before SSLContext initialization.
    index = args.index("-jar")
    keylog.parent.mkdir(parents=True, exist_ok=True)
    return args[:index] + [f"-javaagent:{agent.resolve()}={keylog.resolve()}"] + args[index:]


def inject_keylog(pcap: Path, keylog: Path, output: Path):
    if not shutil.which("editcap"):
        raise FileNotFoundError("editcap required for embedding keylogs in pcapng")
    if not keylog.is_file() or keylog.stat().st_size == 0:
        raise ValueError("empty Java keylog; provider/agent compatibility unverified")
    if output == pcap:
        raise ValueError("output must differ from input")
    subprocess.run(["editcap", "--inject-secrets", f"tls,{keylog}",
                    str(pcap), str(output)], check=True, timeout=60)
    if not output.is_file() or output.stat().st_size < pcap.stat().st_size:
        raise RuntimeError("keylog injection failed")
    return output
