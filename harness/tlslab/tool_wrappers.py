"""Tool discovery, local-only execution and raw evidence capture."""
from pathlib import Path
import os
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def local_tool(name: str):
    if name == "testssl.sh":
        candidates = [ROOT / "third_party/testssl.sh/testssl.sh"]
    elif name == "tlsfuzzer":
        candidates = [ROOT / "third_party/tlsfuzzer"]
    elif name == "extract-tls-secrets":
        candidates = [ROOT / "third_party/extract-tls-secrets-5.0.0.jar"]
    else:
        candidates = []
    for candidate in candidates:
        if candidate.exists():
            return candidate
    result = shutil.which(name)
    return Path(result) if result else None


def run_tool(argv: list[str], *, timeout: int = 45, cwd: Path = ROOT,
             stdin: str | None = None, keep: int = 32768,
             extra_env: dict | None = None):
    """Run local probes without inheriting the terminal as stdin.

    An explicit stdin payload is supported for post-handshake ticket probes.
    """
    try:
        proc = subprocess.run(argv, cwd=cwd, capture_output=True, text=True,
                              timeout=timeout, env={**os.environ, **(extra_env or {})},
                              stdin=subprocess.DEVNULL if stdin is None else None,
                              input=stdin)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {"status": "BLOCKED", "reason": type(exc).__name__,
                "argv": argv, "stdout": "", "stderr": str(exc), "returncode": None}
    return {"status": "OBSERVED", "argv": argv, "stdout": proc.stdout[-keep:],
            "stderr": proc.stderr[-keep:], "returncode": proc.returncode}


def tlsfuzzer_script(name: str):
    root = local_tool("tlsfuzzer")
    if root is None:
        return None
    # Only scripts explicitly listed within the checked-out tool are accepted.
    file = root / "scripts" / name
    return file if file.is_file() else None


def check_target(host: str):
    if host not in ("127.0.0.1", "localhost", "10.77.1.1"):
        raise ValueError("All active probes must target the isolated local laboratory")
