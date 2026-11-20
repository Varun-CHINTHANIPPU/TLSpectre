#!/usr/bin/env python3
"""Fail closed on obvious secrets or private evidence accidentally tracked by Git.

This is a preventative heuristic, not a full credential-history audit.
"""
from __future__ import annotations

from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PRIVATE_DIRS = ("pki/out/", "data/raw/", "data/references/",
                "data/processed/", "data/runtime/", "results/", "third_party/")
PRIVATE_SUFFIXES = (".key", ".p12", ".jks", ".keylog", ".pcap", ".pcapng",
                    ".pem", ".csr", ".srl", ".pfx", ".env")
PRIVATE_NAMES = (".env", "id_rsa", "id_ed25519", "credentials.json")
# Build these strings in pieces so the scanner doesn't match its own code.
PEM_KEY = ("-----BEGIN " + "PRIVATE KEY-----").encode()
PEM_RSA = ("-----BEGIN RSA " + "PRIVATE KEY-----").encode()
PEM_EC = ("-----BEGIN EC " + "PRIVATE KEY-----").encode()
TOKEN_MARKERS = [("gh" + "p_").encode(), ("github_" + "pat_").encode(),
                 ("xox" + "b-").encode()]


def main() -> int:
    proc = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT,
                          check=True, capture_output=True)
    names = [Path(p.decode()) for p in proc.stdout.split(b"\0") if p]
    findings = []
    for relative in names:
        posix = relative.as_posix()
        if (posix.startswith(PRIVATE_DIRS) or relative.name in PRIVATE_NAMES
                or relative.suffix.lower() in PRIVATE_SUFFIXES):
            findings.append(f"{posix}: private file/path tracked")
            continue
        path = ROOT / relative
        if not path.is_file() or path.stat().st_size > 4_000_000:
            continue
        raw = path.read_bytes()
        if any(marker in raw for marker in (PEM_KEY, PEM_RSA, PEM_EC)):
            findings.append(f"{posix}: private-key PEM header")
        if any(marker in raw for marker in TOKEN_MARKERS):
            findings.append(f"{posix}: possible access token marker")
        if re.search(rb"AK" + rb"IA[0-9A-Z]{16}", raw):
            findings.append(f"{posix}: possible AWS access key")
    if findings:
        print("Tracked secret/evidence candidates (values never printed):")
        for finding in findings:
            print(" -", finding)
        return 1
    print(f"PASS: {len(names)} tracked files scanned; no obvious private evidence or key markers")
    print("Scope: current tracked files only; history and nonstandard secret formats require separate review.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
