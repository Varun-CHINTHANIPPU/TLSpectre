"""Launch one configured Jetty server with non-leaking, configuration-scoped JVM policy."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timezone

import yaml

ROOT = Path(__file__).resolve().parents[2]


def build_command(config_path: Path) -> tuple[list[str], dict]:
    path = config_path if config_path.is_absolute() else ROOT / config_path
    settings = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(settings, dict):
        raise ValueError("server configuration must be a YAML mapping")
    protocols = settings.get("protocols", ["TLSv1.3"])
    if not isinstance(protocols, list) or not set(protocols) <= {"TLSv1.2", "TLSv1.3"}:
        raise ValueError("unsupported protocol configuration")
    mode = "dual_stack" if "TLSv1.2" in protocols else "hardened"
    if path.stem.upper() == "B1":
        mode = "vendor"
    args = ["java"]
    if mode != "vendor":
        args.append(f"-Djava.security.properties={ROOT / 'conf' / (mode + '.security')}")
    if not settings.get("sessionCache", False):
        # Jetty's setSessionCachingEnabled(false) does not stop SunJSSE from
        # sending a TLS 1.3 NewSessionTicket after every full handshake. A
        # profile that declares sessionCache=false must not issue resumption
        # tickets at all (observed on the wire with JDK 27: NST follows the
        # first HTTP response, which also breaks strict tlsfuzzer scripts).
        # Both switches are required. With only newSessionTicketCount=0, JDK 27
        # still negotiates the TLS 1.2 session_ticket extension and then never
        # sends NewSessionTicket, so every TLS 1.2 handshake (A3/B2) aborts
        # with unexpected_message on the client.
        args.append("-Djdk.tls.server.enableSessionTicketExtension=false")
        args.append("-Djdk.tls.server.newSessionTicketCount=0")
    groups = settings.get("namedGroups", [])
    if groups:
        args.append("-Djdk.tls.namedGroups=" + ",".join(groups))
    # Only the declared JDK 27 intrinsics ablations are accepted here.
    safe_flags = {
        "-XX:+UnlockDiagnosticVMOptions",
        "-XX:-UseAES", "-XX:-UseAESIntrinsics", "-XX:-UseAESCTRIntrinsics",
        "-XX:-UseGHASHIntrinsics", "-XX:-UseChaCha20Intrinsics",
        "-XX:-UsePoly1305Intrinsics",
    }
    jvm_flags = settings.get("jvmFlags", [])
    if not isinstance(jvm_flags, list) or any(
        not isinstance(flag, str) or flag not in safe_flags for flag in jvm_flags
    ):
        raise ValueError("jvmFlags must be from the documented A4/A5 allow-list")
    if jvm_flags and jvm_flags[0] != "-XX:+UnlockDiagnosticVMOptions":
        raise ValueError("unlock diagnostic options before the ablation flags")
    args.extend(jvm_flags)
    args += ["-jar", str(ROOT / "java/target/tlslab-server.jar"), str(path)]
    manifest = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "config_path": str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "policy": mode,
        "java_args_without_secrets": args,
        "status": "launch_plan_only",
    }
    return args, manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    ns = parser.parse_args()
    args, manifest = build_command(ns.config)
    print(json.dumps(manifest, indent=2), flush=True)
    if ns.dry_run:
        return 0
    if not os.getenv("KS_PASS"):
        parser.error("KS_PASS must be set in the environment")
    if not (ROOT / "java/target/tlslab-server.jar").exists():
        parser.error("Build first: make build")
    return subprocess.call(args, cwd=ROOT)


if __name__ == "__main__":
    sys.exit(main())
